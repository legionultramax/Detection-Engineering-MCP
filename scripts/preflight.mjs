#!/usr/bin/env node
/**
 * Deployment preflight — the server half of the Gemma smoke test.
 *
 * GEMMA-RUNBOOK.md §8 lists seven questions to ask the model once the stack is
 * up. Each has a wrong answer that identifies which layer broke. The problem
 * with running them only through the model is that a failure is ambiguous: a
 * bad answer could be the model, the tool parser, the transport, the profile,
 * or the data.
 *
 * This runs the half that does not need a model. It starts the server exactly
 * as the deployment does — read-only, scoped profile, HTTP transport, bearer
 * token, bounded results — speaks MCP over HTTP the way Open WebUI will, and
 * drives the same seven scenarios as direct tool calls.
 *
 * What that proves: the transport, the auth, the session handling, the profile,
 * the corpus, the search index, the authoring gate and the AQL constraints are
 * all correct on this machine.
 *
 * What it cannot prove: that Gemma chooses the right tool, fills arguments
 * correctly, or follows the sequence. That needs the model, and no amount of
 * server-side testing substitutes for it. When a §8 step fails on the real
 * stack and the same step passes here, the fault is above the server.
 *
 * Usage:
 *   npm run preflight                       # start a server and test it
 *   npm run preflight -- --url http://host:port/mcp --token XYZ
 *                                           # test an already-running one
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import net from 'node:net';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = path.join(ROOT, 'dist', 'index.js');
const DB = process.env.DETECTIONS_DB_PATH ?? path.join(ROOT, 'data', 'detections.db');

const argv = process.argv.slice(2);
const argOf = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const EXTERNAL_URL = argOf('--url');
const EXTERNAL_TOKEN = argOf('--token');

if (!EXTERNAL_URL) {
  if (!existsSync(ENTRY)) {
    console.error('error: dist/index.js not found — run "npm run build" first.');
    process.exit(2);
  }
  if (!existsSync(DB)) {
    console.error(`error: no database at ${DB}. The server would answer every query with silence.`);
    process.exit(2);
  }
}

let pass = 0, fail = 0, warn = 0;
const check = (name, ok, detail = '') => {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? '\n        ' + String(detail).slice(0, 300) : ''}`); }
};
const note = (name, detail) => { warn++; console.log(`  NOTE  ${name}${detail ? ' — ' + detail : ''}`); };

function freePort() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.once('error', rej);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); });
  });
}

// --- transport -------------------------------------------------------------

let sessionId;
async function rpc(url, token, body) {
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    Authorization: `Bearer ${token}`,
  };
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  const sid = res.headers.get('mcp-session-id');
  if (sid) sessionId = sid;
  const text = await res.text();
  // Streamable HTTP may answer as SSE; take the first data: line.
  const json = (() => {
    try { return JSON.parse(text); } catch { /* fall through */ }
    const m = text.match(/^data:\s*(\{[\s\S]*)$/m);
    if (m) { try { return JSON.parse(m[1]); } catch { /* ignore */ } }
    return null;
  })();
  return { status: res.status, json, text };
}

const callTool = async (url, token, name, args = {}) => {
  const r = await rpc(url, token, {
    jsonrpc: '2.0', id: Math.floor(Math.random() * 1e6),
    method: 'tools/call', params: { name, arguments: args },
  });
  const payload = r.json?.result?.content?.[0]?.text;
  let parsed = null;
  try { parsed = payload ? JSON.parse(payload) : null; } catch { parsed = null; }
  return { raw: payload ?? r.text, obj: parsed, status: r.status, isError: r.json?.result?.isError };
};

// --- run -------------------------------------------------------------------

let proc, url, token;

if (EXTERNAL_URL) {
  url = EXTERNAL_URL;
  token = EXTERNAL_TOKEN ?? '';
  console.log(`\nTesting an already-running server at ${url}\n`);
} else {
  const port = await freePort();
  token = 'preflight-' + Math.random().toString(36).slice(2);
  url = `http://127.0.0.1:${port}/mcp`;
  console.log('\nStarting the server with the documented deployment settings:');
  console.log('  HAWKEYE_READONLY=1  HAWKEYE_TOOL_PROFILE=phase1-authoring');
  console.log(`  HAWKEYE_MAX_RESULTS=10  HAWKEYE_TRANSPORT=http  port=${port}\n`);

  proc = spawn(process.execPath, [ENTRY], {
    cwd: ROOT,
    env: {
      ...process.env,
      DETECTIONS_DB_PATH: DB,
      HAWKEYE_READONLY: '1',
      HAWKEYE_TOOL_PROFILE: 'phase1-authoring',
      HAWKEYE_MAX_RESULTS: '10',
      HAWKEYE_TRANSPORT: 'http',
      HAWKEYE_HTTP_PORT: String(port),
      HAWKEYE_HTTP_TOKEN: token,
      HAWKEYE_SKIP_SYNC: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d; });

  const ready = await new Promise(res => {
    const t = setTimeout(() => res(false), 90000);
    const iv = setInterval(() => {
      if (/MCP over HTTP/.test(stderr)) { clearInterval(iv); clearTimeout(t); res(true); }
      if (proc.exitCode !== null) { clearInterval(iv); clearTimeout(t); res(false); }
    }, 250);
  });
  if (!ready) {
    console.error('error: server did not start.\n' + stderr.slice(-1200));
    proc.kill('SIGKILL');
    process.exit(1);
  }
}

const done = (code) => { if (proc) proc.kill('SIGKILL'); process.exit(code); };

try {
  // ---- handshake ----------------------------------------------------------
  console.log('=== Transport: what Open WebUI does on connect ===');
  const init = await rpc(url, token, {
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'preflight', version: '1' } },
  });
  check('initialize succeeds', init.status === 200 && Boolean(init.json?.result),
    `${init.status} ${init.text.slice(0, 200)}`);
  check('server returns a session id', Boolean(sessionId), String(sessionId));
  await rpc(url, token, { jsonrpc: '2.0', method: 'notifications/initialized', params: {} });

  const unauth = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} }),
  });
  check('an unauthenticated request is refused', unauth.status === 401 || unauth.status === 403,
    `got ${unauth.status}`);

  // ---- §8 step 2: profile -------------------------------------------------
  console.log('\n=== §8 step 2: "How many tools do you have?" ===');
  const list = await rpc(url, token, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  const tools = list.json?.result?.tools ?? [];
  check('the scoped profile is served, not the full registry',
    tools.length === 29, `got ${tools.length} — expected 29; check HAWKEYE_TOOL_PROFILE`);
  const defBytes = JSON.stringify(tools).length;
  console.log(`        tool definitions: ${defBytes} B (~${Math.round(defBytes / 3.5)} tokens)`);
  check('definitions fit a 16K window with room to work',
    Math.round(defBytes / 3.5) < 16384 / 2, `${Math.round(defBytes / 3.5)} tokens`);
  check('the composite authoring tools are exposed',
    ['build_authoring_brief', 'synthesize_killchain'].every(n => tools.some(t => t.name === n)));

  // ---- §8 step 1: get_stats ----------------------------------------------
  console.log('\n=== §8 step 1: "Call get_stats" ===');
  const stats = await callTool(url, token, 'get_stats');
  check('get_stats returns real numbers', (stats.obj?.total ?? stats.obj?.total_detections ?? 0) > 15000
    || /15\d{3}/.test(stats.raw), String(stats.raw).slice(0, 160));

  // ---- §8 step 3: routing on a technique id -------------------------------
  console.log('\n=== §8 step 3: "Find detections for T1059.001" ===');
  const byMitre = await callTool(url, token, 'list_by_mitre', { technique_id: 'T1059.001' });
  const n = byMitre.obj?.count ?? byMitre.obj?.detections?.length ?? 0;
  check('list_by_mitre returns coverage', n > 0, String(byMitre.raw).slice(0, 160));
  check('HAWKEYE_MAX_RESULTS bounds the response',
    (byMitre.obj?.detections?.length ?? 0) <= 10,
    `${byMitre.obj?.detections?.length} rows — expected <= 10`);
  console.log(`        response: ${String(byMitre.raw).length} B (~${Math.round(String(byMitre.raw).length / 3.5)} tokens)`);

  // ---- §8 step 4: corpus + FTS -------------------------------------------
  console.log('\n=== §8 step 4: "Search for certutil download" ===');
  const search = await callTool(url, token, 'search_detections', { query: 'certutil download', limit: 5 });
  check('full-text search returns results', (search.obj?.count ?? 0) > 0, String(search.raw).slice(0, 160));
  check('FTS5 is doing the work, not substring fallback',
    /"engine":\s*"fts5"/.test(String(search.raw)),
    'index may be stale — run npm run fts:status');

  // ---- §8 step 5: the authoring loop, server side -------------------------
  console.log('\n=== §8 step 5: "Write a KQL rule for T1003.001" (server half) ===');
  const brief = await callTool(url, token, 'build_authoring_brief',
    { technique_id: 'T1003.001', language: 'kql' });
  check('build_authoring_brief returns a usable brief',
    brief.obj?.gate === 'OK' || brief.obj?.gate === 'CAVEATS', `gate=${brief.obj?.gate}`);
  check('it carries the target field vocabulary',
    (brief.obj?.target?.field_vocabulary ?? []).length > 0);
  check('it carries reference rules', (brief.obj?.reference_rules?.count ?? 0) > 0);
  console.log(`        brief: ${String(brief.raw).length} B (~${Math.round(String(brief.raw).length / 3.5)} tokens)`);

  const gate = await callTool(url, token, 'build_authoring_brief',
    { technique_id: 'T1003.001', language: 'kql', binary: 'not-a-real-lolbin.exe' });
  check('the LOLBAS gate blocks an ungroundable binary', gate.obj?.gate === 'BLOCKED', `gate=${gate.obj?.gate}`);
  check('and withholds the authoring material', gate.obj?.target === undefined);

  const badKql = await callTool(url, token, 'validate_query',
    { query: 'DeviceProcessEvents | where NoSuchColumn == "x"', language: 'kql' });
  check('validate_query rejects an invented column',
    badKql.obj?.valid === false, `valid=${badKql.obj?.valid}`);

  // ---- §8 step 6: AQL constraints ----------------------------------------
  console.log('\n=== §8 step 6: "Write a QRadar AQL query" (server half) ===');
  const aqlOk = await callTool(url, token, 'validate_query', {
    query: 'SELECT starttime, sourceip, username, "Process CommandLine" FROM events ' +
           'WHERE "Process CommandLine" ILIKE \'%-enc %\' ORDER BY starttime DESC LIMIT 100',
    language: 'aql',
  });
  check('a correct AQL query validates', aqlOk.obj?.valid === true,
    JSON.stringify(aqlOk.obj?.blocking ?? []).slice(0, 200));

  const aqlTime = await callTool(url, token, 'validate_query', {
    query: 'SELECT sourceip FROM events WHERE destinationport = 445 LAST 24 HOURS LIMIT 10',
    language: 'aql',
  });
  check('a hand-written time bound is blocked (the backend injects it)',
    (aqlTime.obj?.blocking ?? []).some(f => f.kind === 'aql.time-bound-in-query'));

  const aqlJoin = await callTool(url, token, 'validate_query', {
    query: 'SELECT sourceip FROM events INNER JOIN flows ON events.sourceip = flows.sourceip LIMIT 5',
    language: 'aql',
  });
  check('JOIN is blocked (Ariel has none)',
    (aqlJoin.obj?.blocking ?? []).some(f => f.kind === 'aql.no-join'));

  const aqlAgg = await callTool(url, token, 'validate_query', {
    query: 'SELECT sourceip, COUNT(*) AS n FROM events WHERE destinationport = 445 GROUP BY sourceip LIMIT 50',
    language: 'aql',
  });
  check('aggregation warns about per-chunk counting',
    (aqlAgg.obj?.warnings ?? []).some(f => f.kind === 'aql.aggregation-with-chunking'));

  // ---- §8 step 7: network-bound tools ------------------------------------
  console.log('\n=== §8 step 7: "Look up CVE-2021-44228" (needs outbound HTTPS) ===');
  const cve = await callTool(url, token, 'nvd_cve_lookup', { cve_id: 'CVE-2021-44228' });
  const cveOk = cve.obj?.success !== false && /log4j|Apache/i.test(String(cve.raw));
  if (cveOk) check('NVD lookup succeeded', true);
  else note('NVD lookup did not succeed', 'expected on an isolated or proxied host — the model must ' +
    'say the check did not run rather than treating it as clean');

  // ---- read-only ----------------------------------------------------------
  console.log('\n=== Read-only really is read-only ===');
  const write = await callTool(url, token, 'create_entity', { name: 'preflight', entity_type: 'test' });
  check('a write tool is not reachable under the profile',
    write.isError === true || /not available|unknown tool/i.test(String(write.raw)),
    String(write.raw).slice(0, 140));

} catch (err) {
  console.error(`\nerror during preflight: ${err.message}`);
  done(1);
}

console.log('\n' + '='.repeat(64));
console.log(`  ${pass} passed, ${fail} failed${warn ? `, ${warn} noted` : ''}`);
console.log('='.repeat(64));
console.log('\nThis verifies the server, the transport and the data.');
console.log('It does NOT verify that Gemma picks the right tool, fills arguments');
console.log('correctly, or follows the authoring sequence — that needs the model.');
console.log('Run the seven questions in GEMMA-RUNBOOK.md §8 against the real stack.');
console.log('If one of them fails there and passed here, the fault is above the server.\n');

done(fail === 0 ? 0 : 1);
