#!/usr/bin/env node
/**
 * Verify the HTTP transport over real HTTP.
 *
 * This is the piece that decides whether the server is reachable from Open
 * WebUI at all, so it is tested by starting the actual process and sending
 * actual requests — not by unit-testing the config resolver and hoping.
 *
 * What matters here, in order:
 *   1. stdio is still the default. An existing Claude Desktop configuration
 *      must be unaffected by the existence of this code path.
 *   2. The MCP handshake and a tool call complete over HTTP.
 *   3. Authentication is enforced, and a non-loopback bind without a token
 *      refuses to start rather than warning.
 *
 * Local only: binds 127.0.0.1 on an ephemeral port. No outbound network.
 *
 * Usage: npm run verify:http
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import net from 'node:net';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = path.join(ROOT, 'dist', 'index.js');
const DB = process.env.DETECTIONS_DB_PATH ?? path.join(ROOT, 'data', 'detections.db');

if (!existsSync(ENTRY)) {
  console.error('error: dist/index.js not found — run "npm run build" first.');
  process.exit(2);
}

// Read from the profile definition, not a literal — see the note in
// verify-readonly-profiles.mjs. The subject here is the transport, so the
// expected tool count should track whatever the profile currently declares.
const { PROFILES } = await import(
  pathToFileURL(path.join(ROOT, 'dist', 'tools', 'profiles.js')).href
);
const PHASE1_SIZE = PROFILES['phase1-authoring'].include.length;
if (!existsSync(DB)) {
  console.error(`error: no database at ${DB}.`);
  process.exit(2);
}

let pass = 0, fail = 0;
function check(name, ok, detail = '') {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + String(detail).slice(0, 220) : ''}`); }
}

/** An unused port, so a busy 8765 on the developer's machine cannot fail this. */
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/** Start the server and wait for the line that proves it is listening. */
function startServer(env, { waitFor, timeoutMs = 90000 }) {
  return new Promise((resolve) => {
    const proc = spawn(process.execPath, [ENTRY], {
      cwd: ROOT,
      env: {
        ...process.env,
        DETECTIONS_DB_PATH: DB,
        HAWKEYE_READONLY: '1',
        HAWKEYE_SKIP_SYNC: '1',
        ...env,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let err = '', out = '', settled = false;
    const done = (ready, exitCode) => {
      if (settled) return;
      settled = true;
      resolve({ proc, ready, stderr: () => err, stdout: () => out, exitCode });
    };
    proc.stderr.on('data', d => {
      err += d;
      if (waitFor && err.includes(waitFor)) done(true, undefined);
    });
    proc.stdout.on('data', d => { out += d; });
    proc.on('exit', code => done(false, code));
    setTimeout(() => done(false, undefined), timeoutMs);
  });
}

/**
 * One POST. Carries the session header when given one, because that is what a
 * real client does: initialize returns Mcp-Session-Id and every subsequent
 * request must echo it back. Omitting it is how this test initially "found" a
 * bug that was its own.
 */
const rpc = async (url, body, token, sessionId) => {
  const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* may be SSE-framed */ }
  if (!json) {
    // enableJsonResponse should prevent this, but parse an SSE frame if present.
    const m = /^data:\s*(\{[\s\S]*)$/m.exec(text);
    if (m) { try { json = JSON.parse(m[1]); } catch { /* leave null */ } }
  }
  return { status: res.status, json, text, sessionId: res.headers.get('mcp-session-id') };
};

/** Full handshake, returning the session a client would then reuse. */
const handshake = async (url, token) => {
  const init = await rpc(url, {
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {},
              clientInfo: { name: 'verify-http', version: '1.0.0' } },
  }, token);
  const sid = init.sessionId;
  if (sid) {
    await rpc(url, { jsonrpc: '2.0', method: 'notifications/initialized' }, token, sid);
  }
  return { init, sid };
};

// ---------------------------------------------------------------------------
console.log('\n=== 1. stdio remains the default ===');
{
  const s = await startServer({}, { waitFor: 'Server started', timeoutMs: 90000 });
  check('server starts with no transport env set', s.ready, s.stderr().slice(-200));
  check('reports the stdio transport', /Enhanced Edition, stdio\)/.test(s.stderr()),
    (s.stderr().match(/Server started.*/) ?? [''])[0]);
  check('opens no listening socket', !/MCP over HTTP/.test(s.stderr()));
  s.proc.kill('SIGKILL');
}

console.log('\n=== 2. MCP works end to end over HTTP ===');
{
  const port = await freePort();
  const token = 'test-token-' + Math.random().toString(36).slice(2);
  const s = await startServer(
    { HAWKEYE_TRANSPORT: 'http', HAWKEYE_HTTP_PORT: String(port), HAWKEYE_HTTP_TOKEN: token,
      HAWKEYE_TOOL_PROFILE: 'phase1-authoring' },
    { waitFor: 'MCP over HTTP' });
  check('http transport starts', s.ready, s.stderr().slice(-260));

  if (s.ready) {
    const base = `http://127.0.0.1:${port}`;
    const url = `${base}/mcp`;

    const health = await fetch(`${base}/health`);
    check('health endpoint answers without a token', health.status === 200, String(health.status));

    const { init, sid } = await handshake(url, token);
    check('initialize succeeds', init.status === 200 && Boolean(init.json?.result),
      `${init.status} ${init.text.slice(0, 160)}`);
    check('server instructions arrive over HTTP',
      typeof init.json?.result?.instructions === 'string',
      String(init.json?.result?.instructions ?? '').slice(0, 80));
    check('initialize returns a session id', Boolean(sid), String(sid));

    const list = await rpc(url, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, token, sid);
    const tools = list.json?.result?.tools ?? [];
    check('tools/list returns the scoped profile over HTTP', tools.length === PHASE1_SIZE,
      `${list.status} got ${tools.length} — ${list.text.slice(0, 140)}`);

    const call = await rpc(url, {
      jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: 'search_detections', arguments: { query: 'certutil download', limit: 2 } },
    }, token, sid);
    const payload = call.json?.result?.content?.[0]?.text ?? '';
    check('a real tool call returns real data over HTTP',
      /certutil/i.test(payload), `${call.status} ${payload.slice(0, 140) || call.text.slice(0, 140)}`);
    check('the FTS engine is used over HTTP', /"engine":\s*"fts5"/.test(payload),
      payload.slice(0, 120));

    // A second client must get its own session rather than sharing the first's.
    const second = await handshake(url, token);
    check('a second client gets a distinct session',
      Boolean(second.sid) && second.sid !== sid, `${sid} vs ${second.sid}`);
    const stillWorks = await rpc(url,
      { jsonrpc: '2.0', id: 4, method: 'tools/list', params: {} }, token, sid);
    check('the first session still works after a second connects',
      (stillWorks.json?.result?.tools ?? []).length === PHASE1_SIZE,
      `got ${(stillWorks.json?.result?.tools ?? []).length}`);

    // Without a session, a non-initialize request has to be refused rather
    // than served from whichever session happens to exist.
    const noSession = await rpc(url,
      { jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} }, token);
    check('a request with no session id is refused, not served',
      noSession.status === 400, `${noSession.status} ${noSession.text.slice(0, 120)}`);
    const bogus = await rpc(url,
      { jsonrpc: '2.0', id: 6, method: 'tools/list', params: {} }, token, 'not-a-real-session');
    check('an unknown session id is refused', bogus.status === 400,
      `${bogus.status} ${bogus.text.slice(0, 120)}`);
  }
  s.proc.kill('SIGKILL');
}

console.log('\n=== 3. Authentication is enforced ===');
{
  const port = await freePort();
  const token = 'secret-' + Math.random().toString(36).slice(2);
  const s = await startServer(
    { HAWKEYE_TRANSPORT: 'http', HAWKEYE_HTTP_PORT: String(port), HAWKEYE_HTTP_TOKEN: token },
    { waitFor: 'MCP over HTTP' });
  check('server started for the auth checks', s.ready, s.stderr().slice(-200));

  if (s.ready) {
    const url = `http://127.0.0.1:${port}/mcp`;
    // Auth is checked before session routing, so these must be 401 rather than
    // the 400 an unknown session would produce.
    const init = { jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {},
                clientInfo: { name: 'probe', version: '1' } } };

    const noAuth = await rpc(url, init);
    check('request without a token is rejected', noAuth.status === 401, String(noAuth.status));

    const wrong = await rpc(url, init, 'wrong-token-entirely');
    check('request with the wrong token is rejected', wrong.status === 401, String(wrong.status));

    const sameLength = await rpc(url, init, 't'.repeat(token.length));
    check('a same-length wrong token is rejected', sameLength.status === 401,
      String(sameLength.status));

    const good = await rpc(url, init, token);
    check('the correct token is accepted', good.status === 200, String(good.status));

    const unknown = await fetch(`http://127.0.0.1:${port}/not-mcp`);
    check('unknown path returns 404, not the tool surface', unknown.status === 404,
      String(unknown.status));
  }
  s.proc.kill('SIGKILL');
}

console.log('\n=== 4. Misconfiguration fails loudly rather than silently ===');
{
  const port = await freePort();
  const s = await startServer(
    { HAWKEYE_TRANSPORT: 'http', HAWKEYE_HTTP_HOST: '0.0.0.0', HAWKEYE_HTTP_PORT: String(port) },
    { waitFor: 'MCP over HTTP', timeoutMs: 60000 });
  check('non-loopback bind without a token refuses to start', s.ready === false && s.exitCode === 1,
    `ready=${s.ready} exit=${s.exitCode}`);
  check('the refusal explains itself', /Refusing to bind 0\.0\.0\.0/.test(s.stderr()),
    (s.stderr().match(/FATAL.*/) ?? [''])[0].slice(0, 180));
  try { s.proc.kill('SIGKILL'); } catch { /* already gone */ }

  const bad = await startServer({ HAWKEYE_TRANSPORT: 'websocket' },
    { waitFor: 'MCP over HTTP', timeoutMs: 60000 });
  check('an unknown transport name is fatal', bad.ready === false && bad.exitCode === 1,
    `exit=${bad.exitCode}`);
  check('it names the valid options', /Use "stdio" \(default\) or "http"/.test(bad.stderr()),
    (bad.stderr().match(/FATAL.*/) ?? [''])[0].slice(0, 160));
  try { bad.proc.kill('SIGKILL'); } catch { /* already gone */ }

  const badPort = await startServer(
    { HAWKEYE_TRANSPORT: 'http', HAWKEYE_HTTP_PORT: 'not-a-port' },
    { waitFor: 'MCP over HTTP', timeoutMs: 60000 });
  check('an invalid port is fatal', badPort.ready === false && badPort.exitCode === 1,
    `exit=${badPort.exitCode}`);
  try { badPort.proc.kill('SIGKILL'); } catch { /* already gone */ }
}

console.log(`\n${'='.repeat(52)}`);
console.log(`  ${pass} passed, ${fail} failed`);
console.log('='.repeat(52));
process.exit(fail === 0 ? 0 : 1);
