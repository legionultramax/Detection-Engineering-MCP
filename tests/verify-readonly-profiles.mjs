#!/usr/bin/env node
/**
 * End-to-end verification of read-only mode, atomic writes, and tool profiles.
 *
 * Drives the built server over stdio MCP the way a real client does —
 * initialize, await the response, send notifications/initialized, then request —
 * because the behaviour under test is what a client observes, not what the
 * modules do in isolation.
 *
 * Two constraints shape this suite:
 *
 *   1. It never touches the network. The default startup path git pulls Atomic
 *      Red Team, a repository of working attack payloads, which raises alerts on
 *      an EDR-monitored endpoint. HAWKEYE_SKIP_SYNC is forced on every session,
 *      and no session runs a tool that fetches.
 *   2. It never touches the real database. A copy is made into a temporary
 *      directory that is removed on exit.
 *
 * Usage:
 *   npm run build && node tests/verify-readonly-profiles.mjs
 *   VERIFY_SOURCE_DB=/path/to/detections.db node tests/verify-readonly-profiles.mjs
 *
 * Exits 0 when every check passes, 1 on any failure, 2 if prerequisites are missing.
 */
import { spawn } from 'node:child_process';
import { statSync, existsSync, rmSync, readdirSync, mkdtempSync, copyFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import path from 'node:path';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = path.join(REPO, 'dist', 'index.js');

// Everything this suite writes lives in one throwaway directory, removed on
// exit. The real database is only ever read, and only to make a copy.
const SCRATCH = mkdtempSync(path.join(tmpdir(), 'hawkeye-verify-'));
const TEST_DB = path.join(SCRATCH, 'test.db');

const SOURCE_DB = process.env.VERIFY_SOURCE_DB ?? path.join(REPO, 'data', 'detections.db');
if (!existsSync(ENTRY)) {
  console.error('error: dist/index.js not found — run "npm run build" first.');
  process.exit(2);
}
if (!existsSync(SOURCE_DB)) {
  console.error(`error: no populated database at ${SOURCE_DB}.`);
  console.error('Set VERIFY_SOURCE_DB to one, or build the index first.');
  process.exit(2);
}
copyFileSync(SOURCE_DB, TEST_DB);

// The expected profile size is read from the profile definition rather than
// written here as a literal. A hardcoded 25 in this file went stale the moment
// two tools were added to phase1-authoring, and a test that fails because the
// test is out of date teaches people to edit the number instead of reading it.
// What is actually under test is that the server exposes exactly what the
// profile declares — so assert against the declaration.
const { PROFILES } = await import(
  pathToFileURL(path.join(REPO, 'dist', 'tools', 'profiles.js')).href
);
const PHASE1_SIZE = PROFILES['phase1-authoring'].include.length;

process.on('exit', () => {
  try { rmSync(SCRATCH, { recursive: true, force: true }); } catch { /* best effort */ }
});

let pass = 0, fail = 0;
function check(name, ok, detail = '') {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); }
}

class Client {
  constructor(env, cwd = REPO) {
    this.err = '';
    this.pending = new Map();
    this.exitCode = undefined;
    this.buf = '';
    // HAWKEYE_SKIP_SYNC is forced on for every session, as defence in depth on
    // top of read-only. The startup path git pulls Atomic Red Team — a
    // repository of working attack payloads — and this machine is an
    // EDR-monitored endpoint. No test may reach the network.
    this.proc = spawn(process.execPath, [ENTRY], {
      cwd,
      // Listed last so no caller can accidentally override it.
      env: { ...process.env, ...env, HAWKEYE_SKIP_SYNC: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.proc.stdout.on('data', d => this._onData(String(d)));
    this.proc.stderr.on('data', d => { this.err += d; });
    this.exited = new Promise(res => this.proc.on('exit', code => {
      this.exitCode = code;
      for (const { reject } of this.pending.values()) reject(new Error('process exited'));
      this.pending.clear();
      res(code);
    }));
  }

  _onData(chunk) {
    this.buf += chunk;
    const lines = this.buf.split('\n');
    this.buf = lines.pop() ?? '';
    for (const line of lines) {
      const t = line.trim();
      if (!t) continue;
      let msg;
      try { msg = JSON.parse(t); } catch { continue; }
      const p = this.pending.get(msg.id);
      if (p) { this.pending.delete(msg.id); p.resolve(msg); }
    }
  }

  request(id, method, params = {}, timeoutMs = 60000) {
    if (this.exitCode !== undefined) return Promise.reject(new Error(`exited ${this.exitCode}`));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: v => { clearTimeout(timer); resolve(v); },
        reject: e => { clearTimeout(timer); reject(e); },
      });
      this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }

  notify(method, params = {}) {
    this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  }

  async handshake(timeoutMs = 60000) {
    const init = await this.request(1, 'initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'verify', version: '1.0.0' },
    }, timeoutMs);
    this.notify('notifications/initialized');
    return init;
  }

  async list() {
    const r = await this.request(2, 'tools/list');
    return (r.result?.tools ?? []);
  }

  async call(id, name, args = {}) {
    const r = await this.request(id, 'tools/call', { name, arguments: args });
    return r.result ?? r.error ?? {};
  }

  kill() { try { this.proc.kill('SIGKILL'); } catch { /* already gone */ } }
}

/** Start a server that is expected to exit on its own, and capture why. */
async function expectExit(env, timeoutMs = 90000) {
  const c = new Client(env);
  const raced = await Promise.race([
    c.exited,
    new Promise(res => setTimeout(() => res('timeout'), timeoutMs)),
  ]);
  c.kill();
  return { exitCode: raced === 'timeout' ? 'did-not-exit' : c.exitCode, stderr: c.err };
}

const textOf = (result) => JSON.stringify(result ?? {});

// ---------------------------------------------------------------------------

console.log('\n=== 1. Read-only with no profile withholds only the 8 write tools ===');
{
  // Read-only subtracts WRITE_TOOLS from whatever profile is active, so the
  // surface here is 129 - 8 = 121. Those eight cannot function in read-only, and
  // several bulk-write then saveDb(), which would apply in memory and silently
  // never persist. Withholding beats a write that reports success and evaporates.
  //
  // The unmodified 129-tool surface is covered by session 7, which runs writable.
  // Nothing here runs default mode, because that path git pulls Atomic Red Team.
  const c = new Client({ DETECTIONS_DB_PATH: TEST_DB, HAWKEYE_READONLY: '1' });
  try {
    const init = await c.handshake();
    const instr = init.result?.instructions ?? '';
    const tools = await c.list();
    const names = tools.map(t => t.name);
    check('tools/list returns 124 (132 minus 8 writes)', names.length === 124, `got ${names.length}`);
    check('instructions advertise 124 tools', instr.includes('exposing 124 tools'), instr.slice(0, 110));
    check('knowledge write withheld', !names.includes('create_entity'));
    check('knowledge read kept', names.includes('search_entities'));
    check('sync withheld', !names.includes('sync_lolfarm'));
    check('lolfarm reads kept', names.includes('get_lolfarm_context'));
    check('all five starting points listed', (instr.match(/^- \w+\(/gm) ?? []).length === 5,
      String((instr.match(/^- \w+\(/gm) ?? []).length));
    const stats = await c.call(3, 'get_stats');
    check('get_stats returns data', stats.isError !== true, textOf(stats).slice(0, 120));
    // This tool triggers the lazy LOLFarm seeder, which is the sharpest test of
    // read-only behaviour because it wants to write on a read path.
    //
    // Under sql.js it wrote 85 constants into the in-memory image and they
    // vanished on exit, so the tool appeared to work. On better-sqlite3 the file
    // is genuinely read-only and the write is skipped, so the tool returns empty
    // instead. That is the honest outcome: reference data belongs baked into the
    // database by the indexer, not synthesised on every boot.
    //
    // What must hold either way is that a read path never fails because a
    // caching or seeding write could not happen.
    const lf = await c.call(4, 'get_lolfarm_context', { technique_id: 'T1059.001', mode: 'summary' });
    check('a read path that wants to write does not fail read-only',
      !textOf(lf).includes('EREADONLY') && !textOf(lf).includes('SQLITE_READONLY'),
      textOf(lf).slice(0, 200));
    const payload = JSON.stringify(tools);
    console.log(`        read-only payload: ${payload.length} bytes (~${Math.round(payload.length / 3.5)} tokens)`);
  } catch (e) {
    check('session 1 completed', false, e.message + ' | stderr: ' + c.err.slice(-400));
  } finally { c.kill(); }
}

console.log('\n=== 1b. Stage 1: atomic write path, exercised directly ===');
{
  // Writable mode on a small throwaway database, so the write path is verified
  // without indexing, without network, and without a 59MB image.
  const { pathToFileURL } = await import('node:url');
  const CONN = pathToFileURL(path.join(REPO, 'dist', 'db', 'connection.js')).href;
  const SMALL = path.join(SCRATCH, 'small.db');
  for (const f of readdirSync(SCRATCH).filter(n => n.startsWith('small.db'))) {
    rmSync(path.join(SCRATCH, f), { force: true });
  }
  delete process.env.HAWKEYE_READONLY;
  process.env.DETECTIONS_DB_PATH = SMALL;

  const conn = await import(CONN);
  check('isReadOnly() false when env unset', conn.isReadOnly() === false);
  await conn.initDbAsync();
  check('database file created', existsSync(SMALL));

  conn.runStatement(
    "INSERT INTO detections (id, name, source_type) VALUES (?, ?, ?)",
    ['atomic-probe', 'probe', 'sigma']
  );
  const rows = conn.runQuery("SELECT name FROM detections WHERE id = 'atomic-probe'");
  check('write readable in-session', rows.length === 1 && rows[0].name === 'probe', JSON.stringify(rows));

  const strays = readdirSync(SCRATCH).filter(n => n.startsWith('small.db.tmp'));
  check('temp file cleaned up after rename', strays.length === 0, strays.join(', '));

  // Reopen from disk in a fresh module instance to prove the rename persisted.
  conn.closeDb();
  const conn2 = await import(`${CONN}?reload=${Date.now()}`);
  process.env.DETECTIONS_DB_PATH = SMALL;
  await conn2.initDbAsync();
  const persisted = conn2.runQuery("SELECT name FROM detections WHERE id = 'atomic-probe'");
  check('write survived reopen from disk', persisted.length === 1, JSON.stringify(persisted));
  conn2.closeDb();
}

console.log('\n=== 2. Stage 1: read-only mode ===');
{
  const before = statSync(TEST_DB);
  const c = new Client({ DETECTIONS_DB_PATH: TEST_DB, HAWKEYE_READONLY: '1' });
  try {
    await c.handshake();
    const stats = await c.call(3, 'get_stats');
    check('reads still work in read-only', stats.isError !== true, textOf(stats).slice(0, 120));
    // create_entity is withheld in read-only, so it is refused at dispatch. A
    // client working from a cached tool list would hit exactly this path.
    const write = await c.call(4, 'create_entity', {
      name: 'verify-probe', entity_type: 'test', observations: ['x'],
    });
    check('withheld write tool refused at dispatch',
      textOf(write).includes('not available under the active tool profile'), textOf(write).slice(0, 200));
    check('server still alive after refused write', c.exitCode === undefined);
  } catch (e) {
    check('session 2 completed', false, e.message + ' | stderr: ' + c.err.slice(-400));
  }
  c.kill();
  await c.exited;

  const after = statSync(TEST_DB);
  check('database size unchanged', before.size === after.size, `${before.size} -> ${after.size}`);
  check('database mtime unchanged', before.mtimeMs === after.mtimeMs, `${before.mtimeMs} -> ${after.mtimeMs}`);
  check('read-only notice logged', c.err.includes('read-only mode'));
  check('indexing and sync skipped', c.err.includes('skipping indexing and upstream sync'));
  const strays = readdirSync(SCRATCH).filter(f => f.startsWith('test.db.tmp'));
  check('no stray temp files', strays.length === 0, strays.join(', '));
}

console.log('\n=== 3. Stage 2: phase1-authoring profile ===');
{
  const c = new Client({
    DETECTIONS_DB_PATH: TEST_DB, HAWKEYE_READONLY: '1', HAWKEYE_TOOL_PROFILE: 'phase1-authoring',
  });
  try {
    const init = await c.handshake();
    const instr = init.result?.instructions ?? '';
    const tools = await c.list();
    const names = tools.map(t => t.name);

    check(`tools/list returns exactly ${PHASE1_SIZE}`, names.length === PHASE1_SIZE,
      `got ${names.length}`);
    // Every declared name resolves. unresolvedNames() covers this too, but only
    // if it is called; a profile listing a renamed tool would otherwise just
    // expose fewer tools and still match the length assertion above.
    const declared = PROFILES['phase1-authoring'].include;
    const missing = declared.filter(n => !names.includes(n));
    check('every declared profile tool is exposed', missing.length === 0, missing.join(', '));
    check('in-profile tool present', names.includes('search_detections'));
    check('out-of-profile tool absent', !names.includes('ti_daily_brief'));
    check('report generator excluded', !names.includes('generate_hunt_report'));
    check('knowledge writes excluded', !names.includes('create_entity'));

    check(`instructions advertise ${PHASE1_SIZE} tools`,
      instr.includes(`exposing ${PHASE1_SIZE} tools`), instr.slice(0, 110));
    check('instructions carry scoped notice', instr.includes('scoped tool profile'));
    check('instructions omit excluded names', !instr.includes('ti_daily_brief'));

    const ok = await c.call(3, 'search_detections', { query: 'mimikatz', limit: 2 });
    check('in-profile call succeeds', ok.isError !== true, textOf(ok).slice(0, 120));

    const blocked = await c.call(4, 'ti_daily_brief');
    check('out-of-profile call refused at dispatch',
      textOf(blocked).includes('not available under the active tool profile'), textOf(blocked).slice(0, 200));

    const payload = JSON.stringify(tools);
    console.log(`        scoped payload: ${payload.length} bytes (~${Math.round(payload.length / 3.5)} tokens)`);
  } catch (e) {
    check('session 3 completed', false, e.message + ' | stderr: ' + c.err.slice(-400));
  }
  c.kill();
  await c.exited;
  check('profile logged at startup', c.err.includes('Tool profile "phase1-authoring" active'));
  check(`profile reports ${PHASE1_SIZE} of the full surface`,
    new RegExp(`${PHASE1_SIZE} of \\d+ tools exposed`).test(c.err),
    c.err.match(/\d+ of \d+ tools exposed/)?.[0] ?? '(no such line)');
}

console.log('\n=== 4. research profile excludes writes, keeps reads ===');
{
  const c = new Client({
    DETECTIONS_DB_PATH: TEST_DB, HAWKEYE_READONLY: '1', HAWKEYE_TOOL_PROFILE: 'research',
  });
  try {
    await c.handshake();
    const names = (await c.list()).map(t => t.name);
    check('exposes 124 tools (132 minus 8 writes)', names.length === 124, `got ${names.length}`);
    check('write tool excluded', !names.includes('create_entity'));
    check('read counterpart kept', names.includes('search_entities'));
    check('sync excluded', !names.includes('sync_lolfarm'));
    check('lolfarm reads kept', names.includes('lookup_loldriver'));
  } catch (e) {
    check('session 4 completed', false, e.message + ' | stderr: ' + c.err.slice(-400));
  } finally { c.kill(); }
}

console.log('\n=== 4b. HAWKEYE_MAX_RESULTS bounds response size ===');
{
  // The third deployment knob, alongside read-only and the tool profile. It
  // exists because response size is a property of the deployment: the same
  // list_by_mitre call that is a convenience in a 200K window measured ~4,500
  // tokens, 28% of the 16K context vLLM's own Gemma 4 recipe recommends.
  const textOfCall = async (c, id, name, args) => {
    const r = await c.call(id, name, args);
    return r?.content?.[0]?.text ?? '';
  };

  const big = new Client({ DETECTIONS_DB_PATH: TEST_DB, HAWKEYE_READONLY: '1' });
  const small = new Client({
    DETECTIONS_DB_PATH: TEST_DB, HAWKEYE_READONLY: '1', HAWKEYE_MAX_RESULTS: '5',
  });
  try {
    await big.handshake();
    await small.handshake();

    const wide = await textOfCall(big, 20, 'list_by_mitre', { technique_id: 'T1059.001' });
    const tight = await textOfCall(small, 20, 'list_by_mitre', { technique_id: 'T1059.001' });
    check('an unset budget keeps the historical default', wide.length > 8000, `${wide.length} B`);
    check('a set budget shrinks the response', tight.length < wide.length / 2,
      `${tight.length} B vs ${wide.length} B`);

    // The budget has to beat the caller, not just the default — a model asking
    // for 200 rows is the case a per-tool default cannot catch.
    const overreach = await textOfCall(small, 21, 'list_by_mitre',
      { technique_id: 'T1059.001', limit: 200 });
    check('an explicit oversized limit is capped too',
      overreach.length <= tight.length * 1.1, `${overreach.length} B vs ${tight.length} B`);

    // Under the cap the caller still wins, or the knob would be a straitjacket.
    const under = await textOfCall(small, 22, 'list_by_mitre',
      { technique_id: 'T1059.001', limit: 2 });
    check('a smaller explicit limit is still honoured', under.length < tight.length,
      `${under.length} B vs ${tight.length} B`);

    const groups = await textOfCall(small, 23, 'get_groups_using_technique',
      { technique_id: 'T1059.001' });
    check('get_groups_using_technique is bounded and says so',
      /"truncated"/.test(groups) && groups.length < 2000, `${groups.length} B`);

    const mit = await textOfCall(big, 24, 'get_mitigations', { technique_id: 'T1059.001' });
    check('get_mitigations trims prose by default', /description_truncated/.test(mit),
      mit.slice(0, 120));
    const mitFull = await textOfCall(big, 25, 'get_mitigations',
      { technique_id: 'T1059.001', full_descriptions: true });
    check('...and full_descriptions returns the untrimmed text', mitFull.length > mit.length,
      `${mitFull.length} B vs ${mit.length} B`);
  } catch (e) {
    check('session 4b completed', false, e.message + ' | stderr: ' + small.err.slice(-400));
  } finally { big.kill(); small.kill(); }

  // A bad value must not silently become NaN, which would let Math.min pass
  // every request straight through and disable the budget without saying so.
  const bad = new Client({
    DETECTIONS_DB_PATH: TEST_DB, HAWKEYE_READONLY: '1', HAWKEYE_MAX_RESULTS: 'lots',
  });
  try {
    await bad.handshake();
    const r = await bad.call(26, 'list_by_mitre', { technique_id: 'T1059.001' });
    check('an unparseable budget falls back rather than disabling the cap',
      (r?.content?.[0]?.text ?? '').length > 0);
    check('...and says so on stderr', /HAWKEYE_MAX_RESULTS/.test(bad.err), bad.err.slice(-160));
  } catch (e) {
    check('session 4b-bad completed', false, e.message);
  } finally { bad.kill(); }
}

console.log('\n=== 5. Unknown profile name is fatal ===');
{
  const { exitCode, stderr } = await expectExit({
    DETECTIONS_DB_PATH: TEST_DB, HAWKEYE_READONLY: '1', HAWKEYE_TOOL_PROFILE: 'phase1',
  });
  check('exits with code 1', exitCode === 1, `exit ${exitCode}`);
  check('names the bad profile', stderr.includes('Unknown tool profile "phase1"'));
  check('lists valid profiles', stderr.includes('phase1-authoring'));
}

console.log('\n=== 6. Read-only against an empty database is fatal ===');
{
  const EMPTY = path.join(SCRATCH, 'empty.db');
  if (existsSync(EMPTY)) rmSync(EMPTY);
  const { exitCode, stderr } = await expectExit({
    DETECTIONS_DB_PATH: EMPTY, HAWKEYE_READONLY: '1',
  });
  check('exits with code 1', exitCode === 1, `exit ${exitCode}`);
  // Two layers can catch this, and which one fires depends on whether the file
  // exists at all. On better-sqlite3 a read-only open of a missing file fails
  // in initDbAsync before the server gets far enough to count detections, which
  // is the earlier and more precise failure. Either message is acceptable; the
  // requirement is that it says what is wrong rather than exiting silently.
  check('explains why',
    /holds no detections|no database exists/.test(stderr),
    stderr.split('\n').filter(l => /FATAL|EREADONLY/.test(l))[0] ?? stderr.slice(-200));
  check('empty database not persisted', !existsSync(EMPTY) || statSync(EMPTY).size < 200000);
}

console.log('\n=== 7. Default writable mode with HAWKEYE_SKIP_SYNC ===');
{
  // The only safe way to exercise the writable startup path: skip the git syncs
  // so nothing pulls attack payloads and nothing blocks on an unreachable
  // remote. Runs against the small throwaway database from 1b.
  // cwd is the scratchpad, not the repo, so the local rule repositories and the
  // 7.4MB MITRE STIX bundle do not resolve. autoIndex() and autoIndexMitre()
  // then find nothing to do. That keeps this session fast and keeps it from
  // writing a fully indexed database, while still exercising the writable
  // startup path, a real write, and the skip-sync flag.
  const SMALL = path.join(SCRATCH, 'small.db');
  const c = new Client({ DETECTIONS_DB_PATH: SMALL }, SCRATCH);
  try {
    const init = await c.handshake();
    const tools = await c.list();
    check('writable mode exposes all 132 tools', tools.length === 132, `got ${tools.length}`);
    check('no scoped notice in writable default', !(init.result?.instructions ?? '').includes('scoped tool profile'));
    const w = await c.call(3, 'create_entity', {
      name: 'skip-sync-probe', entity_type: 'test', observations: ['writable'],
    });
    check('writes accepted when not read-only', !textOf(w).includes('EREADONLY'), textOf(w).slice(0, 160));
  } catch (e) {
    check('session 7 completed', false, e.message + ' | stderr: ' + c.err.slice(-400));
  }
  c.kill();
  await c.exited;
  check('skip-sync logged', c.err.includes('HAWKEYE_SKIP_SYNC set'));
  check('no git sync attempted', !c.err.includes('Pulling latest Atomic Red Team'));
  check('indexing reported complete', c.err.includes('Indexing complete'));
  const strays = readdirSync(SCRATCH).filter(n => n.startsWith('small.db.tmp'));
  check('no temp files left', strays.length === 0, strays.join(', '));
}

console.log(`\n${'='.repeat(52)}`);
console.log(`  ${pass} passed, ${fail} failed`);
console.log('='.repeat(52));
process.exit(fail === 0 ? 0 : 1);
