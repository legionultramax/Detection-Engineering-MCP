#!/usr/bin/env node
/**
 * Compatibility with a small local model — specifically Gemma 4 26B-A4B served
 * by vLLM behind Open WebUI.
 *
 * This suite turns research findings into regressions. Each check corresponds
 * to a documented constraint of that deployment, so a change that quietly
 * breaks it fails here rather than in production:
 *
 *   1. Schema shape. Gemma 4 accepts OpenAI-style tool specs but degrades on
 *      deeply nested schemas and complex enums; guidance is one to two levels.
 *      Every tool in this server must stay inside that.
 *   2. Payload size. vLLM's own Gemma 4 recipe recommends --max-model-len
 *      16384, not the model's 256K ceiling. The full 132-tool surface does not
 *      fit in it at all; the scoped profile must.
 *   3. Response size. Measured, list_by_mitre at the historical default of 50
 *      rows was ~4,500 tokens — 28% of a 16K window for one call. The
 *      HAWKEYE_MAX_RESULTS budget exists for that and must actually bind.
 *   4. Argument hygiene. vLLM's gemma4 tool parser leaks the model's own
 *      string delimiters into argument values (vllm#39468, vllm#44522). A
 *      search term arriving as <|"|>certutil<|"|> matches nothing and reads as
 *      "no coverage", so the server repairs it and says so.
 *
 * Offline, read-only. Usage: npm run build && node tests/verify-gemma-compat.mjs
 */
import { pathToFileURL, fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
if (!existsSync(path.join(ROOT, 'dist', 'index.js'))) {
  console.error('error: dist not found — run "npm run build" first.');
  process.exit(2);
}
const DB = process.env.DETECTIONS_DB_PATH ?? path.join(ROOT, 'data', 'detections.db');
if (!existsSync(DB)) {
  console.error(`error: no database at ${DB}.`);
  process.exit(2);
}
process.env.DETECTIONS_DB_PATH = DB;
process.env.HAWKEYE_READONLY = '1';
process.env.HAWKEYE_SKIP_SYNC = '1';

const url = (...p) => pathToFileURL(path.join(ROOT, 'dist', ...p)).href;
const { initDbAsync } = await import(url('db', 'connection.js'));
await initDbAsync();
const mod = await import(url('tools', 'index.js'));
const realErr = console.error;
console.error = () => {};
mod.registerAllTools();
console.error = realErr;
const { PROFILES } = await import(url('tools', 'profiles.js'));
const { sanitizeToolArgs, resetSanitizeNoticeForTests } =
  await import(url('tools', 'sanitize.js'));
const { resolveLimit, resetLimitCacheForTests } = await import(url('config', 'limits.js'));

let pass = 0, fail = 0;
const check = (name, ok, detail = '') => {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); }
};
const TOK = 3.5;
const tok = n => Math.round(n / TOK);
const run = async (n, a) => {
  const o = await mod.toolRegistry.execute(n, a);
  return typeof o === 'string' ? o : JSON.stringify(o);
};

const PROFILE = [...PROFILES['phase1-authoring'].include];

console.log('\n=== 1. Schema shape stays inside Gemma 4\'s ceiling ===');
{
  const depth = (o, d = 0) => {
    if (!o || typeof o !== 'object') return d;
    let m = d;
    for (const v of Object.values(o)) if (v && typeof v === 'object') m = Math.max(m, depth(v, d + 1));
    return m;
  };
  // Depth 2 is a flat property bag: properties -> propName -> {type, description}.
  // Deeper means a nested object or an array of objects, which is what a small
  // model's schema handling degrades on first.
  const violations = (tools) => ({
    deep: tools.filter(t => depth(t.inputSchema?.properties ?? {}) > 2).map(t => t.name),
    combinator: tools.filter(t =>
      /"anyOf"|"oneOf"|"allOf"|"\$ref"/.test(JSON.stringify(t.inputSchema ?? {}))).map(t => t.name),
    objectArg: tools.filter(t =>
      Object.values(t.inputSchema?.properties ?? {}).some(p => p?.type === 'object')).map(t => t.name),
    wide: tools.filter(t => Object.keys(t.inputSchema?.properties ?? {}).length > 8)
      .map(t => `${t.name}(${Object.keys(t.inputSchema.properties).length})`),
  });

  // --- The profile is what Gemma is actually handed. It must be clean. ---
  mod.toolRegistry.setProfile(PROFILE);
  const scoped = mod.toolRegistry.toMcpTools();
  const s = violations(scoped);
  check('profile: no argument nests more than one level', s.deep.length === 0, s.deep.join(', '));
  check('profile: no anyOf/oneOf/allOf/$ref', s.combinator.length === 0, s.combinator.join(', '));
  check('profile: no object-typed argument', s.objectArg.length === 0, s.objectArg.join(', '));
  check('profile: no tool takes more than 8 arguments', s.wide.length === 0, s.wide.join(', '));

  // --- The full surface has two known offenders. Recorded, not pretended away. ---
  //
  // generate_hunt_report takes `cards`, an array of objects with their own
  // properties; create_entity takes `properties`, a free-form object. Both are
  // excluded from phase1-authoring, so neither reaches the Gemma deployment as
  // configured — but both would degrade a `research` or `full` profile behind a
  // small model. The assertion is on the *set* rather than on zero, so a new
  // violation fails here while the known two do not produce a permanently red
  // suite that everyone learns to ignore.
  mod.toolRegistry.setProfile(null);
  const all = mod.toolRegistry.toMcpTools();
  const a = violations(all);
  const KNOWN_DEEP = ['generate_hunt_report'];
  const KNOWN_OBJECT_ARG = ['create_entity'];

  check('full surface: no new deeply-nested schema',
    a.deep.every(n => KNOWN_DEEP.includes(n)),
    `unexpected: ${a.deep.filter(n => !KNOWN_DEEP.includes(n)).join(', ')}`);
  check('full surface: no new object-typed argument',
    a.objectArg.every(n => KNOWN_OBJECT_ARG.includes(n)),
    `unexpected: ${a.objectArg.filter(n => !KNOWN_OBJECT_ARG.includes(n)).join(', ')}`);
  check('full surface: no anyOf/oneOf/allOf/$ref anywhere',
    a.combinator.length === 0, a.combinator.join(', '));
  console.log(`        known exceptions, all outside the profile: ` +
    `${[...new Set([...a.deep, ...a.objectArg])].join(', ')}`);

  mod.toolRegistry.setProfile(PROFILE);

  const emptyDesc = all.filter(t => !t.description || t.description.length < 20).map(t => t.name);
  check('every tool has a usable description', emptyDesc.length === 0, emptyDesc.join(', '));

  const badNames = all.filter(t => !/^[a-z][a-z0-9_]{2,63}$/.test(t.name)).map(t => t.name);
  check('every tool name is a safe identifier', badNames.length === 0, badNames.join(', '));
}

console.log('\n=== 2. The scoped profile fits a 16K served context ===');
{
  mod.toolRegistry.setProfile(PROFILE);
  const scoped = tok(JSON.stringify(mod.toolRegistry.toMcpTools()).length);
  mod.toolRegistry.setProfile(null);
  const full = tok(JSON.stringify(mod.toolRegistry.toMcpTools()).length);
  mod.toolRegistry.setProfile(PROFILE);

  console.log(`        profile ~${scoped} tok, full surface ~${full} tok`);
  // vLLM's Gemma 4 recipe recommends --max-model-len 16384. The tool
  // definitions are resident for the whole conversation, so a third of the
  // window is the outer bound worth tolerating.
  check('scoped profile is under a third of a 16K window', scoped < 16384 / 3, `${scoped} tok`);
  check('full surface does NOT fit 16K — which is why the profile exists',
    full > 16384, `${full} tok`);
  check('profile is a large cut against the full surface', scoped < full / 3,
    `${scoped} vs ${full}`);
}

console.log('\n=== 3. The response budget actually binds ===');
{
  resetLimitCacheForTests();
  check('resolveLimit falls back to the tool default', resolveLimit(undefined, 50) === 50);
  check('an explicit smaller limit wins', resolveLimit(5, 50) === 5);
  check('a junk limit falls back rather than becoming NaN', resolveLimit('lots', 50) === 50);
  check('a zero or negative limit falls back', resolveLimit(0, 50) === 50 && resolveLimit(-9, 50) === 50);

  // The measured worst case: one call at the historical default was ~28% of a
  // 16K window. The budget has to cut that, including when the model asks for
  // more rather than fewer.
  const wide = await run('list_by_mitre', { technique_id: 'T1059.001' });
  console.log(`        list_by_mitre at default: ${tok(wide.length)} tok (${((tok(wide.length) / 16384) * 100).toFixed(0)}% of 16K)`);

  process.env.HAWKEYE_MAX_RESULTS = '5';
  resetLimitCacheForTests();
  check('a budget of 5 caps the tool default', resolveLimit(undefined, 50) === 5);
  check('...and caps an oversized explicit request', resolveLimit(200, 50) === 5);
  check('...but still honours a smaller explicit request', resolveLimit(2, 50) === 2);
  delete process.env.HAWKEYE_MAX_RESULTS;
  resetLimitCacheForTests();

  const mit = JSON.parse(await run('get_mitigations', { technique_id: 'T1059.001' }));
  check('get_mitigations trims prose by default',
    mit.mitigations.some(m => m.description_truncated), JSON.stringify(mit).slice(0, 120));
  const mitFull = JSON.parse(await run('get_mitigations',
    { technique_id: 'T1059.001', full_descriptions: true }));
  check('...and the full text is still reachable',
    JSON.stringify(mitFull).length > JSON.stringify(mit).length);
  check('...and trimming is announced, not silent', typeof mit.note === 'string');

  const g = JSON.parse(await run('get_groups_using_technique', { technique_id: 'T1059.001' }));
  check('get_groups_using_technique reports the true total when it truncates',
    g.count >= g.returned, `count=${g.count} returned=${g.returned}`);
}

console.log('\n=== 4. Leaked Gemma tool-call delimiters are repaired ===');
{
  // The exact shape reported in vllm#39468: the parser leaves its string
  // delimiters inside the argument value.
  resetSanitizeNoticeForTests();
  const a = sanitizeToolArgs('t', { query: '<|"|>certutil<|"|>' });
  check('delimiters are stripped from a string argument', a.query === 'certutil', a.query);

  resetSanitizeNoticeForTests();
  const b = sanitizeToolArgs('t', { q: '<|tool_call>call:f{x:<|"|>v<|"|>}<tool_call|>' });
  check('a whole leaked envelope is stripped', !/<\||\|>/.test(b.q), b.q);

  const untouched = { query: 'destinationport > 1024 AND destinationport < 65535 | stats count' };
  check('ordinary comparison and pipe characters survive',
    sanitizeToolArgs('t', untouched).query === untouched.query);
  check('a clean argument object is returned unchanged by identity',
    sanitizeToolArgs('t', untouched) === untouched);

  check('non-string arguments are preserved',
    (() => { const r = sanitizeToolArgs('t', { n: 5, b: true, z: null });
             return r.n === 5 && r.b === true && r.z === null; })());
  check('nested and array arguments are cleaned',
    (() => { const r = sanitizeToolArgs('t', { a: ['<|"|>x<|"|>'], o: { k: '<|"|>y<|"|>' } });
             return r.a[0] === 'x' && r.o.k === 'y'; })());

  // End to end: a leaked search term must return the same rows as a clean one.
  // Unrepaired this returns zero, which reads as "no detections exist".
  resetSanitizeNoticeForTests();
  const clean = await run('search_detections', { query: 'certutil', limit: 5 });
  const leaked = await run('search_detections', { query: '<|"|>certutil<|"|>', limit: 5 });
  check('a leaked search term returns the same results as a clean one',
    clean === leaked, `${clean.length} B vs ${leaked.length} B`);

  const tid = await run('list_by_mitre', { technique_id: 'T1059.001', limit: 3 });
  const tidLeaked = await run('list_by_mitre', { technique_id: '<|"|>T1059.001<|"|>', limit: 3 });
  check('a leaked technique ID resolves identically', tid === tidLeaked);

  const v = await run('validate_query',
    { query: 'SELECT sourceip FROM events WHERE destinationport = 445 LIMIT 10', language: 'aql' });
  const vLeaked = await run('validate_query',
    { query: '<|"|>SELECT sourceip FROM events WHERE destinationport = 445 LIMIT 10<|"|>', language: 'aql' });
  check('a leaked query validates to the same verdict', v === vLeaked);
}

console.log('\n' + '='.repeat(52));
console.log(`  ${pass} passed, ${fail} failed`);
console.log('='.repeat(52));
process.exit(fail === 0 ? 0 : 1);
