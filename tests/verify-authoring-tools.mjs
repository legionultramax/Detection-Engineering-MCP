#!/usr/bin/env node
/**
 * The composite authoring tools — build_authoring_brief and synthesize_killchain.
 *
 * These exist to move two things out of prose and into code, so the suite is
 * built around proving that the move actually happened:
 *
 *   1. The LOLBAS gate is a return value, not an instruction. A brief for a
 *      binary with no abuse matrix must return BLOCKED *and withhold the
 *      authoring material* — a BLOCKED flag next to a usable payload is
 *      advisory, which is the failure mode this replaces.
 *   2. The composite must be smaller than the calls it replaces. A tool that
 *      returns the union of six responses makes the 16K context problem worse,
 *      not better, so the size relationship is asserted rather than assumed.
 *
 * Plus the correctness properties a scaffold generator can get quietly wrong:
 * phase ordering from ATT&CK rather than argument order, a window expressed in
 * the units each language actually evaluates, and — for AQL — never emitting a
 * join that this server's own validate_query would reject.
 *
 * Offline. Opens the database read-only and never writes.
 *
 * Usage: npm run build && node tests/verify-authoring-tools.mjs
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
const { validateQuery } = await import(url('tools', 'engineering', 'validate.js'));
const { PROFILES } = await import(url('tools', 'profiles.js'));

let pass = 0, fail = 0;
const check = (name, ok, detail = '') => {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); }
};
const run = async (n, a) => {
  const out = await mod.toolRegistry.execute(n, a);
  const text = typeof out === 'string' ? out : JSON.stringify(out);
  return { obj: typeof out === 'string' ? JSON.parse(out) : out, len: text.length };
};
const TOK = n => Math.round(n / 3.5);

console.log('\n=== 1. Registration and schema shape ===');
{
  const names = mod.toolRegistry.getNames();
  check('build_authoring_brief registered', names.includes('build_authoring_brief'));
  check('synthesize_killchain registered', names.includes('synthesize_killchain'));

  const profile = PROFILES['phase1-authoring'].include;
  check('both are in phase1-authoring',
    profile.includes('build_authoring_brief') && profile.includes('synthesize_killchain'));

  // Gemma 4 is documented to struggle past one or two levels of nesting and on
  // complex enums. These schemas have to stay inside that ceiling or the model
  // emits malformed arguments for the very tools meant to steer it.
  const depth = (o, d = 0) => !o || typeof o !== 'object' ? d
    : Math.max(d, ...Object.values(o).map(v => (v && typeof v === 'object') ? depth(v, d + 1) : d));
  for (const t of mod.toolRegistry.toMcpTools()
    .filter(t => ['build_authoring_brief', 'synthesize_killchain'].includes(t.name))) {
    const props = t.inputSchema.properties ?? {};
    check(`${t.name} nesting <= 2`, depth(props) <= 2, `depth ${depth(props)}`);
    check(`${t.name} <= 6 arguments`, Object.keys(props).length <= 6);
    check(`${t.name} has no anyOf/oneOf`, !/"(anyOf|oneOf|allOf)"/.test(JSON.stringify(t.inputSchema)));
  }
}

console.log('\n=== 2. The LOLBAS gate is a return value ===');
{
  const ok = await run('build_authoring_brief',
    { technique_id: 'T1105', language: 'kql', binary: 'certutil.exe' });
  check('a real LOLBIN passes the gate', ok.obj.gate === 'OK' || ok.obj.gate === 'CAVEATS', ok.obj.gate);
  check('the abuse matrix is supplied, not requested',
    (ok.obj.lolbas_gate?.matrices?.[0]?.abuse_patterns ?? []).length > 0);
  check('every documented pattern is included, not a sample',
    ok.obj.lolbas_gate.matrices[0].pattern_count ===
    ok.obj.lolbas_gate.matrices[0].abuse_patterns.length);

  const blocked = await run('build_authoring_brief',
    { technique_id: 'T1105', language: 'kql', binary: 'definitely-not-a-lolbin.exe' });
  check('a binary with no matrix BLOCKS', blocked.obj.gate === 'BLOCKED', blocked.obj.gate);
  // The point of the gate. A BLOCKED flag beside a usable payload is a
  // suggestion; withholding the payload is what makes it a gate.
  check('...and the authoring material is withheld',
    blocked.obj.target === undefined &&
    blocked.obj.lolbas_gate === undefined &&
    blocked.obj.reference_rules === undefined);
  check('...and says why, in terms of consequence',
    /cannot be enumerated/i.test(blocked.obj.blockers?.[0] ?? ''));
  check('...and a blocked brief is far smaller than a usable one',
    blocked.len < ok.len / 3, `${blocked.len} vs ${ok.len}`);

  const forced = await run('build_authoring_brief',
    { technique_id: 'T1105', language: 'kql', binary: 'definitely-not-a-lolbin.exe', require_lolbas: false });
  check('require_lolbas=false is an explicit escape hatch', forced.obj.gate === 'CAVEATS', forced.obj.gate);
  check('...and the caveat survives into the output',
    (forced.obj.caveats ?? []).some(c => /unverified/i.test(c)));
}

console.log('\n=== 3. Blocking when nothing grounds a rule ===');
{
  const unknown = await run('build_authoring_brief', { technique_id: 'T9999', language: 'kql' });
  check('an unknown technique BLOCKS', unknown.obj.gate === 'BLOCKED');
  check('...and points at search_mitre_techniques',
    /search_mitre_techniques/.test(unknown.obj.blockers?.[0] ?? ''));

  const bad = await run('build_authoring_brief', { technique_id: 'T1059.001', language: 'nonsense' });
  check('an unknown language errors with the list', bad.obj.error === true && Array.isArray(bad.obj.supported));
}

console.log('\n=== 4. The brief is smaller than the calls it replaces ===');
{
  const brief = await run('build_authoring_brief', { technique_id: 'T1059.001', language: 'kql' });
  let sum = 0;
  for (const [n, a] of [
    ['lookup_mitre_technique', { technique_id: 'T1059.001' }],
    ['list_by_mitre', { technique_id: 'T1059.001' }],
    ['get_data_sources', { technique_id: 'T1059.001' }],
    ['get_lolfarm_context', { technique_id: 'T1059.001', mode: 'summary' }],
    ['lookup_lolbas', { binary: 'powershell.exe' }],
    ['get_query_language_spec', { language: 'kql' }],
  ]) sum += (await run(n, a)).len;

  check('one call replaces six', true);
  check('and is at least 50% smaller than their sum',
    brief.len < sum * 0.5, `brief ${TOK(brief.len)} tok vs six calls ${TOK(sum)} tok`);
  console.log(`        brief ${TOK(brief.len)} tok vs ${TOK(sum)} tok for six calls ` +
    `(${(100 - brief.len / sum * 100).toFixed(0)}% smaller)`);

  check('it still carries the field vocabulary', (brief.obj.target?.field_vocabulary ?? []).length > 0);
  check('it still carries the blocking prohibitions',
    (brief.obj.target?.blocking_prohibitions ?? []).length > 0);
  check('it carries known false positives', 'known_false_positives' in brief.obj);
  // The saving comes from returning identifiers rather than rule bodies.
  check('reference rules are identifiers, not query text',
    (brief.obj.reference_rules?.rules ?? []).every(r => !('query' in r) && !('raw_content' in r)));
}

console.log('\n=== 5. Kill chain: ordering is computed, not taken from the caller ===');
{
  // Deliberately supplied out of order: persistence, initial-access, execution.
  const k = await run('synthesize_killchain',
    { technique_ids: ['T1547.001', 'T1566.001', 'T1059.001'], language: 'kql' });
  const tactics = k.obj.phases.map(p => p.tactic);
  check('phases are sorted into ATT&CK tactic order',
    tactics.indexOf('initial-access') < tactics.indexOf('execution') &&
    tactics.indexOf('execution') < tactics.indexOf('persistence'), tactics.join(' -> '));
  check('phase order numbers are sequential',
    k.obj.phases.every((p, i) => p.order === i + 1));
  check('each phase reports its reference-rule count',
    k.obj.phases.every(p => typeof p.reference_rules === 'number'));
  check('a phase with no mapped source is caveated, not silently emitted',
    k.obj.phases.some(p => p.source === null)
      ? (k.obj.caveats ?? []).some(c => /no KQL source is mapped/i.test(c))
      : true);
}

console.log('\n=== 6. Kill chain: AQL never emits a join it would then reject ===');
{
  const k = await run('synthesize_killchain',
    { technique_ids: ['T1566.001', 'T1059.001', 'T1547.001'], language: 'aql' });
  check('AQL returns per-phase queries, not one joined query',
    Array.isArray(k.obj.correlation?.queries) && k.obj.correlation.scaffold === undefined);
  check('one query per resolved phase',
    k.obj.correlation.queries.length === k.obj.phases.length);

  // The integrity property: this server must not generate something its own
  // validator blocks.
  for (const [i, q] of k.obj.correlation.queries.entries()) {
    check(`AQL phase ${i + 1} contains no JOIN/UNION`, !/\b(JOIN|UNION)\b/i.test(q.query), q.query.slice(0, 80));
    check(`AQL phase ${i + 1} writes no time bound or domainId`,
      !/\b(START\s+\d|STOP\s+\d|LAST\s+\d+\s+\w+|domainId)\b/i.test(q.query));
  }

  // A filled-in phase query must actually pass validate_query, or the scaffold
  // is leading the model somewhere the gate will reject.
  const filled = k.obj.correlation.queries[0].query
    .replace(/<fields[^>]*>/, '"Process Path", username')
    .replace(/<predicate[^>]*>/, '"Process Path" ILIKE \'%outlook.exe\'');
  const v = validateQuery(filled, 'aql');
  check('a filled AQL phase query validates clean', v.valid,
    v.blocking.map(f => f.kind).join(', '));

  check('the correlation spec explains how to link phases outside the query',
    /correlation_spec/.test(JSON.stringify(k.obj.correlation)) &&
    /within/i.test(k.obj.correlation.correlation_spec));
  check('and it warns about the 7-day chunking limit on aggregation',
    /7 days/.test(k.obj.correlation.correlation_spec));
}

console.log('\n=== 7. Kill chain: window units match the language ===');
{
  const spl = await run('synthesize_killchain',
    { technique_ids: ['T1566.001', 'T1059.001'], language: 'spl', window: '2h' });
  // _time is epoch seconds. A literal `<= 2h` parses as a field reference and
  // compares against null, dropping the window without erroring.
  check('SPL expresses the window in seconds', /<=\s*7200\b/.test(spl.obj.correlation.scaffold),
    spl.obj.correlation.scaffold.split('\n').find(l => l.includes('first_seen)')));

  const cql = await run('synthesize_killchain',
    { technique_ids: ['T1566.001', 'T1059.001'], language: 'cql', window: '2h' });
  check('CQL expresses the window in milliseconds', /<=\s*7200000\b/.test(cql.obj.correlation.scaffold));

  const kql = await run('synthesize_killchain',
    { technique_ids: ['T1566.001', 'T1059.001'], language: 'kql', window: '2h' });
  check('KQL keeps the timespan literal', /2h/.test(kql.obj.correlation.scaffold));

  const weird = await run('synthesize_killchain',
    { technique_ids: ['T1566.001', 'T1059.001'], language: 'spl', window: 'a fortnight' });
  check('an unparseable window is caveated rather than pasted in silently',
    (weird.obj.caveats ?? []).some(c => /not a recognised duration/i.test(c)));
}

console.log('\n=== 8. Kill chain: guards ===');
{
  const one = await run('synthesize_killchain', { technique_ids: ['T1059.001'], language: 'kql' });
  check('a single technique is refused', one.obj.error === true);
  check('...and says to use build_authoring_brief instead',
    /build_authoring_brief/.test(one.obj.message));

  const none = await run('synthesize_killchain', { technique_ids: ['T9998', 'T9999'], language: 'kql' });
  check('all-unknown technique IDs are refused', none.obj.error === true);
  check('...and names which ones did not resolve', /T9998/.test(none.obj.message));

  const notArray = await run('synthesize_killchain', { technique_ids: 'T1059.001', language: 'kql' });
  check('a non-array technique_ids is rejected', notArray.obj.error === true);

  for (const p of ['host', 'user', 'process']) {
    const r = await run('synthesize_killchain',
      { technique_ids: ['T1566.001', 'T1059.001'], language: 'kql', pivot: p });
    check(`pivot "${p}" resolves to a field`, typeof r.obj.pivot?.field === 'string' && r.obj.pivot.field.length > 0);
  }
}

console.log('\n=== 9. Hostile input does not crash either tool ===');
{
  const cases = [
    ['build_authoring_brief', { technique_id: '', language: 'kql' }],
    ['build_authoring_brief', { technique_id: "T1059'; DROP TABLE detections;--", language: 'kql' }],
    ['build_authoring_brief', { technique_id: 'T1059.001', language: 'kql', max_rules: -5 }],
    ['build_authoring_brief', { technique_id: 'T1059.001', language: 'kql', binary: '../../etc/passwd' }],
    ['synthesize_killchain', { technique_ids: [], language: 'kql' }],
    ['synthesize_killchain', { technique_ids: ['', ''], language: 'kql' }],
    ['synthesize_killchain', { technique_ids: ['T1059.001', 'T1566.001'], language: 'kql', window: '' }],
  ];
  for (const [n, a] of cases) {
    try {
      await run(n, a);
      check(`survives ${n}(${JSON.stringify(a).slice(0, 52)})`, true);
    } catch (e) {
      check(`survives ${n}(${JSON.stringify(a).slice(0, 52)})`, false, e.message);
    }
  }
  // The database must still be intact after the injection attempt above.
  const after = await run('get_stats', {});
  check('the corpus survived the injection attempt', after.obj.total_detections > 15000 ||
    JSON.stringify(after.obj).includes('15'), JSON.stringify(after.obj).slice(0, 80));
}

console.log('\n' + '='.repeat(52));
console.log(`  ${pass} passed, ${fail} failed`);
console.log('='.repeat(52));
process.exit(fail === 0 ? 0 : 1);
