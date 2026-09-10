#!/usr/bin/env node
/**
 * The AQL bridge: QRadar Ariel spec, validation, and the Sigma -> AQL brief.
 *
 * This suite exists because AQL is the only language here with no corpus behind
 * it. KQL is graded against 5,509 real rules and SPL against 2,185; AQL has
 * zero, so nothing about it is checked by the coverage suites and every claim
 * has to be pinned down explicitly or it silently rots.
 *
 * Three things are under test, in order of how much damage they prevent:
 *
 *   1. The pipeline constraints. The Phase 2 backend appends its own START/STOP
 *      and domainId and chunks long ranges daily. A query that writes its own
 *      time bound conflicts with the injected one; an aggregate over a range
 *      longer than 7 days comes back computed per day and concatenated. Both
 *      are silent in production, which is what makes them worth a gate.
 *   2. That the gate does not fire on correct queries. The spec's own worked
 *      examples are validated here, and an earlier extractor bug failed four of
 *      them by reading words out of quoted property names. A validator that
 *      rejects its own documentation is worse than none.
 *   3. That normalised Ariel properties and Custom Event Properties are graded
 *      differently and never conflated.
 *
 * Offline. Reads the database read-only and never writes.
 *
 * Usage: npm run build && node tests/verify-aql-bridge.mjs
 */
import { pathToFileURL } from 'node:url';
import { fileURLToPath } from 'node:url';
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
const { initDbAsync, runQuery } = await import(url('db', 'connection.js'));
await initDbAsync();

const { validateQuery } = await import(url('tools', 'engineering', 'validate.js'));
const { buildTranslationBrief } = await import(url('tools', 'engineering', 'translate.js'));
const { SPECS, LANGUAGE_IDS, normaliseLanguage, extract, classifyAqlProperties } =
  await import(url('reference', 'query-languages', 'index.js'));
const { AQL_EVENT_PROPERTIES, AQL_TABLES } = await import(url('reference', 'query-languages', 'aql.js'));
const { CATEGORY_SOURCES, FIELD_MAPPINGS, MODIFIER_TRANSLATION, isAqlCustomProperty } =
  await import(url('reference', 'query-languages', 'field-mappings.js'));

let pass = 0, fail = 0;
const check = (name, ok, detail = '') => {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + String(detail).slice(0, 220) : ''}`); }
};
const v = (q, ctx) => validateQuery(q, 'aql', ctx);
const kinds = r => [...r.blocking, ...r.warnings].map(f => f.kind);
const blocks = (r, kind) => r.blocking.some(f => f.kind === kind);
const warns = (r, kind) => r.warnings.some(f => f.kind === kind);

console.log('\n=== 1. Registration ===');
check('aql is a registered language', LANGUAGE_IDS.includes('aql'), LANGUAGE_IDS.join(','));
check('qradar alias resolves', normaliseLanguage('qradar') === 'aql');
check('ariel alias resolves', normaliseLanguage('Ariel') === 'aql');
check('spec is marked unconfirmed', SPECS.aql.confidence === 'unconfirmed', SPECS.aql.confidence);
check('two Ariel tables, no more', AQL_TABLES.length === 2 && AQL_TABLES.includes('events'));

console.log('\n=== 2. The spec validates its own worked examples ===');
// The regression that matters most. Every example here is documentation a model
// is handed and told to imitate; an example that fails the gate teaches it to
// distrust the gate.
for (const ex of SPECS.aql.examples) {
  const r = v(ex.query);
  check(`example validates: ${ex.title}`, r.valid,
    r.blocking.map(f => `${f.kind}:${f.subject ?? ''}`).join(' | '));
}

console.log('\n=== 3. Pipeline constraints (the reason this bridge exists) ===');
{
  const timed = "SELECT sourceip FROM events WHERE destinationport = 4444 LAST 24 HOURS LIMIT 10";
  check('hand-written LAST blocks in the pipeline',
    blocks(v(timed, 'hunt-pipeline'), 'aql.time-bound-in-query'), kinds(v(timed, 'hunt-pipeline')));
  check('...and is allowed standalone',
    !blocks(v(timed, 'standalone'), 'aql.time-bound-in-query'));

  const started = "SELECT sourceip FROM events WHERE destinationport = 4444 START 1757462400000 STOP 1757548800000 LIMIT 10";
  check('hand-written START/STOP blocks in the pipeline',
    blocks(v(started), 'aql.time-bound-in-query'), kinds(v(started)));

  const dom = "SELECT sourceip FROM events WHERE domainId = 3 AND destinationport = 445 LIMIT 10";
  check('hand-written domainId blocks in the pipeline',
    blocks(v(dom), 'aql.domain-id-in-query'), kinds(v(dom)));
  // Both pipeline rules are conditional for the same reason: each describes
  // something the backend does to the query, and standalone there is no
  // backend. A hand-written domainId is then ordinary tenant scoping, not a
  // clash with an injected predicate.
  check('...and is allowed standalone, where nothing injects a competing domainId',
    !blocks(v(dom, 'standalone'), 'aql.domain-id-in-query'),
    kinds(v(dom, 'standalone')));

  // The guard promised to the integration team. The backend splits a range over
  // 7 days into one query per day and concatenates the CSVs, so each chunk
  // aggregates only its own day and nothing re-adds them.
  const agg = 'SELECT sourceip, COUNT(*) AS hits FROM events WHERE destinationport = 445 ' +
    'GROUP BY sourceip ORDER BY hits DESC LIMIT 50';
  check('GROUP BY warns about per-chunk aggregation',
    warns(v(agg), 'aql.aggregation-with-chunking'), kinds(v(agg)));
  check('...as a warning, not a block — it is correct for ranges of 7 days or less',
    v(agg).valid, v(agg).blocking.map(f => f.kind).join(','));

  const uniq = 'SELECT sourceip, UNIQUECOUNT(username) AS n FROM events WHERE category = 3117 ' +
    'GROUP BY sourceip HAVING n > 10 LIMIT 10';
  check('UNIQUECOUNT also triggers the chunking warning',
    warns(v(uniq), 'aql.aggregation-with-chunking'));
  check('an alias reused in HAVING is not an unknown property',
    !blocks(v(uniq), 'unknown_ariel_property'),
    v(uniq).blocking.map(f => f.subject).join(','));

  const plain = "SELECT sourceip, destinationip FROM events WHERE destinationport = 445 LIMIT 10";
  check('a non-aggregating query is not warned about chunking',
    !warns(v(plain), 'aql.aggregation-with-chunking'));
}

console.log('\n=== 4. Ariel language limits ===');
{
  const j = 'SELECT sourceip FROM events INNER JOIN flows ON events.sourceip = flows.sourceip LIMIT 5';
  const rj = v(j);
  check('JOIN blocks', blocks(rj, 'aql.no-join'), kinds(rj));
  check('JOIN reports one finding, not a pile of phantom properties',
    rj.blocking.length === 1, rj.blocking.map(f => f.kind).join(','));

  check('UNION blocks',
    blocks(v('SELECT sourceip FROM events UNION SELECT sourceip FROM flows LIMIT 5'), 'aql.no-join'));
  check('subquery in FROM blocks',
    blocks(v('SELECT sourceip FROM (SELECT sourceip FROM events) LIMIT 5'), 'aql.no-join'));

  check('REGEXP is rejected — Ariel spells it MATCHES',
    blocks(v("SELECT sourceip FROM events WHERE username REGEXP 'admin.*' LIMIT 5"),
      'aql.wrong-regex-operator'));
  check('MATCHES is accepted',
    !blocks(v("SELECT sourceip FROM events WHERE username MATCHES 'admin.*' LIMIT 5"),
      'aql.wrong-regex-operator'));

  check('unknown Ariel table blocks',
    blocks(v('SELECT sourceip FROM DeviceProcessEvents WHERE sourceip IS NOT NULL LIMIT 5'),
      'unknown_ariel_table'));
  check('flows is a valid table',
    !blocks(v('SELECT sourceip FROM flows WHERE destinationport = 443 LIMIT 5'), 'unknown_ariel_table'));
}

console.log('\n=== 5. A query in the wrong language fails loudly ===');
{
  const kql = 'DeviceProcessEvents\n| where FileName == "powershell.exe"\n| project Timestamp';
  const r = v(kql);
  check('KQL submitted as AQL is rejected', !r.valid);
  check('...and says there is no SELECT/FROM', blocks(r, 'aql.no-select'), kinds(r));
  check('...and names the pipeline syntax', blocks(r, 'aql.pipeline-syntax'));

  const spl = '| tstats count from datamodel=Endpoint.Processes by Processes.process';
  check('SPL submitted as AQL is rejected', !v(spl).valid);
}

console.log('\n=== 6. Normalised properties vs Custom Event Properties ===');
{
  const q = 'SELECT starttime, sourceip, username, "Process Name" FROM events ' +
    'WHERE "Process Name" ILIKE \'%cmd.exe\' LIMIT 10';
  const r = v(q);
  check('the query is valid', r.valid, r.blocking.map(f => f.title).join(' | '));
  check('CEPs are extracted separately from bare properties',
    (r.observed.customProperties ?? []).includes('Process Name'),
    JSON.stringify(r.observed.customProperties));
  check('words inside a quoted CEP are not read as properties',
    !r.observed.fields.includes('process') && !r.observed.fields.includes('name'),
    r.observed.fields.join(','));
  check('normalised properties are recognised',
    ['starttime', 'sourceip', 'username'].every(p => r.observed.fields.includes(p)),
    r.observed.fields.join(','));
  check('every CEP is reported as unverified', warns(r, 'custom_event_properties'));
  check('CEPs are listed in the confidence block',
    r.confidence.unverifiedFields.includes('Process Name'));

  const typo = "SELECT sourceipp FROM events WHERE sourceipp = '10.0.0.1' LIMIT 5";
  const rt = v(typo);
  check('a misspelled normalised property blocks', blocks(rt, 'unknown_ariel_property'));
  check('...and suggests the real one',
    (rt.blocking.find(f => f.kind === 'unknown_ariel_property')?.suggestions ?? []).includes('sourceip'),
    JSON.stringify(rt.blocking[0]?.suggestions));

  // String literals must not contribute properties either.
  const lit = "SELECT sourceip FROM events WHERE username = 'administrator' LIMIT 5";
  check('a string literal is not read as a property',
    !v(lit).observed.fields.includes('administrator'), v(lit).observed.fields.join(','));

  const { normalised, unknown } = classifyAqlProperties(['sourceip', 'notathing'], new Set());
  check('classifyAqlProperties splits known from unknown',
    normalised.includes('sourceip') && unknown.includes('notathing'));
}

console.log('\n=== 7. Honesty about what was and was not checked ===');
{
  const r = v('SELECT sourceip FROM events WHERE destinationport = 445 LIMIT 5');
  check('confidence tier is unconfirmed', r.confidence.tier === 'unconfirmed');
  check('the note says there is no AQL corpus', /no AQL rules in the corpus/i.test(r.confidence.note),
    r.confidence.note.slice(0, 90));
  check('catalogAvailable is false — AQL never consults it',
    r.catalogAvailable === false);
  check('submissionContext is echoed back', r.submissionContext === 'hunt-pipeline');
  check('authority points at IBM', /ibm\.com/.test(r.authority), r.authority);
}

console.log('\n=== 8. Sigma -> AQL translation brief ===');
{
  const row = runQuery(
    `SELECT id, name FROM detections
     WHERE source_type = 'sigma' AND logsource_category = 'process_creation'
       AND raw_content LIKE '%CommandLine%' LIMIT 1`
  )[0];
  check('a process_creation Sigma rule exists to translate', Boolean(row));

  const brief = buildTranslationBrief('aql', { detectionId: row.id });
  check('brief resolves the shape', brief.shape === 'process_creation', String(brief.shape));
  check('brief targets the events table', brief.target.source === 'events', String(brief.target.source));
  check('brief carries AQL prohibitions', brief.target.prohibitions.some(p => p.id === 'aql.no-join'));
  check('brief returns no query — that is the model\'s job', brief.query === undefined);

  const cl = brief.fieldMappings.find(f => f.sigmaField === 'CommandLine');
  check('CommandLine maps to a quoted CEP', cl && isAqlCustomProperty(cl.target), JSON.stringify(cl));
  check('...and is graded unconfirmed', cl?.confidence === 'unconfirmed', cl?.confidence);
  check('...with the per-deployment reason, not a missing-catalog one',
    /per log source|deployment/i.test(cl?.evidence ?? ''), cl?.evidence?.slice(0, 90));

  check('AQL instructions warn about the injected time bound',
    brief.instructions.some(i => /time bound|domainId/i.test(i)));
  check('AQL instructions warn about the missing JOIN',
    brief.instructions.some(i => /no JOIN/i.test(i)));
  check('AQL instructions warn about chunked aggregation',
    brief.instructions.some(i => /7 days/i.test(i)));
  check('cautions name the CEPs as deployment-specific',
    brief.cautions.some(c => /Custom Event Propert/i.test(c)), JSON.stringify(brief.cautions).slice(0, 140));

  // A normalised property must grade differently from a CEP, or the whole
  // distinction is decorative.
  const net = runQuery(
    `SELECT id FROM detections WHERE source_type = 'sigma'
       AND logsource_category = 'network_connection' LIMIT 1`
  )[0];
  if (net) {
    const nb = buildTranslationBrief('aql', { detectionId: net.id });
    const confirmed = nb.fieldMappings.filter(f => f.confidence === 'confirmed');
    check('network_connection yields at least one confirmed normalised property',
      confirmed.length > 0, JSON.stringify(nb.fieldMappings.map(f => [f.target, f.confidence])));
    check('...and confirmed targets are unquoted',
      confirmed.every(f => !isAqlCustomProperty(f.target)),
      confirmed.map(f => f.target).join(','));
  }
}

console.log('\n=== 9. Mapping table integrity ===');
{
  check('every category has an AQL source',
    Object.values(CATEGORY_SOURCES).every(s => s.aql === 'events'),
    Object.entries(CATEGORY_SOURCES).filter(([, s]) => s.aql !== 'events').map(([c]) => c).join(','));

  check('every Sigma modifier has an AQL translation',
    Object.values(MODIFIER_TRANSLATION).every(m => typeof m.aql === 'string' && m.aql.length > 0),
    Object.entries(MODIFIER_TRANSLATION).filter(([, m]) => !m.aql).map(([k]) => k).join(','));

  // An unquoted AQL target must be a real normalised property. A bare name that
  // is neither is the failure mode this whole file guards against: it looks
  // authoritative and resolves to nothing.
  const bad = [];
  for (const [cat, table] of Object.entries(FIELD_MAPPINGS)) {
    for (const [field, t] of Object.entries(table)) {
      if (typeof t.aql !== 'string') continue;
      if (isAqlCustomProperty(t.aql)) continue;
      if (!AQL_EVENT_PROPERTIES.has(t.aql.toLowerCase())) bad.push(`${cat}.${field}=${t.aql}`);
    }
  }
  check('every unquoted AQL target is a real normalised property', bad.length === 0, bad.join(', '));

  let cepCount = 0, normCount = 0;
  for (const table of Object.values(FIELD_MAPPINGS)) {
    for (const t of Object.values(table)) {
      if (typeof t.aql !== 'string') continue;
      if (isAqlCustomProperty(t.aql)) cepCount++; else normCount++;
    }
  }
  check('both kinds of mapping are present', cepCount > 0 && normCount > 0,
    `cep=${cepCount} normalised=${normCount}`);
  console.log(`        ${normCount} normalised mappings, ${cepCount} custom-property mappings`);
}

console.log('\n=== 10. Extraction does not crash on hostile input ===');
for (const q of ['', '   ', 'SELECT', '"', "'", 'SELECT * FROM events WHERE a = "unclosed LIMIT 1']) {
  try {
    extract(q, 'aql');
    validateQuery(q, 'aql');
    check(`survives ${JSON.stringify(q.slice(0, 24))}`, true);
  } catch (e) {
    check(`survives ${JSON.stringify(q.slice(0, 24))}`, false, e.message);
  }
}

console.log('\n' + '='.repeat(52));
console.log(`  ${pass} passed, ${fail} failed`);
console.log('='.repeat(52));
process.exit(fail === 0 ? 0 : 1);
