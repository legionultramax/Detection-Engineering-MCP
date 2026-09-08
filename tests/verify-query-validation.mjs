#!/usr/bin/env node
/**
 * Verify get_query_language_spec and validate_query.
 *
 * The load-bearing test here is the last one: every worked example in every
 * language spec is run through that language's own validator. If a spec ships
 * an example its own gate rejects, one of the two is wrong, and shipping either
 * would teach a model to write queries the validator then blocks.
 *
 * Local only — reads the corpus and the catalog, touches no network.
 *
 * Usage: npm run verify:queries
 */
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.env.HAWKEYE_READONLY = '1';
if (!process.env.DETECTIONS_DB_PATH) {
  process.env.DETECTIONS_DB_PATH = path.join(ROOT, 'data', 'detections.db');
}

const dist = path.join(ROOT, 'dist', 'tools', 'index.js');
if (!existsSync(dist)) {
  console.error('error: dist not found — run "npm run build" first.');
  process.exit(2);
}

let pass = 0, fail = 0;
function check(name, ok, detail = '') {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + String(detail).slice(0, 220) : ''}`); }
}

const realErr = console.error; console.error = () => {};
const conn = await import(pathToFileURL(path.join(ROOT, 'dist', 'db', 'connection.js')).href);
await conn.initDbAsync();
const mod = await import(pathToFileURL(dist).href);
mod.registerAllTools();
console.error = realErr;

const call = (name, args) => mod.toolRegistry.execute(name, args);
const ids = (r) => [...(r.blocking ?? []), ...(r.warnings ?? [])].map(f => f.kind);
const blockingIds = (r) => (r.blocking ?? []).map(f => f.kind);

// ---------------------------------------------------------------------------
console.log('\n=== 1. Tools are registered and reachable ===');
{
  check('get_query_language_spec registered', mod.toolRegistry.has('get_query_language_spec'));
  check('validate_query registered', mod.toolRegistry.has('validate_query'));
  check('registry total is 132', mod.toolRegistry.count() === 132, `got ${mod.toolRegistry.count()}`);
}

console.log('\n=== 2. Specs load, and carry a real vocabulary ===');
for (const [lang, expectConf] of [['kql', 'confirmed'], ['spl', 'confirmed'], ['cql', 'community']]) {
  const s = await call('get_query_language_spec', { language: lang });
  check(`${lang}: spec returned`, s.language === lang, JSON.stringify(s).slice(0, 120));
  check(`${lang}: confidence is ${expectConf}`, s.confidence === expectConf, s.confidence);
  check(`${lang}: has operators`, (s.operators ?? []).length >= 6, String((s.operators ?? []).length));
  check(`${lang}: has prohibitions`, (s.prohibitions ?? []).length >= 4, String((s.prohibitions ?? []).length));
  check(`${lang}: catalog-backed vocabulary`, s.vocabulary?.available === true,
    JSON.stringify(s.vocabulary).slice(0, 120));
  check(`${lang}: cites an authority`, typeof s.authority === 'string' && s.authority.startsWith('http'));
  const size = JSON.stringify(s).length;
  console.log(`        spec payload: ${size} bytes (~${Math.round(size / 3.5)} tokens)`);
}

console.log('\n=== 3. Alias resolution and bad input ===');
{
  const a = await call('get_query_language_spec', { language: 'sentinel' });
  check('alias sentinel -> kql', a.language === 'kql');
  const b = await call('get_query_language_spec', { language: 'logscale' });
  check('alias logscale -> cql', b.language === 'cql');
  const c = await call('get_query_language_spec', { language: 'aql' });
  check('unsupported language rejected with the list', c.error === true && Array.isArray(c.supported),
    JSON.stringify(c).slice(0, 140));
  const d = await call('validate_query', { query: '', language: 'kql' });
  check('empty query rejected', d.error === true);
}

console.log('\n=== 4. Shape-matched examples ===');
{
  const s = await call('get_query_language_spec', { language: 'kql', shape: 'registry_event' });
  check('shape filter selects matching examples',
    s.examples.every(e => e.shape === 'registry_event'), JSON.stringify(s.examples.map(e => e.shape)));
  const t = await call('get_query_language_spec', { language: 'kql', shape: 'nonexistent_shape' });
  check('unmatched shape falls back rather than returning none', (t.examples ?? []).length > 0);
}

console.log('\n=== 5. KQL validation ===');
{
  const good = 'DeviceProcessEvents\n| where Timestamp > ago(1h)\n| where FileName =~ "powershell.exe"\n| project Timestamp, DeviceName, ProcessCommandLine';
  const r = await call('validate_query', { query: good, language: 'kql' });
  check('clean query passes', r.valid === true, JSON.stringify(r.blocking));
  check('table was observed', r.observed.sources.includes('DeviceProcessEvents'));

  const noTime = 'DeviceProcessEvents\n| where FileName =~ "powershell.exe"';
  const r2 = await call('validate_query', { query: noTime, language: 'kql' });
  check('missing time bound blocks', blockingIds(r2).includes('kql.no-time-bound'), ids(r2).join(','));

  const badTable = 'DeviceProcessEventz\n| where Timestamp > ago(1h)\n| where FileName =~ "x.exe"';
  const r3 = await call('validate_query', { query: badTable, language: 'kql' });
  check('unknown table blocks', blockingIds(r3).includes('unknown_table'), ids(r3).join(','));
  const sug = (r3.blocking.find(f => f.kind === 'unknown_table')?.suggestions ?? []);
  check('unknown table suggests the real one', sug.includes('DeviceProcessEvents'), sug.join(','));

  const badField = 'DeviceProcessEvents\n| where Timestamp > ago(1h)\n| where ProcessCommandline has "enc"';
  const r4 = await call('validate_query', { query: badField, language: 'kql' });
  const ff = r4.blocking.find(f => f.kind === 'unknown_field');
  check('wrong-case field blocks', Boolean(ff), ids(r4).join(','));
  check('wrong-case field suggests correct spelling',
    (ff?.suggestions ?? []).includes('ProcessCommandLine'), (ff?.suggestions ?? []).join(','));

  const containsQ = 'DeviceProcessEvents\n| where Timestamp > ago(1h)\n| where ProcessCommandLine contains "mimikatz"';
  const r5 = await call('validate_query', { query: containsQ, language: 'kql' });
  check('contains-for-term warns but does not block',
    r5.valid === true && ids(r5).includes('kql.contains-for-term'), ids(r5).join(','));

  const clTable = 'Veeam_GetSecurityEvents\n| where TimeGenerated > ago(1h)\n| where Name =~ "x"';
  const r6 = await call('validate_query', { query: clTable, language: 'kql' });
  check('solution-specific table warns', ids(r6).includes('solution_specific_table'), ids(r6).join(','));

  const extended = 'DeviceProcessEvents\n| where Timestamp > ago(1h)\n| extend Suspicious = ProcessCommandLine\n| where Suspicious has "enc"';
  const r7 = await call('validate_query', { query: extended, language: 'kql' });
  check('extend-defined field is not reported unknown',
    !blockingIds(r7).includes('unknown_field'), JSON.stringify(r7.blocking).slice(0, 160));
}

console.log('\n=== 6. SPL validation ===');
{
  const good = '| tstats summariesonly=true count from datamodel=Endpoint.Processes\n    where Processes.process_name="powershell.exe"\n    by Processes.dest Processes.user\n| rename "Processes.*" as *';
  const r = await call('validate_query', { query: good, language: 'spl' });
  check('clean tstats query passes', r.valid === true, JSON.stringify(r.blocking));
  check('data model observed', r.observed.sources.includes('Endpoint.Processes'), r.observed.sources.join(','));

  const external = '| tstats count from datamodel=Endpoint.Processes by Processes.dest\n| `drop_dm_object_name(Processes)`';
  const r2 = await call('validate_query', { query: external, language: 'spl' });
  check('external macro blocks', blockingIds(r2).includes('external_macro'), ids(r2).join(','));
  check('external macro fix names the rename workaround',
    /rename/i.test(r2.blocking.find(f => f.kind === 'external_macro')?.fix ?? ''));

  const noAnchor = 'EventCode=4688\n| stats count by ComputerName';
  const r3 = await call('validate_query', { query: noAnchor, language: 'spl' });
  check('missing source anchor blocks', blockingIds(r3).includes('spl.no-source-anchor'), ids(r3).join(','));

  const dsMacro = '`sysmon` EventCode=1\n| stats count by Computer';
  const r4 = await call('validate_query', { query: dsMacro, language: 'spl' });
  check('datasource macro warns', ids(r4).includes('datasource_macro'), ids(r4).join(','));

  const filterMacro = 'index=main EventCode=4688\n| `my_detection_filter`';
  const r5 = await call('validate_query', { query: filterMacro, language: 'spl' });
  check('ESCU filter macro warns', ids(r5).includes('escu_filter_macro'), ids(r5).join(','));

  const txn = 'index=main\n| transaction ComputerName';
  const r6 = await call('validate_query', { query: txn, language: 'spl' });
  check('transaction warns', ids(r6).includes('spl.transaction'), ids(r6).join(','));
}

console.log('\n=== 7. CQL validation ===');
{
  const good = '#repo=falcon event_simpleName=SyntheticProcessRollup2\n| in(FileName, values=["curl", "wget"])\n| groupBy([ComputerName, FileName], function=count())';
  const r = await call('validate_query', { query: good, language: 'cql' });
  check('clean query passes', r.valid === true, JSON.stringify(r.blocking));
  check('event observed', r.observed.sources.includes('SyntheticProcessRollup2'), r.observed.sources.join(','));
  check('confidence reported as community', r.confidence.tier === 'community', r.confidence.tier);

  const sql = 'SELECT ComputerName FROM falcon WHERE event_simpleName = "ProcessRollup2"';
  const r2 = await call('validate_query', { query: sql, language: 'cql' });
  check('SQL syntax blocks', blockingIds(r2).includes('cql.sql-syntax'), ids(r2).join(','));

  const badEvent = '#repo=falcon event_simpleName=ProcessRollup3\n| groupBy([ComputerName])';
  const r3 = await call('validate_query', { query: badEvent, language: 'cql' });
  check('unknown event blocks', blockingIds(r3).includes('unknown_event'), ids(r3).join(','));
  const sug = r3.blocking.find(f => f.kind === 'unknown_event')?.suggestions ?? [];
  check('unknown event suggests a real one', sug.some(s => s.startsWith('ProcessRollup')), sug.join(','));

  const noSel = 'ComputerName=/^WS-/\n| groupBy([ComputerName])';
  const r4 = await call('validate_query', { query: noSel, language: 'cql' });
  check('missing event selector blocks', blockingIds(r4).includes('cql.no-event-selector'), ids(r4).join(','));

  const pr2 = '#repo=falcon event_simpleName=ProcessRollup2\n| groupBy([ComputerName])';
  const r5 = await call('validate_query', { query: pr2, language: 'cql' });
  check('ProcessRollup2 platform scope is flagged',
    ids(r5).includes('platform_scope_hint'), ids(r5).join(','));
  check('platform hint names the cross-platform event',
    /SyntheticProcessRollup2/.test(r5.warnings.find(f => f.kind === 'platform_scope_hint')?.fix ?? ''));
}

console.log('\n=== 8. EVERY spec example passes its own validator ===');
{
  // Read the specs directly rather than through the tool: the tool caps examples
  // at three by design, and an example that is never returned is still an
  // example that ships. All of them must pass.
  const specs = await import(pathToFileURL(
    path.join(ROOT, 'dist', 'reference', 'query-languages', 'index.js')).href);
  let total = 0;
  for (const lang of ['kql', 'spl', 'cql']) {
    for (const ex of specs.SPECS[lang].examples) {
      total++;
      const r = await call('validate_query', { query: ex.query, language: lang });
      check(`${lang}: "${ex.title}"`, r.valid === true,
        (r.blocking ?? []).map(f => `${f.kind}:${f.subject ?? ''}`).join(' | '));
    }
  }
  console.log(`        ${total} examples checked across 3 languages`);
}

console.log('\n=== 9. translate_detection builds a brief, not a query ===');
{
  // A real Sigma rule that uses the list-of-maps form, which is where field
  // extraction previously lost three fields of four.
  const row = conn.runQuery(
    `SELECT id, name FROM detections
     WHERE source_type='sigma' AND logsource_category='process_creation'
       AND raw_content LIKE '%- Image|endswith%'
     ORDER BY name LIMIT 1`)[0];
  check('found a list-of-maps Sigma rule to translate', Boolean(row));

  if (row) {
    const b = await call('translate_detection', { detection_id: row.id, target_language: 'kql' });
    check('brief returns the source rule', b.source?.id === row.id);
    check('brief names the target table', b.target?.source === 'DeviceProcessEvents', b.target?.source);
    check('shape resolved', b.shape === 'process_creation', b.shape);

    // Regression: list-of-maps fields must not be dropped.
    const mappedNames = (b.fieldMappings ?? []).map(f => f.sigmaField);
    check('extracts fields written as "- Field|modifier:"',
      mappedNames.includes('Image'), mappedNames.join(','));
    check('extracts more than one field', mappedNames.length >= 3, mappedNames.join(','));

    check('every mapping carries a confidence',
      (b.fieldMappings ?? []).every(f => typeof f.confidence === 'string'));
    check('every mapping carries evidence',
      (b.fieldMappings ?? []).every(f => typeof f.evidence === 'string' && f.evidence.length > 10));
    check('at least one mapping is corroborated',
      (b.fieldMappings ?? []).some(f => f.confidence === 'confirmed'));

    check('brief carries prohibitions', (b.target?.prohibitions ?? []).length >= 4);
    check('brief carries shape-matched examples',
      (b.examples ?? []).length > 0 && b.examples.every(e => e.shape === 'process_creation'));
    check('brief instructs validation before presenting',
      (b.instructions ?? []).some(i => /validate_query/.test(i)));

    // The defining property: this tool must not answer with a query.
    const asText = JSON.stringify(b);
    check('brief contains no generated query field',
      b.generatedQuery === undefined && b.result === undefined);
    check('brief is a reasonable size', asText.length < 40000,
      `${asText.length} bytes`);

    // SPL surfaces a field with no CIM equivalent.
    const s = await call('translate_detection', { detection_id: row.id, target_language: 'spl' });
    const noEq = (s.fieldMappings ?? []).filter(f => f.target === null);
    check('SPL brief reports fields with no equivalent rather than guessing',
      noEq.length > 0 && noEq.every(f => f.confidence === 'none'),
      JSON.stringify((s.fieldMappings ?? []).map(f => [f.sigmaField, f.target])));
    check('cautions name the unmapped fields',
      (s.cautions ?? []).some(c => /no .* equivalent/i.test(c)), (s.cautions ?? []).join(' | '));

    // CQL cannot corroborate field names — the dictionary lists events, not columns.
    const c2 = await call('translate_detection', { detection_id: row.id, target_language: 'cql' });
    check('CQL mappings are graded community, not confirmed',
      (c2.fieldMappings ?? []).filter(f => f.target).every(f => f.confidence === 'community'),
      JSON.stringify((c2.fieldMappings ?? []).map(f => f.confidence)));
  }

  // Inline rule, not from the corpus.
  const inline = await call('translate_detection', {
    query: 'title: t\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: \\rundll32.exe\n  condition: sel',
    source_language: 'sigma',
    target_language: 'kql',
  });
  check('accepts an inline rule', inline.shape === 'process_creation', inline.shape);
  check('inline rule maps its field',
    (inline.fieldMappings ?? []).some(f => f.sigmaField === 'Image'),
    JSON.stringify((inline.fieldMappings ?? []).map(f => f.sigmaField)));

  const bad = await call('translate_detection', { detection_id: 'does-not-exist', target_language: 'kql' });
  check('unknown detection id errors clearly', bad.error === true && /not found/i.test(bad.message));

  const noInput = await call('translate_detection', { target_language: 'kql' });
  check('missing source errors clearly', noInput.error === true);

  const badTarget = await call('translate_detection', { detection_id: 'x', target_language: 'aql' });
  check('unsupported target rejected before lookup',
    badTarget.error === true && Array.isArray(badTarget.supported));
}

conn.closeDb();
console.log(`\n${'='.repeat(52)}`);
console.log(`  ${pass} passed, ${fail} failed`);
console.log('='.repeat(52));
process.exit(fail === 0 ? 0 : 1);
