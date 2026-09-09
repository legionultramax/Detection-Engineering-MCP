#!/usr/bin/env node
/**
 * Verify search_detections: multi-word matching, relevance ranking, and that
 * its description does not claim capabilities it lacks.
 *
 * Two regressions this guards against, both of which shipped:
 *
 *   1. The whole query was used as a single LIKE substring, so any multi-word
 *      search matched almost nothing. "certutil download" returned zero results
 *      against a corpus containing several certutil download rules — no error,
 *      just an empty answer.
 *   2. Results were ORDER BY name, so the first 20 matches were whichever
 *      sorted earliest alphabetically rather than whichever were relevant.
 *
 * And one that is easy to reintroduce: the description claimed FTS5 full-text
 * search, which the sql.js WASM build does not include. A tool that overstates
 * itself is worse than one that understates, because the model believes it.
 *
 * Local only, read-only, no network.  Usage: npm run verify:search
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
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); }
}

const realErr = console.error; console.error = () => {};
const conn = await import(pathToFileURL(path.join(ROOT, 'dist', 'db', 'connection.js')).href);
await conn.initDbAsync();
const mod = await import(pathToFileURL(dist).href);
mod.registerAllTools();
const fts = await import(pathToFileURL(path.join(ROOT, 'dist', 'db', 'fts.js')).href);
console.error = realErr;
const search = (args) => mod.toolRegistry.execute('search_detections', args);

console.log('\n=== 1. The description matches the implementation ===');
{
  // The original defect was a description claiming FTS5 the engine did not
  // have. FTS5 is real now, so the requirement inverts: the description must
  // describe what the tool does and must still disclaim what it does not.
  const def = mod.toolRegistry.get('search_detections');
  const d = def.description;
  check('states results are ranked', /rank/i.test(d));
  check('states terms are prefix-matched', /prefix/i.test(d));
  check('warns it is not semantic or stemmed', /stem|synonym|semantic/i.test(d));
  check('explains technique-ID matching', /T1003/.test(d));
  check('tells the caller the engine is reported', /engine/i.test(d));
}

console.log('\n=== 1b. FTS5 index is present and answering ===');
{
  const st = fts.ftsStatus(true);
  check('index exists and matches the corpus', st.available === true, st.reason);
  check('index row count equals detection count', st.rows === st.detections,
    `${st.rows} vs ${st.detections}`);
  const r = await search({ query: 'mimikatz', limit: 3 });
  check('search reports which engine answered', r.engine === 'fts5', String(r.engine));
  check('scores are positive so higher is better',
    r.detections.every(d => d.score > 0), r.detections.map(d => d.score).join(','));

  // The declared column order and weights must match the table the schema
  // actually creates, or bm25 applies weights to the wrong columns silently.
  const cols = fts.FTS_COLUMNS.map(c => c.column);
  const declared = conn.runQuery(
    `SELECT sql FROM sqlite_master WHERE name = ?`, [fts.FTS_TABLE])[0]?.sql ?? '';
  check('declared columns appear in the created table in order',
    cols.every(c => declared.includes(c)) &&
      cols.reduce((ok, c, i) => ok && (i === 0 || declared.indexOf(c) > declared.indexOf(cols[i - 1])), true),
    declared.replace(/\s+/g, ' ').slice(0, 160));
}

console.log('\n=== 1c. Technique IDs and prefixes behave precisely ===');
{
  // The tokenchars setting exists so a dotted subtechnique ID stays one token.
  // Without it "T1003.001" splits and matches every subtechnique of T1003.
  const exact = conn.runQuery(
    `SELECT COUNT(*) n FROM ${fts.FTS_TABLE} f JOIN detections d ON d.id = f.detection_id
     WHERE ${fts.FTS_TABLE} MATCH ?`, ['"T1003.001"'])[0].n;
  const tagged = conn.runQuery(
    `SELECT COUNT(*) n FROM detections WHERE mitre_techniques LIKE ?`, ['%T1003.001%'])[0].n;
  check('exact subtechnique match is precise, not split by the dot',
    exact === tagged && exact > 0, `matched ${exact}, tagged ${tagged}`);

  const fam = await search({ query: 'T1003', limit: 20 });
  check('a parent technique ID matches the family via prefix', fam.count > 0, `got ${fam.count}`);

  const pre = await search({ query: 'certut', limit: 5 });
  check('partial word matches by prefix', pre.count > 0, `got ${pre.count}`);
  check('prefix hit is the expected binary', /certutil/i.test(pre.detections[0]?.name ?? ''),
    pre.detections[0]?.name);
}

console.log('\n=== 1d. FTS5 query syntax cannot be injected ===');
{
  // Unquoted, several of these are FTS5 operators rather than search terms: a
  // hyphen reads as NOT, a colon as a column filter, AND/OR/NEAR as operators.
  // buildMatchExpression quotes every term, so they must arrive as literals
  // rather than erroring or silently meaning something else.
  const nasty = [
    'lsass-dump', 'field:value', 'AND', 'OR', 'NOT', 'NEAR(a b)',
    '"unbalanced', 'a*b', '(paren', 'back\\slash', "o'brien",
  ];
  let errored = null;
  for (const q of nasty) {
    const r = await search({ query: q, limit: 2 });
    if (r.error === true && q.trim()) { errored = `${q} -> ${r.message}`; break; }
    if (typeof r.count !== 'number') { errored = `${q} -> no count`; break; }
  }
  check('FTS5 operator characters are treated as literals', errored === null, errored ?? '');
  check('match expression quotes every term',
    fts.buildMatchExpression(['a-b', 'c:d']) === '"a-b"* AND "c:d"*',
    fts.buildMatchExpression(['a-b', 'c:d']));
  check('embedded quotes are doubled, not escaped away',
    fts.buildMatchExpression(['say"hi']) === '"say""hi"*',
    fts.buildMatchExpression(['say"hi']));
}

console.log('\n=== 2. Multi-word queries match (the zero-result regression) ===');
{
  // Verified against the corpus: as a single substring this matched 0 rows.
  const r = await search({ query: 'certutil download', limit: 5 });
  check('"certutil download" returns results', r.count > 0, `got ${r.count}`);
  check('top hit mentions certutil', /certutil/i.test(r.detections[0]?.name ?? ''),
    r.detections[0]?.name);

  const r2 = await search({ query: 'credential dumping lsass', limit: 5 });
  check('"credential dumping lsass" returns results', r2.count > 0, `got ${r2.count}`);
  check('top hit mentions lsass', /lsass/i.test(r2.detections[0]?.name ?? ''),
    r2.detections[0]?.name);

  check('terms are reported back', Array.isArray(r2.terms) && r2.terms.length === 3,
    JSON.stringify(r2.terms));
}

console.log('\n=== 3. Results are ranked, not alphabetical ===');
{
  const r = await search({ query: 'lsass dump', limit: 10 });
  const scores = r.detections.map(d => d.score);
  check('every result carries a score', scores.every(s => typeof s === 'number'));
  check('scores are non-increasing', scores.every((s, i) => i === 0 || scores[i - 1] >= s),
    scores.join(','));
  const names = r.detections.map(d => d.name);
  const alphabetical = [...names].sort((a, b) => a.localeCompare(b));
  check('order is not merely alphabetical',
    JSON.stringify(names) !== JSON.stringify(alphabetical), names.slice(0, 3).join(' | '));
  check('a name match outranks the tail',
    (r.detections[0]?.score ?? 0) > (r.detections[r.detections.length - 1]?.score ?? 0));
}

console.log('\n=== 4. Structured-field matches rank above free text ===');
{
  const r = await search({ query: 'mimikatz', limit: 20 });
  const named = r.detections.filter(d => /mimikatz/i.test(d.name));
  const unnamed = r.detections.filter(d => !/mimikatz/i.test(d.name));
  check('rules with the term in the name are returned', named.length > 0);
  if (named.length && unnamed.length) {
    check('name matches score above non-name matches',
      Math.min(...named.map(d => d.score)) >= Math.max(...unnamed.map(d => d.score)),
      `named min ${Math.min(...named.map(d => d.score))} vs other max ${Math.max(...unnamed.map(d => d.score))}`);
  } else {
    check('name matches score above non-name matches (all results were name matches)', true);
  }
}

console.log('\n=== 5. Technique and CVE identifiers work directly ===');
{
  const r = await search({ query: 'T1003.001', limit: 5 });
  check('technique ID returns results', r.count > 0, `got ${r.count}`);
  const hit = r.detections.some(d => (d.techniques ?? []).some(t => String(t).includes('T1003')));
  check('results actually carry the technique', hit,
    JSON.stringify(r.detections[0]?.techniques));
}

console.log('\n=== 6. Filters and edge cases ===');
{
  const r = await search({ query: 'powershell', source: 'sigma', limit: 5 });
  check('source filter applies', r.detections.every(d => d.source === 'sigma'),
    r.detections.map(d => d.source).join(','));

  const r2 = await search({ query: 'powershell', severity: 'high', limit: 5 });
  check('severity filter applies', r2.detections.every(d => d.severity === 'high'),
    r2.detections.map(d => d.severity).join(','));

  const r3 = await search({ query: '   ', limit: 5 });
  check('blank query errors rather than scanning everything', r3.error === true);

  const r4 = await search({ query: 'a', limit: 5 });
  check('single short term still searches rather than returning nothing',
    typeof r4.count === 'number');

  const r5 = await search({ query: 'zzzznonexistentzzz', limit: 5 });
  check('no match returns zero cleanly', r5.count === 0 && Array.isArray(r5.detections));

  const r6 = await search({ query: "o'brien or 100% --", limit: 3 });
  check('quotes and SQL metacharacters are parameterised safely',
    typeof r6.count === 'number', JSON.stringify(r6).slice(0, 120));
}

conn.closeDb();
console.log(`\n${'='.repeat(52)}`);
console.log(`  ${pass} passed, ${fail} failed`);
console.log('='.repeat(52));
process.exit(fail === 0 ? 0 : 1);
