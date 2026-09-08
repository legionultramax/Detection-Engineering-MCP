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
console.error = realErr;
const search = (args) => mod.toolRegistry.execute('search_detections', args);

console.log('\n=== 1. The description does not overstate the implementation ===');
{
  const def = mod.toolRegistry.get('search_detections');
  const d = def.description;
  check('does not claim FTS5', !/fts5/i.test(d), d.slice(0, 120));
  check('does not claim full-text search', !/full-text search/i.test(d.replace(/not full-text search/i, '')));
  check('states matching is substring-based', /substring/i.test(d));
  check('states results are ranked', /rank/i.test(d));
  check('warns it is not semantic or stemmed', /stem|synonym|semantic/i.test(d));
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
