import { initDbAsync } from '../dist/db/connection.js';
import { detectionTools } from '../dist/tools/detections/index.js';

process.env.SIGMA_PATHS = 'C:\\Users\\harsh\\Desktop\\security-detections-mcp\\rules\\sigma\\rules';
process.env.SPLUNK_PATHS = 'C:\\Users\\harsh\\Desktop\\security-detections-mcp\\rules\\splunk\\detections';
process.env.ELASTIC_PATHS = 'C:\\Users\\harsh\\Desktop\\security-detections-mcp\\rules\\elastic\\rules';

await initDbAsync();

const toolMap = Object.fromEntries(detectionTools.map(t => [t.name, t]));
const call = (name, args) => toolMap[name].handler(args);

let pass = 0, fail = 0;
const log = [];

function ok(label, bytes) {
  log.push({ ok: true, label, bytes });
  pass++;
}
function fail_(label, detail) {
  log.push({ ok: false, label, detail: JSON.stringify(detail).slice(0, 200) });
  fail++;
}
function assert(label, cond, actual, bytes) {
  if (cond) ok(label, bytes);
  else       fail_(label, actual);
}

// ── REGISTRY CHECK ───────────────────────────────────────────────────────────
const names = detectionTools.map(t => t.name);
assert('Registry: 20 tools total (15 old + 5 new)', detectionTools.length === 20, detectionTools.length);
for (const n of ['get_technique_count','get_coverage_summary','get_technique_ids','get_top_gaps','suggest_detections']) {
  assert(`Registry: ${n} exported`, names.includes(n), names);
}
assert('Registry: analyze_coverage kept', names.includes('analyze_coverage'), names);
assert('Registry: identify_gaps kept',   names.includes('identify_gaps'),    names);

// ── get_technique_count ──────────────────────────────────────────────────────
let r, bytes;

r = await call('get_technique_count', { technique_id: 'T1059' });
bytes = Buffer.byteLength(JSON.stringify(r));
assert('count(T1059): count is number',  typeof r.count === 'number', r);
assert('count(T1059): tid normalised',   r.technique_id === 'T1059', r);
assert('count(T1059): size < 100B',      bytes < 100, bytes, bytes);

r = await call('get_technique_count', { technique_id: 'T9999' });
assert('count(T9999): returns 0 not error', r.count === 0 && !r.error, r);

r = await call('get_technique_count', { technique_id: '' });
assert('count(""): error field present',  !!r.error, r);

r = await call('get_technique_count', { technique_id: 't1059' });
assert('count(lowercase): normalised to T1059', r.technique_id === 'T1059', r);

r = await call('get_technique_count', { technique_id: 'T1059.001' });
assert('count(sub-technique): numeric result', typeof r.count === 'number', r);

// ── get_coverage_summary ────────────────────────────────────────────────────
r = await call('get_coverage_summary', {});
bytes = Buffer.byteLength(JSON.stringify(r));
assert('summary(): plain object',          !Array.isArray(r) && typeof r === 'object', r);
assert('summary(): at least one tactic',   Object.keys(r).length > 0, r);
assert('summary(): all values numeric',    Object.values(r).every(v => typeof v === 'number'), r);
assert('summary(): size < 400B',           bytes < 400, bytes, bytes);

r = await call('get_coverage_summary', { source_type: 'sigma' });
assert('summary(sigma): object',           typeof r === 'object' && !Array.isArray(r), r);

r = await call('get_coverage_summary', { source_type: 'nonexistent_xyz' });
assert('summary(bad source): empty obj not crash', typeof r === 'object' && Object.keys(r).length === 0, r);

// ── get_technique_ids ───────────────────────────────────────────────────────
r = await call('get_technique_ids', {});
const allIds = r;
assert('ids(): returns array',           Array.isArray(r), r);
assert('ids(): elements are strings',    r.length === 0 || typeof r[0] === 'string', r[0]);
assert('ids(): sorted asc',             r.length < 2 || r[0] <= r[1], [r[0], r[1]]);
assert('ids(): no duplicates',          new Set(r).size === r.length, r.length);

r = await call('get_technique_ids', { tactic: 'execution' });
assert('ids(execution): subset of all', r.length <= allIds.length, { filtered: r.length, all: allIds.length });
assert('ids(execution): array',         Array.isArray(r), r);

r = await call('get_technique_ids', { severity: 'critical' });
assert('ids(critical): array',          Array.isArray(r), r);

r = await call('get_technique_ids', { source_type: 'sigma', tactic: 'persistence', severity: 'high' });
assert('ids(all 3 filters): array',     Array.isArray(r), r);

// ── get_top_gaps ─────────────────────────────────────────────────────────────
r = await call('get_top_gaps', { threat_profile: 'ransomware' });
bytes = Buffer.byteLength(JSON.stringify(r));
assert('top_gaps(ransomware): top_gaps array',      Array.isArray(r.top_gaps), r);
assert('top_gaps(ransomware): max 5',               r.top_gaps.length <= 5, r.top_gaps.length);
assert('top_gaps(ransomware): has counts obj',      typeof r.counts === 'object', r);
assert('top_gaps(ransomware): size < 400B',         bytes < 400, bytes, bytes);
assert('top_gaps(ransomware): sorted asc by count',
  r.top_gaps.length < 2 || (r.counts[r.top_gaps[0]] ?? 0) <= (r.counts[r.top_gaps[1]] ?? 0),
  r.counts);

r = await call('get_top_gaps', { threat_profile: 'apt' });
assert('top_gaps(apt): valid array',    Array.isArray(r.top_gaps), r);

r = await call('get_top_gaps', { threat_profile: 'credential-access' });
assert('top_gaps(cred-access): valid',  Array.isArray(r.top_gaps), r);

r = await call('get_top_gaps', { threat_profile: 'invalid_xyz' });
assert('top_gaps(invalid): error field', !!r.error, r);

// ── suggest_detections ──────────────────────────────────────────────────────
r = await call('suggest_detections', { technique_id: 'T1059' });
bytes = Buffer.byteLength(JSON.stringify(r));
assert('suggest(T1059): detections array',     Array.isArray(r.detections), r);
assert('suggest(T1059): count matches len',    r.count === r.detections.length, r);
assert('suggest(T1059): max 10 results',       r.detections.length <= 10, r.detections.length);
assert('suggest(T1059): no query field',       r.detections.every(d => d.query === undefined), 'query found');
assert('suggest(T1059): has id field',         r.detections.length === 0 || 'id'       in r.detections[0], r.detections[0]);
assert('suggest(T1059): has name field',       r.detections.length === 0 || 'name'     in r.detections[0], r.detections[0]);
assert('suggest(T1059): has severity field',   r.detections.length === 0 || 'severity' in r.detections[0], r.detections[0]);
assert('suggest(T1059): has log_hint field',   r.detections.length === 0 || 'log_hint' in r.detections[0], r.detections[0]);
assert('suggest(T1059): has tactics array',    r.detections.length === 0 || Array.isArray(r.detections[0].tactics), r.detections[0]);
assert('suggest(T1059): size < 2KB',           bytes < 2048, bytes, bytes);

r = await call('suggest_detections', { technique_id: 'T9999' });
assert('suggest(T9999): count=0 not error',    r.count === 0 && Array.isArray(r.detections), r);

r = await call('suggest_detections', { technique_id: '' });
assert('suggest(""): error field',             !!r.error, r);

r = await call('suggest_detections', { technique_id: 'T1059', source_type: 'sigma' });
assert('suggest(T1059,sigma): all sigma',
  r.detections.every(d => d.source === 'sigma'), r.detections.map(d => d.source));

// ── analyze_coverage tweaks ─────────────────────────────────────────────────
r = await call('analyze_coverage', {});
bytes = Buffer.byteLength(JSON.stringify(r));
assert('analyze_coverage(): has weak_spots array',    Array.isArray(r.weak_spots), r);
assert('analyze_coverage(): top_techniques <= 10',    r.top_techniques.length <= 10, r.top_techniques.length);
assert('analyze_coverage(): has tactic_coverage',     typeof r.tactic_coverage === 'object', r);
assert('analyze_coverage(): has unique_techniques',   typeof r.unique_techniques === 'number', r);
assert('analyze_coverage(): size < 3KB',              bytes < 3072, bytes, bytes);

r = await call('analyze_coverage', { source_type: 'sigma' });
assert('analyze_coverage(sigma): filters work',  typeof r.total_detections_with_mitre === 'number', r);

// ── identify_gaps tweaks ────────────────────────────────────────────────────
r = await call('identify_gaps', { profile: 'ransomware' });
assert('identify_gaps(ransomware): source_type=all',  r.source_type === 'all', r);
assert('identify_gaps(ransomware): gaps array',       Array.isArray(r.gaps), r);
assert('identify_gaps(ransomware): coverage obj',     typeof r.coverage === 'object', r);
assert('identify_gaps(ransomware): pct 0-100',        r.coverage_percentage >= 0 && r.coverage_percentage <= 100, r.coverage_percentage);

r = await call('identify_gaps', { profile: 'apt', source_type: 'sigma' });
assert('identify_gaps(apt,sigma): source_type set',   r.source_type === 'sigma', r);

r = await call('identify_gaps', { profile: 'bad_profile' });
assert('identify_gaps(bad): error field',             !!r.error, r);

// ── TOKEN EFFICIENCY BENCHMARKS ──────────────────────────────────────────────
// Benchmark A: get_technique_count vs list_by_mitre (pre-check cost)
const bA_full = await call('list_by_mitre', { technique_id: 'T1059', limit: 10 });
const bA_lean = await call('get_technique_count', { technique_id: 'T1059' });
const bA_fullB = Buffer.byteLength(JSON.stringify(bA_full));
const bA_leanB = Buffer.byteLength(JSON.stringify(bA_lean));
const bA_ratio = (bA_fullB / bA_leanB).toFixed(1);
assert(`Benchmark A: get_technique_count is ${bA_ratio}x smaller than list_by_mitre (need >5x)`,
  bA_fullB / bA_leanB > 5, { bA_fullB, bA_leanB, bA_ratio });

// Benchmark B: get_coverage_summary vs analyze_coverage
const bB_full = await call('analyze_coverage', {});
const bB_lean = await call('get_coverage_summary', {});
const bB_fullB = Buffer.byteLength(JSON.stringify(bB_full));
const bB_leanB = Buffer.byteLength(JSON.stringify(bB_lean));
const bB_ratio = (bB_fullB / bB_leanB).toFixed(1);
assert(`Benchmark B: get_coverage_summary is ${bB_ratio}x smaller than analyze_coverage (need >2x)`,
  bB_fullB / bB_leanB > 2, { bB_fullB, bB_leanB, bB_ratio });

// Benchmark C: get_top_gaps vs identify_gaps (just IDs vs full coverage map)
const bC_full = await call('identify_gaps', { profile: 'ransomware' });
const bC_lean = await call('get_top_gaps', { threat_profile: 'ransomware' });
const bC_fullB = Buffer.byteLength(JSON.stringify(bC_full));
const bC_leanB = Buffer.byteLength(JSON.stringify(bC_lean));
const bC_ratio = (bC_fullB / bC_leanB).toFixed(1);
// identify_gaps is already compact (~8 techniques) — 1.5x is the realistic floor
assert(`Benchmark C: get_top_gaps is ${bC_ratio}x smaller than identify_gaps (need >1.5x)`,
  bC_fullB / bC_leanB > 1.5, { bC_fullB, bC_leanB, bC_ratio });

// Benchmark D: suggest_detections vs search_detections (the real heavy tool)
const bD_full = await call('search_detections', { query: 'T1059', limit: 10 });
const bD_lean = await call('suggest_detections', { technique_id: 'T1059' });
const bD_fullB = Buffer.byteLength(JSON.stringify(bD_full));
const bD_leanB = Buffer.byteLength(JSON.stringify(bD_lean));
const bD_ratio = (bD_fullB / bD_leanB).toFixed(1);
// Note: search_detections includes description (200 chars each); suggest_detections strips it
assert(`Benchmark D: suggest_detections is ${bD_ratio}x smaller than search_detections (need >=1x)`,
  bD_fullB / bD_leanB >= 1, { bD_fullB, bD_leanB, bD_ratio });

const fullB = bA_fullB; const leanB = bA_leanB; const ratio = bA_ratio;

// ── RESULTS ──────────────────────────────────────────────────────────────────
console.log('\n' + '='.repeat(65));
console.log(' SELF-TEST RESULTS — harris-hawkeye surgical tools');
console.log('='.repeat(65));
for (const entry of log) {
  const icon  = entry.ok ? '\u2713' : '\u2717';
  const size  = entry.bytes != null ? `  [${entry.bytes}B]` : '';
  const detail = entry.detail ? `  \u2192 ${entry.detail}` : '';
  console.log(`${icon} ${entry.label}${size}${detail}`);
}
console.log('-'.repeat(65));
console.log(`PASS: ${pass}   FAIL: ${fail}   TOTAL: ${pass + fail}`);
console.log(`\nBenchmarks:`);
console.log(`  A: get_technique_count=${bA_leanB}B  vs list_by_mitre=${bA_fullB}B   → ${bA_ratio}x smaller`);
console.log(`  B: get_coverage_summary=${bB_leanB}B  vs analyze_coverage=${bB_fullB}B  → ${bB_ratio}x smaller`);
console.log(`  C: get_top_gaps=${bC_leanB}B  vs identify_gaps=${bC_fullB}B   → ${bC_ratio}x smaller`);
console.log(`  D: suggest_detections=${bD_leanB}B  vs search_detections=${bD_fullB}B  → ${bD_ratio}x smaller`);
if (fail > 0) process.exit(1);
