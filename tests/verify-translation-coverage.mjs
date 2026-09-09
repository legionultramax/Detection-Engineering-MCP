#!/usr/bin/env node
/**
 * Golden set — pipeline coverage.
 *
 * Runs translate_detection across a deterministic sample of real corpus rules,
 * in every target language, and measures what comes back.
 *
 * What this measures, precisely: whether the *tooling* can produce a usable
 * brief for a real rule. Does the shape resolve, does a target table get
 * assigned, do the rule's fields map, and how much of that mapping the derived
 * catalog corroborates.
 *
 * What it does not measure, and cannot: whether a model given that brief writes
 * a good query. That needs the model, and substituting a larger one here would
 * produce a number that looks like a measurement and predicts nothing about a
 * 4B-active router. The honest split is that this file scores the inputs and a
 * separate harness, run against the deployed model, scores the outputs.
 *
 * The most actionable output is the tail: Sigma fields that appear in real
 * rules and have no mapping entry, ranked by how often they occur. That is the
 * work queue for field-mappings.ts.
 *
 * Local only, read-only, no network.  Usage: npm run verify:coverage
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

/** Rules sampled per category. Deterministic ordering, so runs are comparable. */
const PER_CATEGORY = Number(process.env.COVERAGE_SAMPLE ?? 25);
const LANGUAGES = ['kql', 'spl', 'cql'];

let pass = 0, fail = 0;
function check(name, ok, detail = '') {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); }
}
const pct = (n, d) => (d === 0 ? 0 : (n / d) * 100);
const fmtPct = (n, d) => `${pct(n, d).toFixed(1)}%`;

const realErr = console.error; console.error = () => {};
const conn = await import(pathToFileURL(path.join(ROOT, 'dist', 'db', 'connection.js')).href);
await conn.initDbAsync();
const mod = await import(pathToFileURL(dist).href);
mod.registerAllTools();
const fm = await import(pathToFileURL(path.join(ROOT, 'dist', 'reference', 'query-languages', 'field-mappings.js')).href);
console.error = realErr;

const mappedCategories = Object.keys(fm.FIELD_MAPPINGS);

// --- sample ----------------------------------------------------------------

const sample = [];
for (const cat of mappedCategories) {
  const rows = conn.runQuery(
    `SELECT id, name, logsource_category FROM detections
     WHERE source_type='sigma' AND logsource_category = ?
     ORDER BY id LIMIT ?`, [cat, PER_CATEGORY]);
  for (const r of rows) sample.push(r);
}

console.log(`\nGolden set — pipeline coverage`);
console.log(`  sampled ${sample.length} Sigma rules across ${mappedCategories.length} mapped categories`);
console.log(`  ${LANGUAGES.length} target languages -> ${sample.length * LANGUAGES.length} briefs\n`);

// --- run --------------------------------------------------------------------

const stats = {};
for (const lang of LANGUAGES) {
  stats[lang] = {
    briefs: 0, errors: 0, shapeResolved: 0, targetAssigned: 0,
    withFields: 0, totalFields: 0,
    confirmed: 0, community: 0, unconfirmed: 0, none: 0,
    anyConfirmed: 0, withCautions: 0, nestedWarnings: 0,
  };
}
/** Sigma fields seen in real rules with no entry in the mapping table. */
const unmappedFields = new Map();
const perCategory = {};

for (const row of sample) {
  const cat = row.logsource_category;
  perCategory[cat] ??= { rules: 0, targetAssigned: 0, anyConfirmed: 0 };
  perCategory[cat].rules++;

  for (const lang of LANGUAGES) {
    const s = stats[lang];
    let b;
    try {
      b = await mod.toolRegistry.execute('translate_detection',
        { detection_id: row.id, target_language: lang });
    } catch (err) {
      s.errors++;
      continue;
    }
    if (b?.error) { s.errors++; continue; }
    s.briefs++;

    if (b.shape && b.shape !== 'unknown') s.shapeResolved++;
    if (b.target?.source) {
      s.targetAssigned++;
      if (lang === 'kql') perCategory[cat].targetAssigned++;
    }

    const fields = b.fieldMappings ?? [];
    if (fields.length > 0) s.withFields++;
    s.totalFields += fields.length;
    let sawConfirmed = false;
    for (const f of fields) {
      if (f.confidence === 'confirmed') { s.confirmed++; sawConfirmed = true; }
      else if (f.confidence === 'community') s.community++;
      else if (f.confidence === 'unconfirmed') s.unconfirmed++;
      else s.none++;
    }
    if (sawConfirmed) {
      s.anyConfirmed++;
      if (lang === 'kql') perCategory[cat].anyConfirmed++;
    }
    if ((b.cautions ?? []).length > 0) s.withCautions++;
    if (b.condition?.warning) s.nestedWarnings++;

    // Unmapped fields are reported once per rule, in the cautions, phrased as
    // "N referenced field(s) have no mapping entry ... : A, B, C".
    for (const c of b.cautions ?? []) {
      const m = String(c).match(/no mapping entry and must be resolved manually: (.+?)\.$/);
      if (m) for (const f of m[1].split(',').map(x => x.trim())) {
        if (f) unmappedFields.set(f, (unmappedFields.get(f) ?? 0) + 1);
      }
    }
  }
}

// --- report -----------------------------------------------------------------

console.log('Per language');
console.log('  lang  briefs  err  shape   target   fields  anyConfirmed');
for (const lang of LANGUAGES) {
  const s = stats[lang];
  console.log(
    `  ${lang.padEnd(5)} ${String(s.briefs).padStart(6)} ${String(s.errors).padStart(4)}` +
    `  ${fmtPct(s.shapeResolved, s.briefs).padStart(6)}` +
    `  ${fmtPct(s.targetAssigned, s.briefs).padStart(7)}` +
    `  ${String(s.totalFields).padStart(6)}` +
    `  ${fmtPct(s.anyConfirmed, s.briefs).padStart(12)}`);
}

console.log('\nField-mapping confidence (all briefs)');
console.log('  lang   confirmed  community  unconfirmed  no-equivalent');
for (const lang of LANGUAGES) {
  const s = stats[lang];
  const tot = s.confirmed + s.community + s.unconfirmed + s.none;
  console.log(
    `  ${lang.padEnd(5)} ${fmtPct(s.confirmed, tot).padStart(10)}` +
    ` ${fmtPct(s.community, tot).padStart(10)}` +
    ` ${fmtPct(s.unconfirmed, tot).padStart(12)}` +
    ` ${fmtPct(s.none, tot).padStart(14)}`);
}

console.log('\nPer category (KQL, as representative)');
for (const [cat, c] of Object.entries(perCategory).sort((a, b) => b[1].rules - a[1].rules)) {
  console.log(`  ${cat.padEnd(22)} ${String(c.rules).padStart(4)} rules` +
    `   target ${fmtPct(c.targetAssigned, c.rules).padStart(6)}` +
    `   anyConfirmed ${fmtPct(c.anyConfirmed, c.rules).padStart(6)}`);
}

if (unmappedFields.size > 0) {
  console.log('\nWork queue — Sigma fields in real rules with no mapping entry');
  const ranked = [...unmappedFields.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20);
  for (const [f, n] of ranked) {
    console.log(`  ${String(n).padStart(4)}x  ${f}`);
  }
  console.log(`  (${unmappedFields.size} distinct)`);
}

// Categories the corpus uses that the mapping table does not cover.
const uncovered = conn.runQuery(
  `SELECT logsource_category cat, COUNT(*) n FROM detections
   WHERE source_type='sigma' AND cat IS NOT NULL AND cat != ''
   GROUP BY cat ORDER BY n DESC`)
  .filter(r => !mappedCategories.includes(r.cat));
if (uncovered.length > 0) {
  const declined = fm.UNMAPPED_CATEGORIES ?? {};
  const deliberate = uncovered.filter(r => declined[r.cat]);
  const oversight = uncovered.filter(r => !declined[r.cat]);
  const sum = (rows) => rows.reduce((a, r) => a + r.n, 0);

  // A decision and an oversight look identical in a coverage number, so they
  // are separated here. Only the second kind is work.
  console.log(`\nDeliberately unmapped — ${sum(deliberate)} rules across ${deliberate.length} categories`);
  for (const r of deliberate.slice(0, 6)) {
    console.log(`  ${String(r.n).padStart(4)}  ${r.cat.padEnd(26)} ${declined[r.cat].slice(0, 68)}`);
  }
  if (oversight.length > 0) {
    console.log(`\nUnaccounted for — ${sum(oversight)} rules across ${oversight.length} categories`);
    for (const r of oversight.slice(0, 8)) console.log(`  ${String(r.n).padStart(4)}  ${r.cat}`);
  } else {
    console.log('\nUnaccounted for — none. Every corpus category is mapped or explicitly declined.');
  }
}

// --- gates ------------------------------------------------------------------
//
// These are coverage bars, not correctness claims. They exist so a regression in
// the mapping table or the extractor shows up as a failure rather than a
// quietly worse number.

console.log('\n=== Gates ===');

// A missing target and a target that does not exist are different things. Every
// Sigma category has some Defender or Sentinel table, so KQL should be 100%.
// Splunk's CIM has no data model for image loads, script blocks, process access
// or driver loads, and those categories declare null deliberately — asserting
// 100% there would push the mapping table into naming a plausible-looking model
// that sends the query at the wrong data.
const expectedTargets = {};
for (const lang of LANGUAGES) {
  expectedTargets[lang] = sample.filter(
    r => fm.CATEGORY_SOURCES[r.logsource_category]?.[lang]).length;
}

for (const lang of LANGUAGES) {
  const s = stats[lang];
  check(`${lang}: every sampled rule produced a brief`, s.errors === 0, `${s.errors} errors`);
  check(`${lang}: shape resolved for all briefs`, s.shapeResolved === s.briefs,
    `${s.shapeResolved}/${s.briefs}`);
  check(`${lang}: target assigned wherever one is declared`,
    s.targetAssigned === expectedTargets[lang],
    `${s.targetAssigned}/${expectedTargets[lang]} (of ${s.briefs} briefs)`);
  check(`${lang}: at least one field mapped in >=95% of briefs`,
    pct(s.withFields, s.briefs) >= 95, fmtPct(s.withFields, s.briefs));
}
check('kql: a target exists for every sampled category',
  expectedTargets.kql === sample.length,
  `${expectedTargets.kql}/${sample.length} — every Sigma category maps to some Defender table`);
console.log(`        declared targets: kql ${expectedTargets.kql}, spl ${expectedTargets.spl}, ` +
  `cql ${expectedTargets.cql}, of ${sample.length} sampled rules`);
// Corroboration is only meaningful where the language has a target to be
// corroborated against. Scoring SPL across all briefs counted the 100 rules in
// categories where CIM has no data model as failures, which measured the
// corpus's shape rather than the mapping table's quality.
for (const lang of ['kql', 'spl']) {
  const s = stats[lang];
  check(`${lang}: >=80% of briefs with a declared target carry a corroborated mapping`,
    pct(s.anyConfirmed, expectedTargets[lang]) >= 80,
    `${fmtPct(s.anyConfirmed, expectedTargets[lang])} (${s.anyConfirmed}/${expectedTargets[lang]})`);
}
check('cql: nothing is claimed as confirmed',
  stats.cql.confirmed === 0, `${stats.cql.confirmed} confirmed — the dictionary lists events, not fields`);

// Categories the corpus cannot corroborate at all are worth surfacing rather
// than averaging away. driver_load is the current example: its mappings target
// DeviceEvents, and the 26 DeviceEvents rules in the corpus never use FolderPath
// or SHA256, so every mapping is honestly reported unconfirmed. That is a limit
// of the evidence, not an error in the mapping.
const uncorroborated = Object.entries(perCategory)
  .filter(([, c]) => c.rules >= 5 && c.anyConfirmed === 0)
  .map(([cat]) => cat);
if (uncorroborated.length > 0) {
  console.log(`\n  note: categories the corpus cannot corroborate (KQL): ${uncorroborated.join(', ')}`);
  console.log('        mappings there are reported unconfirmed, which is the honest answer.');
}

conn.closeDb();
console.log(`\n${'='.repeat(52)}`);
console.log(`  ${pass} passed, ${fail} failed`);
console.log('='.repeat(52));
process.exit(fail === 0 ? 0 : 1);
