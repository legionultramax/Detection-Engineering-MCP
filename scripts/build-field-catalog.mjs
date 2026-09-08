#!/usr/bin/env node
/**
 * Build the query-language field catalog by deriving it from real data.
 *
 * Why derived rather than authored: a hand-written catalog of table and field
 * names is one more thing that drifts from reality and cannot be checked. This
 * one regenerates, and every entry traces to a source that can be re-read.
 *
 * Sources, and what confidence each earns:
 *
 *   KQL  — 4,971 Sentinel rules in the local corpus. A field that appears in
 *          rules people actually deploy is real. CONFIRMED.
 *   SPL  — 2,185 Splunk ESCU rules plus the 173 macro definitions from the
 *          security_content repo. CIM data models and qualified fields are
 *          canonical; macros split by kind (see below). CONFIRMED / UNCONFIRMED.
 *   CQL  — the 998-event CrowdStrike Falcon dictionary vendored under
 *          data/third-party/. Unofficial community extraction. COMMUNITY.
 *
 * The SPL macro split matters more than it looks. ESCU averages 4.4 macros per
 * query and a macro that does not resolve is a query that cannot run:
 *
 *   utility     — security_content_ctime, security_content_summariesonly.
 *                 Definitions on disk, safe to expand.
 *   datasource  — sysmon, wineventlog_security, o365_management_activity.
 *                 Definitions on disk, but ESCU's own description says
 *                 "Replace the macro definition with configurations for your
 *                 Splunk Environment" — so the expansion is a DEFAULT, not a
 *                 fact about any given deployment.
 *   filter      — one per detection, empty by default, safe to drop.
 *   external    — drop_dm_object_name (1,145 references), globedistance,
 *                 get_asset. Ship with Splunk_SA_CIM, not with the rules. Not
 *                 resolvable here, and drop_dm_object_name is semantically
 *                 load-bearing: it strips the data-model prefix from field
 *                 names. Emitting it to a Splunk without the CIM app fails.
 *
 * Usage:
 *   node scripts/build-field-catalog.mjs            # write the catalog
 *   node scripts/build-field-catalog.mjs --report   # summarise, write nothing
 *
 * Env:
 *   SPLUNK_MACROS_PATH   defaults to ../hawkeye-rules/splunk/macros
 *   DETECTIONS_DB_PATH   the corpus (read-only; never written)
 */
import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const args = new Set(process.argv.slice(2));
const reportOnly = args.has('--report');

const OUT_DIR = path.join(ROOT, 'src', 'reference', 'field-catalog');
const OUT_FILE = path.join(OUT_DIR, 'catalog.json');
const CS_CSV = path.join(ROOT, 'data', 'third-party', 'crowdstrike-events', 'sensor_events.csv');
const MACRO_DIR = process.env.SPLUNK_MACROS_PATH
  ?? path.join(path.dirname(ROOT), '..', '..', '..', 'hawkeye-rules', 'splunk', 'macros');

// Read-only: this script must never modify the corpus it reads.
process.env.HAWKEYE_READONLY = '1';

// Default to the repo's own database. Without this, an unset DETECTIONS_DB_PATH
// silently falls back to ~/.cache/security-detections-mcp/detections.db, which
// on a fresh machine does not exist — and the catalog then builds from an empty
// corpus and reports zero fields as though that were the answer.
if (!process.env.DETECTIONS_DB_PATH) {
  const local = path.join(ROOT, 'data', 'detections.db');
  if (!existsSync(local)) {
    console.error(`error: no corpus found at ${local}`);
    console.error('Set DETECTIONS_DB_PATH, or build the index first.');
    process.exit(2);
  }
  process.env.DETECTIONS_DB_PATH = local;
}

const DIST = path.join(ROOT, 'dist', 'db', 'connection.js');
if (!existsSync(DIST)) {
  console.error('error: dist/db/connection.js not found — run "npm run build" first.');
  process.exit(2);
}
const conn = await import(pathToFileURL(DIST).href);
await conn.initDbAsync();
const q = (sql, p = []) => conn.runQuery(sql, p);

// ---------------------------------------------------------------------------
// KQL — tables and fields from the corpus
// ---------------------------------------------------------------------------

/**
 * Kusto builtins that a naive `where <token>` regex mistakes for field names.
 * Without this the extracted catalog lists isnotempty() as a column.
 */
const KQL_BUILTINS = new Set([
  'isnotempty', 'isempty', 'isnull', 'isnotnull', 'tostring', 'tolower', 'toupper',
  'ago', 'now', 'datetime', 'todatetime', 'toint', 'tolong', 'todouble', 'toreal',
  'count', 'dcount', 'countif', 'dcountif', 'make_set', 'make_list', 'make_bag',
  'arg_max', 'arg_min', 'bin', 'bin_auto', 'extract', 'extract_all', 'parse_json',
  'split', 'strcat', 'strcat_delim', 'strlen', 'iff', 'iif', 'case', 'coalesce',
  'array_length', 'set_union', 'set_intersect', 'set_difference', 'materialize',
  'todynamic', 'replace_string', 'replace_regex', 'trim', 'trim_start', 'trim_end',
  'substring', 'indexof', 'hash_sha256', 'hash_md5', 'format_datetime', 'format_timespan',
  'startofday', 'endofday', 'startofweek', 'startofmonth', 'row_number', 'prev', 'next',
  'min', 'max', 'avg', 'sum', 'any', 'anyif', 'take_any', 'percentile', 'percentiles',
  'toscalar', 'range', 'series_stats', 'pack', 'pack_array', 'unpack', 'zip',
  'has_any', 'has_all', 'ipv4_is_match', 'ipv4_is_private', 'geo_info_from_ip_address',
  'parse_url', 'parse_urlquery', 'url_decode', 'base64_decode_tostring', 'gettype',
  'tobool', 'toguid', 'totimespan', 'dayofweek', 'datetime_diff', 'datetime_add',
]);

/** A field must appear in at least this many distinct rules to be trusted. */
const KQL_MIN_SUPPORT = 3;

const kqlRows = q(
  "SELECT query FROM detections WHERE source_type='kql' AND query IS NOT NULL AND length(query) > 40");

const kqlTables = new Map();     // table -> rule count
const kqlFields = new Map();     // field -> rule count
const kqlTableFields = new Map();// table -> Map(field -> count)

for (const { query } of kqlRows) {
  const text = String(query);

  // The leading token before the first pipe or newline is the table.
  const head = text.trim().split(/[\n|]/)[0].trim();
  const tm = head.match(/^([A-Za-z][A-Za-z0-9_]{2,})\s*$/);
  const table = tm ? tm[1] : null;
  if (table) {
    kqlTables.set(table, (kqlTables.get(table) ?? 0) + 1);
    if (!kqlTableFields.has(table)) kqlTableFields.set(table, new Map());
  }

  // Fields, counted once per rule so one query repeating a field does not
  // inflate its support.
  const seen = new Set();
  const patterns = [
    /\bwhere\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|=~|!=|!~|>|<|>=|<=|\bhas\b|\bhas_any\b|\bcontains\b|\bstartswith\b|\bendswith\b|\bin\b)/g,
    /\bproject\s+([A-Za-z_][A-Za-z0-9_,\s]*)/g,
    /\bextend\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/g,
    /\bsummarize\b[^|]*\bby\s+([A-Za-z_][A-Za-z0-9_,\s]*)/g,
  ];
  for (const re of patterns) {
    for (const m of text.matchAll(re)) {
      for (const raw of String(m[1]).split(',')) {
        const f = raw.trim();
        if (!f || f.length < 3) continue;
        if (KQL_BUILTINS.has(f.toLowerCase())) continue;
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(f)) continue;
        seen.add(f);
      }
    }
  }
  for (const f of seen) {
    kqlFields.set(f, (kqlFields.get(f) ?? 0) + 1);
    if (table) {
      const tf = kqlTableFields.get(table);
      tf.set(f, (tf.get(f) ?? 0) + 1);
    }
  }
}

const kqlFieldsKept = [...kqlFields.entries()]
  .filter(([, c]) => c >= KQL_MIN_SUPPORT)
  .sort((a, b) => b[1] - a[1]);

/**
 * Which tables to put in front of the model.
 *
 * The corpus yields 306 distinct tables, which is far too many to present, and
 * the busiest include third-party solution tables — BHEAttackPathsData_CL,
 * Pathlock_TDnR_CL, Veeam_GetSecurityEvents. Those are real, and they exist
 * only in workspaces that installed those solutions, so recommending one to a
 * client who has not is the same silent-zero-rows failure as a wrong field name.
 *
 * `_CL` is Log Analytics' custom-log suffix, so it is a reliable marker of a
 * customer- or vendor-specific table rather than a first-party one.
 */
const KQL_CORE_PREFIXES = [
  'Device', 'Security', 'Email', 'Cloud', 'Identity', 'Azure', 'AAD', 'Signin',
  'SigninLogs', 'Audit', 'Alert', 'Common', 'Threat', 'Url', 'Office', 'Office365',
  'AWSCloudTrail', 'GCP', 'Syslog', 'Heartbeat', 'Update', 'W3CIISLog', 'DnsEvents',
  'Perf', 'BehaviorAnalytics', 'IdentityInfo', 'WindowsEvent', 'SecurityAlert',
];
function isCoreKqlTable(name) {
  if (name.endsWith('_CL')) return false;
  return KQL_CORE_PREFIXES.some(p => name.startsWith(p));
}
const kqlCoreTables = [...kqlTables.entries()]
  .filter(([t]) => isCoreKqlTable(t))
  .sort((a, b) => b[1] - a[1]);

// ---------------------------------------------------------------------------
// SPL — CIM data models, qualified fields, and the macro table
// ---------------------------------------------------------------------------

const splRows = q(
  "SELECT query FROM detections WHERE source_type='splunk_escu' AND query IS NOT NULL AND length(query) > 40");

const splModels = new Map();
const splFields = new Map();
const splCommands = new Map();
const macroRefs = new Map();

for (const { query } of splRows) {
  const text = String(query);

  for (const m of text.matchAll(/\bfrom\s+datamodel\s*[:=]\s*["']?([A-Za-z_][A-Za-z0-9_.]*)/gi)) {
    splModels.set(m[1], (splModels.get(m[1]) ?? 0) + 1);
  }
  // CIM-qualified fields are the canonical ones: Processes.process_name etc.
  for (const m of text.matchAll(/\b([A-Z][A-Za-z0-9_]*\.[a-z_][A-Za-z0-9_]*)/g)) {
    splFields.set(m[1], (splFields.get(m[1]) ?? 0) + 1);
  }
  for (const m of text.matchAll(/\|\s*([a-z_]{2,})\b/g)) {
    splCommands.set(m[1], (splCommands.get(m[1]) ?? 0) + 1);
  }
  for (const m of text.matchAll(/`([a-zA-Z0-9_]+)(?:\([^)]*\))?`/g)) {
    macroRefs.set(m[1], (macroRefs.get(m[1]) ?? 0) + 1);
  }
}

// Load macro definitions.
const macroDefs = new Map();
let macroDirFound = existsSync(MACRO_DIR);
if (macroDirFound) {
  for (const f of readdirSync(MACRO_DIR).filter(n => n.endsWith('.yml'))) {
    const txt = readFileSync(path.join(MACRO_DIR, f), 'utf8');
    const name = txt.match(/^name:\s*(.+)$/m)?.[1]?.trim();
    const def = txt.match(/^definition:\s*(.+)$/m)?.[1]?.trim();
    const desc = txt.match(/^description:\s*(.+)$/m)?.[1]?.trim() ?? '';
    if (name) macroDefs.set(name, { definition: def ?? null, description: desc });
  }
}

/**
 * ESCU macros that live in Splunk_SA_CIM rather than the rules repo. Not
 * resolvable from the corpus, and drop_dm_object_name is load-bearing — it
 * strips the data-model prefix from field names, so a query using it against a
 * Splunk without the CIM app fails.
 */
const EXTERNAL_MACROS = {
  drop_dm_object_name: 'Splunk_SA_CIM — strips the data-model prefix from field names',
  globedistance: 'Splunk_SA_CIM — geospatial distance',
  get_asset: 'Splunk Enterprise Security — asset lookup',
};

const macros = {};
for (const [name, count] of macroRefs.entries()) {
  const d = macroDefs.get(name);
  let kind, expansion = null, note = null;
  if (name.endsWith('_filter')) {
    kind = 'filter';
    note = 'per-detection whitelist hook, empty by default — safe to omit';
  } else if (EXTERNAL_MACROS[name]) {
    kind = 'external';
    note = EXTERNAL_MACROS[name];
  } else if (!d) {
    kind = 'unresolved';
    note = 'no definition found on disk';
  } else if (/customer specific|Replace the macro definition|index, source, sourcetype/i.test(d.description)) {
    kind = 'datasource';
    expansion = d.definition;
    note = 'deployment-specific: this expansion is ESCU\'s default, not a fact about any client';
  } else {
    kind = 'utility';
    expansion = d.definition;
  }
  macros[name] = { kind, references: count, expansion, note };
}

const macroSummary = { filter: 0, datasource: 0, utility: 0, external: 0, unresolved: 0 };
let macroInvocations = 0;
for (const [, m] of Object.entries(macros)) {
  macroSummary[m.kind]++;
  macroInvocations += m.references;
}

// ---------------------------------------------------------------------------
// CQL — CrowdStrike Falcon events
// ---------------------------------------------------------------------------

/** Minimal CSV row splitter honouring double-quoted fields. */
function splitCsvLine(line) {
  const out = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++; } else inQ = !inQ;
    } else if (ch === ',' && !inQ) { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

const cqlEvents = {};
let cqlDescribed = 0;
if (existsSync(CS_CSV)) {
  const lines = readFileSync(CS_CSV, 'utf8').split(/\r?\n/).filter(l => l.trim());
  const header = splitCsvLine(lines[0]).map(h => h.trim().toLowerCase());
  const iH = header.indexOf('header'), iD = header.indexOf('description'), iP = header.indexOf('platforms');
  for (const line of lines.slice(1)) {
    const c = splitCsvLine(line);
    const name = (c[iH] ?? '').trim();
    if (!name) continue;
    const desc = (c[iD] ?? '').trim();
    if (desc) cqlDescribed++;
    cqlEvents[name] = {
      platforms: (c[iP] ?? '').split(',').map(s => s.trim()).filter(Boolean),
      documented: Boolean(desc),
    };
  }
}

// ---------------------------------------------------------------------------
// Assemble
// ---------------------------------------------------------------------------

const catalog = {
  generated: new Date().toISOString(),
  generator: 'scripts/build-field-catalog.mjs',
  note: 'Derived, not authored. Regenerate rather than hand-editing.',
  kql: {
    confidence: 'confirmed',
    source: `${kqlRows.length} Sentinel rules in the local corpus`,
    minSupport: KQL_MIN_SUPPORT,
    tables: Object.fromEntries([...kqlTables.entries()].sort((a, b) => b[1] - a[1])),
    coreTables: Object.fromEntries(kqlCoreTables),
    customTableNote: 'Tables absent from coreTables — notably any ending _CL — exist only in ' +
      'workspaces that installed the corresponding solution. Recommending one to a client who ' +
      'has not is the same silent-zero-rows failure as a wrong field name.',
    fields: Object.fromEntries(kqlFieldsKept),
    tableFields: Object.fromEntries(
      [...kqlTableFields.entries()]
        .filter(([, m]) => m.size > 0)
        .map(([t, m]) => [t, Object.fromEntries([...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40))])
    ),
  },
  spl: {
    confidence: 'confirmed',
    source: `${splRows.length} Splunk ESCU rules + ${macroDefs.size} macro definitions`,
    macroDirFound,
    dataModels: Object.fromEntries([...splModels.entries()].sort((a, b) => b[1] - a[1])),
    fields: Object.fromEntries([...splFields.entries()].sort((a, b) => b[1] - a[1])),
    commands: Object.fromEntries([...splCommands.entries()].sort((a, b) => b[1] - a[1])),
    macros,
    macroSummary,
    macroInvocations,
  },
  cql: {
    confidence: 'community',
    source: 'data/third-party/crowdstrike-events/sensor_events.csv (unofficial extraction)',
    authority: 'https://docs.crowdstrike.com/r/en-US/sensormap.ftmap',
    eventCount: Object.keys(cqlEvents).length,
    documentedCount: cqlDescribed,
    events: cqlEvents,
  },
};

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const pad = (s, n) => String(s).padEnd(n);
console.log('Field catalog\n');
console.log(`KQL   confirmed   ${kqlRows.length} rules -> ${kqlTables.size} tables, ` +
  `${kqlFieldsKept.length} fields (support >= ${KQL_MIN_SUPPORT}, from ${kqlFields.size} candidates)`);
console.log(`SPL   confirmed   ${splRows.length} rules -> ${splModels.size} data models, ` +
  `${splFields.size} CIM fields, ${splCommands.size} commands`);
console.log(`CQL   community   ${Object.keys(cqlEvents).length} events ` +
  `(${cqlDescribed} documented, ${Object.keys(cqlEvents).length - cqlDescribed} undocumented)`);

console.log(`\nSPL macros — ${macroInvocations} invocations across ${Object.keys(macros).length} distinct`);
for (const [k, v] of Object.entries(macroSummary)) {
  console.log(`  ${pad(k, 12)} ${String(v).padStart(5)}`);
}
if (!macroDirFound) {
  console.log(`\n  WARNING: macro directory not found at ${MACRO_DIR}`);
  console.log('  Every macro is classified unresolved. Set SPLUNK_MACROS_PATH.');
}

console.log(`\nTop core KQL tables (${kqlCoreTables.length} of ${kqlTables.size} are core; ` +
  `the rest are solution-specific):`);
for (const [t, c] of kqlCoreTables.slice(0, 10)) {
  console.log(`  ${String(c).padStart(4)}  ${t}`);
}
console.log('\nTop KQL fields kept:');
for (const [f, c] of kqlFieldsKept.slice(0, 10)) {
  console.log(`  ${String(c).padStart(4)}  ${f}`);
}
console.log('\nTop SPL data models:');
for (const [m, c] of [...splModels.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)) {
  console.log(`  ${String(c).padStart(4)}  ${m}`);
}

if (reportOnly) {
  console.log('\n--report: nothing written.');
  conn.closeDb();
  process.exit(0);
}

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(OUT_FILE, JSON.stringify(catalog, null, 2), 'utf8');
const kb = (readFileSync(OUT_FILE).length / 1024).toFixed(0);
console.log(`\nwrote ${path.relative(ROOT, OUT_FILE)} (${kb} KB)`);
conn.closeDb();
