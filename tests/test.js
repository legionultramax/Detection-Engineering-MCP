/**
 * Phase 8 — Registration & Testing
 * Harris HawkEye MCP — Full Validation Suite
 *
 * Test Contracts (per ELITE_TI_TOOLGEN_PROMPT.md):
 *   1  Tool Registration      — every tool has name, description, inputSchema, handler
 *   2  Tool Count             — all phases register expected counts
 *   3  Extraction Accuracy    — intel marker extraction finds T-IDs, CVEs, IOCs, actors
 *   4  Error Resilience       — tools return structured errors, never throw
 *   5  Caching                — cache module imports and functions correctly
 *   6  Correlation Integrity  — correlation tools produce valid fused output shape
 *
 * Run: npm run test
 */

import { initDbAsync } from '../dist/db/connection.js';
import {
  extractIntelMarkers,
  parseRSS,
  extractArticleBody,
  scoreVendorConfidence,
  VENDOR_BLOG_TTL,
  GOVT_FEED_TTL,
  LIVE_FEED_TTL,
  CVE_FEED_TTL,
} from '../dist/tools/threat-intel/vendors/utils.js';
import { getCached, setCached } from '../dist/tools/threat-intel/cache.js';

// Tool module imports (all phases)
import { correlationTools,  correlationToolCount  } from '../dist/tools/threat-intel/correlation/index.js';
import { exploitTools,      exploitToolCount      } from '../dist/tools/threat-intel/exploit/index.js';
import { communityTools,    communityToolCount    } from '../dist/tools/threat-intel/community/index.js';
import { vendorTools,       vendorToolCount       } from '../dist/tools/threat-intel/vendors/index.js';
import { governmentTools,   governmentToolCount   } from '../dist/tools/threat-intel/government/index.js';
import { researchTools,     researchToolCount     } from '../dist/tools/threat-intel/research/index.js';
import { threatIntelTools,  threatIntelToolCount  } from '../dist/tools/threat-intel/index.js';
import { registerAllTools,  getToolsSummary       } from '../dist/tools/index.js';

// ─── MINI TEST HARNESS ────────────────────────────────────────────────────────

const RESET  = '\x1b[0m';
const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN   = '\x1b[36m';
const BOLD   = '\x1b[1m';

let passed = 0;
let failed = 0;
let warned = 0;

function pass(name) {
  console.log(`  ${GREEN}✅ PASS${RESET}  ${name}`);
  passed++;
}

function fail(name, detail = '') {
  console.log(`  ${RED}❌ FAIL${RESET}  ${name}${detail ? `\n         ${RED}${detail}${RESET}` : ''}`);
  failed++;
}

function warn(name, detail = '') {
  console.log(`  ${YELLOW}⚠️  WARN${RESET}  ${name}${detail ? ` (${detail})` : ''}`);
  warned++;
}

function section(title) {
  console.log(`\n${BOLD}${CYAN}═══ ${title} ═══${RESET}`);
}

function assert(condition, name, detail = '') {
  if (condition) pass(name);
  else           fail(name, detail);
}

function assertWarn(condition, name, detail = '') {
  if (condition) pass(name);
  else           warn(name, detail);
}

// ─── INITIALIZE DB ────────────────────────────────────────────────────────────

console.log(`\n${BOLD}Harris HawkEye MCP — Phase 8 Test Suite${RESET}`);
console.log(`${'─'.repeat(50)}`);
console.log('Initializing database...');

await initDbAsync();
console.log('DB ready.\n');

// ─── CONTRACT 1: TOOL REGISTRATION ───────────────────────────────────────────

section('CONTRACT 1: Tool Registration');

/** Validate a single ToolDefinition object */
function validateTool(tool, index) {
  const prefix = `[${index}] ${tool?.name ?? '(unnamed)'}`;

  if (!tool || typeof tool !== 'object') {
    fail(`${prefix} — not an object`);
    return false;
  }

  let ok = true;

  if (typeof tool.name !== 'string' || !tool.name) {
    fail(`${prefix} — missing name`); ok = false;
  }
  if (typeof tool.description !== 'string' || tool.description.length < 10) {
    fail(`${prefix} — description too short or missing`); ok = false;
  }
  if (!tool.inputSchema || tool.inputSchema.type !== 'object') {
    fail(`${prefix} — inputSchema.type must be 'object'`); ok = false;
  }
  if (typeof tool.handler !== 'function') {
    fail(`${prefix} — handler must be a function`); ok = false;
  }
  // snake_case check
  if (!/^[a-z][a-z0-9_]*$/.test(tool.name)) {
    fail(`${prefix} — name '${tool.name}' is not snake_case`); ok = false;
  }

  return ok;
}

/** Run registration checks on a tool array */
function validateToolArray(tools, label) {
  let valid = 0;
  const names = new Set();
  const dupes = [];

  for (let i = 0; i < tools.length; i++) {
    const tool = tools[i];
    if (validateTool(tool, i)) valid++;
    if (tool?.name) {
      if (names.has(tool.name)) dupes.push(tool.name);
      names.add(tool.name);
    }
  }

  assert(valid === tools.length, `${label}: all ${tools.length} tools pass registration checks`,
    `${tools.length - valid} failed`);
  assert(dupes.length === 0, `${label}: no duplicate tool names`,
    `Duplicates: ${dupes.join(', ')}`);
}

validateToolArray(vendorTools,     'Phase 2 (vendor)');
validateToolArray(governmentTools, 'Phase 3 (government)');
validateToolArray(researchTools,   'Phase 4 (research)');
validateToolArray(correlationTools,'Phase 5 (correlation)');
validateToolArray(exploitTools,    'Phase 6 (exploit)');
validateToolArray(communityTools,  'Phase 7 (community)');

// Check for global duplicate names across all TI tools
const allNames   = threatIntelTools.map(t => t.name);
const nameSet    = new Set(allNames);
const globalDups = allNames.filter((n, i) => allNames.indexOf(n) !== i);
assert(globalDups.length === 0, 'Global: no duplicate tool names across all TI tools',
  `Duplicates: ${globalDups.join(', ')}`);

// ─── CONTRACT 2: TOOL COUNT VALIDATION ───────────────────────────────────────

section('CONTRACT 2: Tool Count Validation');

assert(vendorToolCount      === 12, `Phase 2 (vendor):      12 tools — got ${vendorToolCount}`);
assert(governmentToolCount  === 10, `Phase 3 (government):  10 tools — got ${governmentToolCount}`);
assert(researchToolCount    === 20, `Phase 4 (research):    20 tools — got ${researchToolCount}`);
assert(correlationToolCount ===  5, `Phase 5 (correlation):  5 tools — got ${correlationToolCount}`);
assert(exploitToolCount     === 10, `Phase 6 (exploit):     10 tools — got ${exploitToolCount}`);
assert(communityToolCount   ===  9, `Phase 7 (community):    9 tools — got ${communityToolCount}`);

// Total TI
const EXPECTED_TI = 93;
assert(threatIntelToolCount === EXPECTED_TI,
  `Total TI tools: ${EXPECTED_TI} — got ${threatIntelToolCount}`);

// Check registerAllTools and summary
registerAllTools();
const summary = getToolsSummary();
assert(summary.threat_intel === EXPECTED_TI,
  `Registry threat_intel count matches: ${EXPECTED_TI}`);
assert(summary.total > 0,
  `Registry total tools > 0 — got ${summary.total}`);

// Verify Phase 5-7 tool names exist in the global registry
const registeredNames = new Set(summary.names);
const expectedCorrelation = [
  'ti_multi_source_ttp_lookup', 'ti_actor_full_profile',
  'ti_hunt_package', 'ti_report_ingest', 'ti_daily_brief',
];
const expectedExploit = [
  'epss_score_lookup', 'epss_bulk_check', 'nvd_cve_lookup',
  'project_zero_search', 'exploit_db_search', 'rapid7_search',
  'qualys_search', 'tenable_search', 'zdi_search', 'google_tag_search',
];
const expectedCommunity = [
  'malpedia_search', 'malpedia_actor_profile', 'malpedia_family_profile',
  'sans_isc_search', 'anyrun_trending', 'bleeping_search',
  'malwarebytes_search', 'vx_underground_search', 'misp_warninglist_check',
];

for (const name of [...expectedCorrelation, ...expectedExploit, ...expectedCommunity]) {
  assert(registeredNames.has(name), `Tool registered in MCP: ${name}`);
}

// ─── CONTRACT 3: EXTRACTION ACCURACY ─────────────────────────────────────────

section('CONTRACT 3: Intel Marker Extraction');

// T-IDs
{
  const text = 'The actor used T1059.001 (PowerShell) and T1053.005 for persistence via T1547.001';
  const m = extractIntelMarkers(text);
  assert(m.techniques.includes('T1059.001'), 'Extracts T1059.001 from text');
  assert(m.techniques.includes('T1053.005'), 'Extracts T1053.005 from text');
  assert(m.techniques.includes('T1547.001'), 'Extracts T1547.001 from text');
  assert(!m.techniques.includes('T0000'),    'Does not extract invalid T0000');
}

// CVEs
{
  const text = 'Exploiting CVE-2024-3400 and cve-2021-44228 in the wild';
  const m = extractIntelMarkers(text);
  assert(m.cves.includes('CVE-2024-3400'),  'Extracts CVE-2024-3400 (uppercase)');
  assert(m.cves.includes('CVE-2021-44228'), 'Extracts CVE-2021-44228 (lowercase input)');
}

// Defanged IOCs
{
  const text = 'C2 at 192[.]168[.]1[.]100 and beacon to 10[.]0[.]0[.]1 — defanged';
  const m = extractIntelMarkers(text);
  const ips = m.iocs.filter(i => i.type === 'ip').map(i => i.value);
  assert(ips.includes('192.168.1.100'), 'Re-fangs defanged IP 192[.]168[.]1[.]100');
  // 10.0.0.1 is private — should be filtered out
  assert(!ips.includes('10.0.0.1'), 'Filters private IP 10.0.0.1');
}

// Defanged domain
{
  const text = 'Payload served from hxxps://evil[.]example[.]com/payload';
  const m = extractIntelMarkers(text);
  const urls = m.iocs.filter(i => i.type === 'url').map(i => i.value);
  assert(urls.some(u => u.includes('evil.example.com')), 'Re-fangs defanged URL hxxps://evil[.]example[.]com/payload');
}

// SHA-256 hash
{
  const sha256 = 'a'.repeat(64);
  const text   = `Malicious sample hash: ${sha256}`;
  const m      = extractIntelMarkers(text);
  const hashes = m.iocs.filter(i => i.type === 'sha256').map(i => i.value);
  assert(hashes.includes(sha256), 'Extracts SHA-256 hash');
}

// Actor names
{
  const text = 'Attribution: APT29 (Cozy Bear / Midnight Blizzard) used Cobalt Strike';
  const m    = extractIntelMarkers(text);
  assert(m.actors.some(a => a.includes('APT29') || a.includes('Cozy Bear')),
    'Extracts known actor (APT29 / Cozy Bear)');
  assert(m.malware.some(mal => mal.includes('Cobalt Strike')),
    'Extracts known malware (Cobalt Strike)');
}

// Dedup
{
  const text = 'T1059.001 T1059.001 T1059.001';
  const m    = extractIntelMarkers(text);
  const count = m.techniques.filter(t => t === 'T1059.001').length;
  assert(count === 1, 'Deduplicates repeated T-IDs');
}

// RSS parser smoke test
{
  const sampleRss = `<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <item>
      <title>Test Report: APT29 and T1059.001</title>
      <link>https://example.com/report</link>
      <pubDate>Wed, 19 Feb 2026 00:00:00 +0000</pubDate>
      <description><![CDATA[Adversaries used CVE-2024-3400 and T1566.001]]></description>
    </item>
  </channel>
</rss>`;
  const items = parseRSS(sampleRss);
  assert(items.length === 1,                              'RSS parser: returns 1 item');
  assert(items[0].title === 'Test Report: APT29 and T1059.001', 'RSS parser: correct title');
  assert(items[0].link === 'https://example.com/report', 'RSS parser: correct link');
  assert(items[0].description.includes('CVE-2024-3400'), 'RSS parser: CDATA description decoded');
}

// HTML article extractor
{
  const html = `<html><body>
    <nav>Navigation</nav>
    <article><p>The attacker used T1059.001 to execute PowerShell.</p></article>
    <footer>Footer</footer>
  </body></html>`;
  const body = extractArticleBody(html);
  assert(body.includes('T1059.001'), 'HTML extractor: extracts from <article> tag');
  assert(!body.includes('Navigation'), 'HTML extractor: strips <nav> content');
}

// Confidence scorer
{
  const highConf  = scoreVendorConfidence({ techniques: ['T1059.001'], cves: ['CVE-2024-3400'], actors: ['APT29'], malware: ['Cobalt Strike'], tools: [], iocs: [{ type: 'ip', value: '1.2.3.4' }], industries: [], regions: [] });
  const lowConf   = scoreVendorConfidence({ techniques: [], cves: [], actors: [], malware: [], tools: [], iocs: [], industries: [], regions: [] });
  assert(['high', 'medium', 'low'].includes(highConf), `Confidence scorer returns valid tier (high conf: ${highConf})`);
  assert(lowConf === 'low',                             `Confidence scorer returns 'low' for empty markers`);
}

// TTL constants sanity
assert(VENDOR_BLOG_TTL > 0, `VENDOR_BLOG_TTL defined: ${VENDOR_BLOG_TTL}s`);
assert(GOVT_FEED_TTL   > 0, `GOVT_FEED_TTL defined: ${GOVT_FEED_TTL}s`);
assert(LIVE_FEED_TTL   > 0, `LIVE_FEED_TTL defined: ${LIVE_FEED_TTL}s`);
assert(CVE_FEED_TTL    > 0, `CVE_FEED_TTL defined: ${CVE_FEED_TTL}s`);

// ─── CONTRACT 4: ERROR RESILIENCE ────────────────────────────────────────────

section('CONTRACT 4: Error Resilience (mock network failure)');

// Monkey-patch fetch to always reject
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new Error('Simulated network failure'); };

// epss_score_lookup — should return {success: false} not throw
{
  const tool = exploitTools.find(t => t.name === 'epss_score_lookup');
  assert(!!tool, 'epss_score_lookup tool found');
  if (tool) {
    try {
      const result = await tool.handler({ cve_id: 'CVE-2024-3400' });
      assert(result.success === false,  'epss_score_lookup: returns success:false on network failure');
      assert(!!result.error,            'epss_score_lookup: returns error field on failure');
      assert(result.data === null,      'epss_score_lookup: returns data:null on failure');
    } catch (e) {
      fail('epss_score_lookup: THREW exception instead of returning structured error', e.message);
    }
  }
}

// nvd_cve_lookup — should return {success: false} not throw
{
  const tool = exploitTools.find(t => t.name === 'nvd_cve_lookup');
  assert(!!tool, 'nvd_cve_lookup tool found');
  if (tool) {
    try {
      const result = await tool.handler({ cve_id: 'CVE-2024-3400' });
      assert(result.success === false,  'nvd_cve_lookup: returns success:false on network failure');
      assert(!!result.error,            'nvd_cve_lookup: returns error field on failure');
    } catch (e) {
      fail('nvd_cve_lookup: THREW exception instead of returning structured error', e.message);
    }
  }
}

// project_zero_search — should return {success: false} not throw
{
  const tool = exploitTools.find(t => t.name === 'project_zero_search');
  assert(!!tool, 'project_zero_search tool found');
  if (tool) {
    try {
      const result = await tool.handler({ query: 'browser' });
      assert(result.success === false,  'project_zero_search: returns success:false on network failure');
    } catch (e) {
      fail('project_zero_search: THREW exception instead of returning structured error', e.message);
    }
  }
}

// sans_isc_search — should return {success: false} not throw
{
  const tool = communityTools.find(t => t.name === 'sans_isc_search');
  assert(!!tool, 'sans_isc_search tool found');
  if (tool) {
    try {
      const result = await tool.handler({ query: 'log4j' });
      assert(result.success === false,  'sans_isc_search: returns success:false on network failure');
    } catch (e) {
      fail('sans_isc_search: THREW exception instead of returning structured error', e.message);
    }
  }
}

// ti_report_ingest — should return {success: false} not throw
{
  const tool = correlationTools.find(t => t.name === 'ti_report_ingest');
  assert(!!tool, 'ti_report_ingest tool found');
  if (tool) {
    try {
      const result = await tool.handler({ url: 'https://example.com/fake-report' });
      assert(result.success === false,  'ti_report_ingest: returns success:false on network failure');
      assert(!!result.error,            'ti_report_ingest: returns error field on failure');
    } catch (e) {
      fail('ti_report_ingest: THREW exception instead of returning structured error', e.message);
    }
  }
}

// Restore fetch
globalThis.fetch = originalFetch;

// ─── CONTRACT 5: CACHING ─────────────────────────────────────────────────────

section('CONTRACT 5: Caching Functionality');

// Structural: getCached/setCached work correctly
{
  const key = '__test_cache_key__';
  const val = { test: true, value: 42 };

  // Should be null before setting
  const before = getCached(key);
  assert(before === null, 'getCached: returns null for uncached key');

  // Set and retrieve
  setCached(key, val, 60);
  const after = getCached(key);
  assert(after !== null,       'setCached + getCached: value stored successfully');
  assert(after?.test === true, 'Cached value: object properties preserved');
  assert(after?.value === 42,  'Cached value: number preserved');
}

// Verify TTL constants are in expected ranges (sanity)
assert(VENDOR_BLOG_TTL === 14_400, `VENDOR_BLOG_TTL = 4h (14400s)`);
assert(GOVT_FEED_TTL   ===  3_600, `GOVT_FEED_TTL = 1h (3600s)`);
assert(LIVE_FEED_TTL   ===  1_800, `LIVE_FEED_TTL = 30min (1800s)`);
assert(CVE_FEED_TTL    ===  7_200, `CVE_FEED_TTL = 2h (7200s)`);

// ─── CONTRACT 6: CORRELATION INTEGRITY ───────────────────────────────────────

section('CONTRACT 6: Correlation Tool Output Integrity');

// ti_multi_source_ttp_lookup — structural shape test
{
  const tool = correlationTools.find(t => t.name === 'ti_multi_source_ttp_lookup');
  assert(!!tool, 'ti_multi_source_ttp_lookup tool found');

  if (tool) {
    // This call uses DB (synchronous SQLite) + vendor feeds (network — may be empty)
    // Vendor feeds will fail silently if network unavailable
    try {
      const result = await tool.handler({ technique_id: 'T1059.001' });

      // Shape checks — these must pass regardless of data availability
      assert(result !== null && typeof result === 'object',
        'ti_multi_source_ttp_lookup: returns object');
      assert('technique' in result,
        'ti_multi_source_ttp_lookup: has technique field');
      assert('actors_using' in result,
        'ti_multi_source_ttp_lookup: has actors_using field');
      assert('malware_using' in result,
        'ti_multi_source_ttp_lookup: has malware_using field');
      assert('recent_campaigns' in result,
        'ti_multi_source_ttp_lookup: has recent_campaigns field');
      assert('detection_coverage' in result,
        'ti_multi_source_ttp_lookup: has detection_coverage field');
      assert('telemetry_requirements' in result,
        'ti_multi_source_ttp_lookup: has telemetry_requirements field');
      assert('confidence' in result,
        'ti_multi_source_ttp_lookup: has confidence field');
      assert(['high','medium','low'].includes(result.confidence),
        `ti_multi_source_ttp_lookup: confidence is valid tier (${result.confidence})`);
      assert('sources_consulted' in result && Array.isArray(result.sources_consulted),
        'ti_multi_source_ttp_lookup: sources_consulted is array');
      assert(result.sources_consulted.length >= 1,
        `ti_multi_source_ttp_lookup: at least 1 source consulted (${result.sources_consulted.join(', ')})`);
      assert(result.technique.id === 'T1059.001',
        'ti_multi_source_ttp_lookup: technique.id matches input');
      assert(Array.isArray(result.actors_using),
        'ti_multi_source_ttp_lookup: actors_using is array');
      assert(typeof result.detection_coverage.total_rules === 'number',
        'ti_multi_source_ttp_lookup: detection_coverage.total_rules is number');
      assert(['covered','partial','gap'].includes(result.detection_coverage.gap_status),
        `ti_multi_source_ttp_lookup: gap_status is valid (${result.detection_coverage.gap_status})`);
    } catch (e) {
      fail('ti_multi_source_ttp_lookup: threw unexpectedly', e.message);
    }
  }
}

// ti_actor_full_profile — structural shape test
{
  const tool = correlationTools.find(t => t.name === 'ti_actor_full_profile');
  assert(!!tool, 'ti_actor_full_profile tool found');

  if (tool) {
    try {
      const result = await tool.handler({ actor: 'APT29', include_iocs: false });
      assert(result !== null && typeof result === 'object',
        'ti_actor_full_profile: returns object');
      assert('actor_name' in result,
        'ti_actor_full_profile: has actor_name field');
      assert('techniques_total' in result,
        'ti_actor_full_profile: has techniques_total field');
      assert('coverage_summary' in result,
        'ti_actor_full_profile: has coverage_summary field');
      assert('vendor_reports' in result && Array.isArray(result.vendor_reports),
        'ti_actor_full_profile: vendor_reports is array');
      assert(['high','medium','low'].includes(result.confidence),
        `ti_actor_full_profile: confidence is valid (${result.confidence})`);
      assertWarn(result.mitre_profile !== null,
        'ti_actor_full_profile: APT29 found in MITRE DB (requires indexed MITRE data)');
    } catch (e) {
      fail('ti_actor_full_profile: threw unexpectedly', e.message);
    }
  }
}

// ti_hunt_package — structural shape test
{
  const tool = correlationTools.find(t => t.name === 'ti_hunt_package');
  assert(!!tool, 'ti_hunt_package tool found');

  if (tool) {
    try {
      const result = await tool.handler({
        industry: 'finance',
        region:   'United States',
        scenario: 'ransomware',
      });
      assert(result !== null && typeof result === 'object',
        'ti_hunt_package: returns object');
      assert('client_context' in result,
        'ti_hunt_package: has client_context field');
      assert('threat_actors' in result && Array.isArray(result.threat_actors),
        'ti_hunt_package: threat_actors is array');
      assert('priority_techniques' in result && Array.isArray(result.priority_techniques),
        'ti_hunt_package: priority_techniques is array');
      assert('coverage_score' in result,
        'ti_hunt_package: has coverage_score field');
      assert('generated_at' in result,
        'ti_hunt_package: has generated_at field');
      assert(result.client_context.industry === 'finance',
        'ti_hunt_package: client_context.industry preserved');
    } catch (e) {
      fail('ti_hunt_package: threw unexpectedly', e.message);
    }
  }
}

// ti_daily_brief — structural shape test (no network — vendor feeds will be empty)
{
  const tool = correlationTools.find(t => t.name === 'ti_daily_brief');
  assert(!!tool, 'ti_daily_brief tool found');

  if (tool) {
    // Patch fetch to return empty RSS so we avoid network dependency
    const savedFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
      ok: true,
      text: async () => `<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>`,
    });

    try {
      const result = await tool.handler({ hours_lookback: 24, industries: ['finance'] });
      assert(result !== null && typeof result === 'object',
        'ti_daily_brief: returns object');
      assert('brief_date' in result,
        'ti_daily_brief: has brief_date field');
      assert('items' in result && Array.isArray(result.items),
        'ti_daily_brief: items is array');
      assert('intel_summary' in result,
        'ti_daily_brief: has intel_summary field');
      assert('vendors_polled' in result,
        'ti_daily_brief: has vendors_polled field');
    } catch (e) {
      fail('ti_daily_brief: threw unexpectedly', e.message);
    } finally {
      globalThis.fetch = savedFetch;
    }
  }
}

// epss_bulk_check — structural shape test (mock good EPSS response)
{
  const tool = exploitTools.find(t => t.name === 'epss_bulk_check');
  assert(!!tool, 'epss_bulk_check tool found');

  if (tool) {
    const savedFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      if (url.includes('first.org')) {
        return {
          ok: true,
          text: async () => JSON.stringify({
            status: 'OK',
            total:  2,
            data: [
              { cve: 'CVE-2024-3400', epss: '0.94500', percentile: '0.99800', date: '2026-02-19' },
              { cve: 'CVE-2021-44228', epss: '0.97600', percentile: '0.99900', date: '2026-02-19' },
            ],
          }),
        };
      }
      throw new Error('Unexpected URL');
    };

    try {
      const result = await tool.handler({ cve_ids: ['CVE-2024-3400', 'CVE-2021-44228'] });
      assert(result.success === true,                 'epss_bulk_check: success:true on valid response');
      assert(result.data.scored === 2,                'epss_bulk_check: scored 2 CVEs');
      assert(result.data.results[0].epss_score > 0,  'epss_bulk_check: first result has epss_score');
      assert(result.data.results[0].risk_tier !== undefined, 'epss_bulk_check: risk_tier assigned');
      // Should be sorted descending by score
      assert(result.data.results[0].epss_score >= result.data.results[1].epss_score,
        'epss_bulk_check: results sorted by score descending');
    } catch (e) {
      fail('epss_bulk_check: threw unexpectedly', e.message);
    } finally {
      globalThis.fetch = savedFetch;
    }
  }
}

// misp_warninglist_check — mock response test
{
  const tool = communityTools.find(t => t.name === 'misp_warninglist_check');
  assert(!!tool, 'misp_warninglist_check tool found');

  if (tool) {
    const savedFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
      ok:   true,
      text: async () => JSON.stringify({ list: ['google.com', 'microsoft.com', 'github.com'] }),
    });

    try {
      // google.com should be in the warning list (false positive candidate)
      const result1 = await tool.handler({ ioc: 'google.com', lists: ['google'] });
      assert(result1.success === true,
        'misp_warninglist_check: returns success:true');
      assert(result1.data.is_false_positive_candidate === true,
        'misp_warninglist_check: google.com flagged as FP candidate');

      // evil.example.com should NOT be in the list
      const result2 = await tool.handler({ ioc: 'evil.example.com', lists: ['google'] });
      assert(result2.data.is_false_positive_candidate === false,
        'misp_warninglist_check: evil.example.com not flagged as FP');
    } catch (e) {
      fail('misp_warninglist_check: threw unexpectedly', e.message);
    } finally {
      globalThis.fetch = savedFetch;
    }
  }
}

// ─── FINAL SUMMARY ────────────────────────────────────────────────────────────

const total = passed + failed + warned;
const pct   = total > 0 ? Math.round((passed / total) * 100) : 0;

console.log(`\n${'═'.repeat(50)}`);
console.log(`${BOLD}Phase 8 — Test Results${RESET}`);
console.log(`${'─'.repeat(50)}`);
console.log(`  ${GREEN}PASSED${RESET}:  ${passed}`);
console.log(`  ${RED}FAILED${RESET}:  ${failed}`);
console.log(`  ${YELLOW}WARNED${RESET}:  ${warned}`);
console.log(`  TOTAL:   ${total}`);
console.log(`  SCORE:   ${pct}%`);
console.log(`${'═'.repeat(50)}\n`);

if (failed > 0) {
  console.error(`${RED}${BOLD}${failed} test(s) failed. Fix before deployment.${RESET}\n`);
  process.exit(1);
} else if (warned > 0) {
  console.log(`${YELLOW}All critical tests passed. ${warned} warning(s) — likely require MITRE DB to be indexed.${RESET}\n`);
  process.exit(0);
} else {
  console.log(`${GREEN}${BOLD}All ${passed} tests passed. Server is ready for deployment.${RESET}\n`);
  process.exit(0);
}
