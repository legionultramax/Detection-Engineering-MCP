# ELITE THREAT INTELLIGENCE MCP TOOL GENERATION PROMPT

> **Purpose:** Give this prompt to an AI code generator to produce production-ready MCP tools that crawl, ingest, normalize, and correlate threat intelligence from 70+ sources across 7 tiers — fully integrated into the Harris HawkEye MCP server.
>
> **Self-tested:** This prompt includes validation contracts, test harnesses, and architectural compliance checks.

---

## SYSTEM CONTEXT — READ THIS FIRST

You are an elite detection engineer and TypeScript developer building MCP (Model Context Protocol) tools for a threat intelligence platform called **Harris HawkEye**. This platform is used by MSSP analysts to correlate threat intelligence with MITRE ATT&CK techniques and generate detections.

You MUST produce code that integrates into an **existing MCP server** with the architecture described below. Do NOT create a new server. You are adding tools to an existing system.

---

## ARCHITECTURE YOU MUST FOLLOW (NON-NEGOTIABLE)

### A. Tool Definition Pattern

Every tool MUST use this exact pattern:

```typescript
import { defineTool, type ToolDefinition } from '../registry.js';

const myTool = defineTool({
  name: 'tool_name',                              // snake_case, prefixed by source
  description: 'What this tool does',             // Concise, operational description
  inputSchema: {
    type: 'object' as const,
    properties: {
      param1: { type: 'string', description: '...' },
    },
    required: ['param1'],
  },
  handler: async (args) => {
    const { param1 } = args as { param1: string };
    return someImplementation(param1);
  },
});

export const myTools: ToolDefinition[] = [myTool];
export const myToolCount = myTools.length;
```

### B. Response Envelope (MANDATORY)

Every threat intel tool MUST return `IntelResult<T>`:

```typescript
interface IntelResult<T> {
  source: string;                        // e.g., 'mandiant', 'kaspersky', 'cisa'
  success: boolean;
  data: T | null;
  error?: string;
  queried_at: string;                    // ISO-8601
  pivot_suggestions?: PivotSuggestion[];
}

interface PivotSuggestion {
  type: 'ip' | 'domain' | 'hash' | 'url' | 'family' | 'actor' | 'tag' | 'imphash' | 'technique' | 'cve';
  value: string;
  reason: string;
  source_tool: string;
  confidence?: 'high' | 'medium' | 'low';
}
```

### C. HTTP Client Pattern

```typescript
// Use native fetch (Node 18+)
// Always implement:
//   1. TTL-based caching via withCache()
//   2. Rate-limit backoff (429 → sleep → retry)
//   3. Graceful error handling (never throw, return makeErr())
//   4. User-Agent header identification

const HEADERS = {
  'User-Agent': 'HarrisHawkEye-MCP/1.0 (ThreatIntel)',
  'Accept': 'application/json',
};

// Error helper
function makeErr(source: string, error: string): IntelResult<null> {
  return {
    source,
    success: false,
    data: null,
    error,
    queried_at: new Date().toISOString(),
    pivot_suggestions: [],
  };
}
```

### D. Caching

```typescript
import { withCache, makeCacheKey } from './cache.js';

// TTLs by source reliability:
const VENDOR_BLOG_TTL = 14_400;    // 4 hours (blog content doesn't change fast)
const GOVT_FEED_TTL   = 3_600;     // 1 hour (advisories can update)
const LIVE_FEED_TTL   = 1_800;     // 30 minutes (IOC feeds)
const CVE_FEED_TTL    = 7_200;     // 2 hours (NVD/EPSS)
```

### E. File Organization

```
src/tools/threat-intel/
├── vendors/                    ← NEW DIRECTORY
│   ├── mandiant.ts
│   ├── microsoft.ts
│   ├── crowdstrike.ts
│   ├── unit42.ts
│   ├── talos.ts
│   ├── kaspersky.ts
│   ├── eset.ts
│   ├── trendmicro.ts
│   ├── sentinelone.ts
│   ├── symantec.ts
│   ├── sophos.ts
│   ├── secureworks.ts
│   ├── checkpoint.ts
│   ├── proofpoint.ts
│   ├── trellix.ts
│   ├── fortinet.ts
│   ├── cybereason.ts
│   ├── elastic.ts
│   ├── types.ts               ← Shared vendor types
│   └── index.ts               ← Aggregator
├── government/                 ← NEW DIRECTORY
│   ├── cisa-alerts.ts
│   ├── nsa.ts
│   ├── fbi.ts
│   ├── ncsc-uk.ts
│   ├── cert-eu.ts
│   ├── anssi.ts
│   ├── jpcert.ts
│   ├── acsc.ts
│   ├── cccs.ts
│   ├── types.ts
│   └── index.ts
├── research/                   ← NEW DIRECTORY
│   ├── recorded-future.ts
│   ├── group-ib.ts
│   ├── red-canary.ts
│   ├── dragos.ts
│   ├── volexity.ts
│   ├── dfir-report.ts
│   ├── ncc-group.ts
│   ├── huntress.ts
│   ├── withsecure.ts
│   ├── intezer.ts
│   ├── sekoia.ts
│   ├── outpost24.ts
│   ├── blackberry.ts
│   ├── threatfabric.ts
│   ├── types.ts
│   └── index.ts
├── exploit-research/           ← NEW DIRECTORY
│   ├── project-zero.ts
│   ├── google-tag.ts
│   ├── zdi.ts
│   ├── rapid7.ts
│   ├── qualys.ts
│   ├── tenable.ts
│   ├── bishopfox.ts
│   ├── horizon3.ts
│   ├── types.ts
│   └── index.ts
├── community/                  ← NEW DIRECTORY
│   ├── sans-isc.ts
│   ├── malwarebytes.ts
│   ├── bleepingcomputer.ts
│   ├── krebs.ts
│   ├── vx-underground.ts
│   ├── malpedia.ts
│   ├── anyrun.ts
│   ├── types.ts
│   └── index.ts
├── feeds/                      ← NEW DIRECTORY
│   ├── epss.ts
│   ├── misp-feeds.ts
│   ├── opencti.ts
│   ├── types.ts
│   └── index.ts
├── correlation/                ← NEW DIRECTORY (THE BRAIN)
│   ├── ttp-correlator.ts
│   ├── multi-source-fuser.ts
│   ├── confidence-scorer.ts
│   ├── report-normalizer.ts
│   ├── types.ts
│   └── index.ts
├── abusech.ts                  ← EXISTING
├── otx.ts                      ← EXISTING
├── cache.ts                    ← EXISTING
├── types.ts                    ← EXISTING
├── pivot.ts                    ← EXISTING
└── index.ts                    ← EXISTING (update to register new tools)
```

### F. Registration in Main Index

After building all tools, update `src/tools/threat-intel/index.ts`:

```typescript
import { vendorTools, vendorToolCount } from './vendors/index.js';
import { governmentTools, governmentToolCount } from './government/index.js';
import { researchTools, researchToolCount } from './research/index.js';
import { exploitResearchTools, exploitResearchToolCount } from './exploit-research/index.js';
import { communityTools, communityToolCount } from './community/index.js';
import { feedTools, feedToolCount } from './feeds/index.js';
import { correlationTools, correlationToolCount } from './correlation/index.js';

export const threatIntelTools: ToolDefinition[] = [
  ...existingTools,          // Keep all existing tools
  ...vendorTools,
  ...governmentTools,
  ...researchTools,
  ...exploitResearchTools,
  ...communityTools,
  ...feedTools,
  ...correlationTools,
];
```

---

## TOOL SPECIFICATIONS BY TIER

### ═══════════════════════════════════════════
### TIER 1: HIGH-FIDELITY VENDOR TOOLS
### ═══════════════════════════════════════════

For EACH vendor (Mandiant, Microsoft, CrowdStrike, Unit 42, Talos, Kaspersky, ESET, Trend Micro, SentinelOne, Symantec, Sophos, Secureworks, Check Point, Proofpoint, Trellix, Fortinet, Cybereason, Elastic), generate TWO tools:

#### Tool 1: `{vendor}_search_reports`

**Purpose:** Search the vendor's public blog/research for threat reports matching a keyword, actor name, malware family, or CVE.

**Implementation Strategy:**
- Use web scraping via `fetch()` against the vendor's public blog/research RSS feed or search endpoint
- Parse HTML/RSS/JSON response to extract report metadata
- Normalize to standard format

**Vendor Endpoints (use these exact URLs):**

```typescript
const VENDOR_ENDPOINTS: Record<string, VendorConfig> = {
  mandiant: {
    search: 'https://cloud.google.com/blog/topics/threat-intelligence/',
    rss: 'https://cloud.google.com/blog/topics/threat-intelligence/rss',
    name: 'Mandiant / Google Threat Intelligence',
  },
  microsoft: {
    search: 'https://www.microsoft.com/en-us/security/blog/',
    rss: 'https://www.microsoft.com/en-us/security/blog/feed/',
    name: 'Microsoft Threat Intelligence',
  },
  crowdstrike: {
    search: 'https://www.crowdstrike.com/en-us/blog/',
    rss: 'https://www.crowdstrike.com/en-us/blog/feed/',
    name: 'CrowdStrike Intelligence',
  },
  unit42: {
    search: 'https://unit42.paloaltonetworks.com/',
    rss: 'https://unit42.paloaltonetworks.com/feed/',
    name: 'Palo Alto Unit 42',
  },
  talos: {
    search: 'https://blog.talosintelligence.com/',
    rss: 'https://blog.talosintelligence.com/rss/',
    name: 'Cisco Talos',
  },
  kaspersky: {
    search: 'https://securelist.com/',
    rss: 'https://securelist.com/feed/',
    name: 'Kaspersky Securelist',
  },
  eset: {
    search: 'https://www.welivesecurity.com/',
    rss: 'https://www.welivesecurity.com/feed/',
    name: 'ESET WeLiveSecurity',
  },
  trendmicro: {
    search: 'https://www.trendmicro.com/en_us/research.html',
    rss: 'https://feeds.trendmicro.com/TrendMicroResearch',
    name: 'Trend Micro Research',
  },
  sentinelone: {
    search: 'https://www.sentinelone.com/labs/',
    rss: 'https://www.sentinelone.com/labs/feed/',
    name: 'SentinelOne Labs',
  },
  symantec: {
    search: 'https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence',
    rss: 'https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/rss',
    name: 'Symantec Threat Hunter',
  },
  sophos: {
    search: 'https://news.sophos.com/en-us/category/threat-research/',
    rss: 'https://news.sophos.com/en-us/category/threat-research/feed/',
    name: 'Sophos X-Ops',
  },
  secureworks: {
    search: 'https://www.secureworks.com/research',
    rss: 'https://www.secureworks.com/rss?feed=research',
    name: 'Secureworks CTU',
  },
  checkpoint: {
    search: 'https://research.checkpoint.com/',
    rss: 'https://research.checkpoint.com/feed/',
    name: 'Check Point Research',
  },
  proofpoint: {
    search: 'https://www.proofpoint.com/us/blog/threat-insight',
    rss: 'https://www.proofpoint.com/us/rss.xml',
    name: 'Proofpoint Threat Insight',
  },
  trellix: {
    search: 'https://www.trellix.com/blogs/research/',
    rss: 'https://www.trellix.com/blogs/research/rss/',
    name: 'Trellix Research',
  },
  fortinet: {
    search: 'https://www.fortinet.com/blog/threat-research',
    rss: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml',
    name: 'FortiGuard Labs',
  },
  cybereason: {
    search: 'https://www.cybereason.com/blog/research',
    rss: 'https://www.cybereason.com/blog/rss.xml',
    name: 'Cybereason Nocturnus',
  },
  elastic: {
    search: 'https://www.elastic.co/security-labs',
    rss: 'https://www.elastic.co/security-labs/rss/feed.xml',
    name: 'Elastic Security Labs',
  },
};
```

**Input Schema:**
```typescript
{
  type: 'object',
  properties: {
    query: { type: 'string', description: 'Search keyword: actor name, malware family, CVE, or technique' },
    limit: { type: 'number', description: 'Max results (default: 10)' },
  },
  required: ['query'],
}
```

**Output Data Shape:**
```typescript
interface VendorSearchResult {
  reports: Array<{
    title: string;
    url: string;
    published: string;         // ISO-8601
    snippet: string;           // First 300 chars of content
    tags: string[];            // Any tags/categories from the source
    actors_mentioned: string[];  // Extracted actor names (regex match)
    techniques_mentioned: string[];  // Extracted T-IDs (regex: /T\d{4}(\.\d{3})?/g)
    cves_mentioned: string[];  // Extracted CVEs (regex: /CVE-\d{4}-\d{4,}/g)
    malware_mentioned: string[];  // Extracted malware names
  }>;
  total_found: number;
  source: string;
  query: string;
}
```

**Extraction Logic (apply to ALL vendors):**
```typescript
function extractIntelMarkers(text: string): IntelMarkers {
  return {
    techniques: [...new Set(text.match(/T\d{4}(?:\.\d{3})?/g) || [])],
    cves: [...new Set(text.match(/CVE-\d{4}-\d{4,}/g) || [])],
    actors: extractActorNames(text),       // Match against MITRE group names
    malware: extractMalwareNames(text),     // Match against known families
  };
}
```

#### Tool 2: `{vendor}_fetch_report`

**Purpose:** Fetch a specific report URL from this vendor and extract structured TTP intelligence.

**Input Schema:**
```typescript
{
  type: 'object',
  properties: {
    url: { type: 'string', description: 'Full URL of the vendor report to analyze' },
  },
  required: ['url'],
}
```

**Output Data Shape:**
```typescript
interface VendorReportAnalysis {
  url: string;
  title: string;
  published: string;
  vendor: string;
  extracted_intelligence: {
    actors: string[];
    malware_families: string[];
    techniques: Array<{
      id: string;           // e.g., T1059.001
      name: string;         // e.g., PowerShell
      context: string;      // How the technique was used (extracted sentence)
    }>;
    cves: string[];
    iocs: Array<{
      type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
      value: string;
    }>;
    tools_used: string[];    // e.g., Cobalt Strike, Mimikatz
    target_industries: string[];
    target_regions: string[];
    kill_chain_phases: string[];   // Which phases of the attack are covered
  };
  raw_text_length: number;
  confidence: 'high' | 'medium' | 'low';  // Based on extraction completeness
}
```

**Implementation Notes:**
- Fetch the URL content with appropriate headers
- Parse HTML to extract article body text (strip nav, footer, ads)
- Apply `extractIntelMarkers()` to the body text
- Extract IOCs using regex patterns:
  ```typescript
  const IOC_PATTERNS = {
    ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    ipv4_defanged: /\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b/g,
    domain: /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b/g,
    domain_defanged: /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\][a-zA-Z]{2,}\b/g,
    md5: /\b[a-fA-F0-9]{32}\b/g,
    sha1: /\b[a-fA-F0-9]{40}\b/g,
    sha256: /\b[a-fA-F0-9]{64}\b/g,
    url: /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
    url_defanged: /hxxps?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
    cve: /CVE-\d{4}-\d{4,}/g,
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    mitre: /T\d{4}(?:\.\d{3})?/g,
  };
  ```
- Refang defanged IOCs: `[.]` → `.`, `hxxp` → `http`
- Filter out common false positive domains (google.com, microsoft.com, github.com, etc.)

---

### ═══════════════════════════════════════════
### TIER 2: GOVERNMENT & CERT TOOLS
### ═══════════════════════════════════════════

#### Tool: `cisa_search_advisories`

```typescript
// CISA has a public JSON API
const CISA_ADVISORIES_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
// For alerts: scrape/RSS
const CISA_ALERTS_RSS = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';
```

**Input:** `{ query: string, type?: 'advisory' | 'alert' | 'all' }`
**Output:** Same `VendorSearchResult` format with government-specific fields

#### Tool: `ncsc_uk_search`

```typescript
const NCSC_RSS = 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml';
```

#### Tool: `govt_joint_advisory_search`

**Purpose:** Search for joint advisories (CISA + FBI + NSA + Five Eyes) which are the highest-confidence TTP sources.

**Input:** `{ query: string, year?: number }`
**Implementation:** Search across CISA, NCSC-UK, ACSC, CCCS simultaneously and deduplicate by advisory ID.

Generate similar tools for: `nsa_search_advisories`, `fbi_flash_search`, `cert_eu_search`, `anssi_search`, `jpcert_search`, `acsc_search`, `cccs_search`

---

### ═══════════════════════════════════════════
### TIER 3: SPECIALIZED RESEARCH TOOLS
### ═══════════════════════════════════════════

Same `{source}_search_reports` and `{source}_fetch_report` pattern for each source.

**Key endpoints:**
```typescript
const RESEARCH_ENDPOINTS: Record<string, VendorConfig> = {
  dfir_report: {
    search: 'https://thedfirreport.com/',
    rss: 'https://thedfirreport.com/feed/',
    name: 'The DFIR Report',
  },
  volexity: {
    search: 'https://www.volexity.com/blog/',
    rss: 'https://www.volexity.com/blog/feed/',
    name: 'Volexity',
  },
  red_canary: {
    search: 'https://redcanary.com/blog/',
    rss: 'https://redcanary.com/blog/feed/',
    name: 'Red Canary',
  },
  huntress: {
    search: 'https://www.huntress.com/blog',
    rss: 'https://www.huntress.com/blog/rss.xml',
    name: 'Huntress Labs',
  },
  dragos: {
    search: 'https://www.dragos.com/blog/',
    rss: 'https://www.dragos.com/blog/feed/',
    name: 'Dragos (OT/ICS)',
  },
  ncc_group: {
    search: 'https://research.nccgroup.com/',
    rss: 'https://research.nccgroup.com/feed/',
    name: 'NCC Group',
  },
  withsecure: {
    search: 'https://labs.withsecure.com/',
    rss: 'https://labs.withsecure.com/feed/',
    name: 'WithSecure Labs',
  },
  intezer: {
    search: 'https://intezer.com/blog/',
    rss: 'https://intezer.com/blog/feed/',
    name: 'Intezer Research',
  },
  sekoia: {
    search: 'https://blog.sekoia.io/',
    rss: 'https://blog.sekoia.io/feed/',
    name: 'Sekoia.io',
  },
  blackberry: {
    search: 'https://blogs.blackberry.com/en/category/research-and-intelligence',
    rss: 'https://blogs.blackberry.com/en/feed',
    name: 'BlackBerry Research',
  },
};
```

---

### ═══════════════════════════════════════════
### TIER 4: EXPLOIT & VULNERABILITY RESEARCH TOOLS
### ═══════════════════════════════════════════

#### Tool: `epss_score_lookup`

**Purpose:** Get FIRST EPSS (Exploit Prediction Scoring System) probability for a CVE.

```typescript
const EPSS_API = 'https://api.first.org/data/v1/epss';
// GET ?cve=CVE-2024-1234
```

**Input:** `{ cve_id: string }`
**Output:**
```typescript
interface EPSSResult {
  cve: string;
  epss_score: number;        // 0.0 - 1.0 probability of exploitation in 30 days
  percentile: number;        // Relative ranking
  date: string;
}
```

#### Tool: `project_zero_search`

```typescript
const PZ_ISSUES = 'https://bugs.chromium.org/p/project-zero/issues/list';
// Or RSS: project-zero.issues.chromium.org
```

#### Tool: `exploit_db_search`

```typescript
const EXPLOIT_DB_API = 'https://exploit-db.com/search';
// Or use the GitLab mirror: https://gitlab.com/exploit-database/exploitdb
```

Generate similar tools for: `rapid7_search`, `qualys_search`, `tenable_search`, `zdi_search`, `google_tag_search`

---

### ═══════════════════════════════════════════
### TIER 5: COMMUNITY & OPEN RESEARCH TOOLS
### ═══════════════════════════════════════════

#### Tool: `sans_isc_search`

```typescript
const SANS_ISC_API = 'https://isc.sans.edu/api/';
const SANS_ISC_RSS = 'https://isc.sans.edu/rssfeed.xml';
```

#### Tool: `malpedia_search`

```typescript
const MALPEDIA_API = 'https://malpedia.caad.fkie.fraunhofer.de/api/';
// GET /api/list/actors
// GET /api/get/actor/{actor_id}
// GET /api/list/families
// GET /api/get/family/{family_name}
// GET /api/find/actor/{search_term}
```

**Input:** `{ query: string, type?: 'actor' | 'family' | 'all' }`

#### Tool: `anyrun_trending`

```typescript
const ANYRUN_TRENDS = 'https://any.run/malware-trends/';
```

Generate similar tools for: `bleeping_search`, `malwarebytes_search`, `vx_underground_search`

---

### ═══════════════════════════════════════════
### TIER 6: STRUCTURED FEED TOOLS
### ═══════════════════════════════════════════

#### Tool: `epss_bulk_check`

**Purpose:** Check EPSS scores for multiple CVEs at once (batch enrichment).

```typescript
// GET https://api.first.org/data/v1/epss?cve=CVE-2024-1234,CVE-2024-5678
```

#### Tool: `misp_warninglist_check`

**Purpose:** Check if an IOC appears in MISP warning lists (known false positives).

```typescript
const MISP_WARNINGLISTS = 'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/';
```

#### Tool: `nvd_cve_lookup`

```typescript
const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
// GET ?cveId=CVE-2024-1234
// Rate: 5 requests per 30 seconds without API key, 50 with key
```

---

### ═══════════════════════════════════════════
### TIER 7: THREAT ACTOR & CAMPAIGN DATABASES
### ═══════════════════════════════════════════

#### Tool: `malpedia_actor_profile`

```typescript
// GET https://malpedia.caad.fkie.fraunhofer.de/api/get/actor/{name}
// Returns: aliases, country, motivation, description, families used
```

#### Tool: `malpedia_family_profile`

```typescript
// GET https://malpedia.caad.fkie.fraunhofer.de/api/get/family/{name}
// Returns: alt_names, urls, description, attribution
```

---

## THE CORRELATION ENGINE (TIER 8 — THE BRAIN)

This is the most critical component. These tools FUSE intelligence from all tiers.

### ═══════════════════════════════════════════
### CORRELATION TOOL 1: `ti_multi_source_ttp_lookup`
### ═══════════════════════════════════════════

**Purpose:** Given a MITRE technique ID, fan out to ALL available sources and return a fused intelligence picture showing who uses it, how, with what tools, and what detections exist.

**Input:**
```typescript
{
  type: 'object',
  properties: {
    technique_id: { type: 'string', description: 'MITRE ATT&CK technique ID (e.g., T1059.001)' },
    client_industry: { type: 'string', description: 'Optional: client industry for relevance filtering' },
    client_region: { type: 'string', description: 'Optional: client region for relevance filtering' },
  },
  required: ['technique_id'],
}
```

**Implementation Flow:**
```typescript
async function multiSourceTTPLookup(techniqueId: string, industry?: string, region?: string) {
  // PHASE 1: Structured intelligence (fast, cached)
  const [mitreData, groups, software, dataSources, mitigations, existingDetections] = await Promise.all([
    lookupMitreTechnique(techniqueId),
    getGroupsUsingTechnique(techniqueId),
    getSoftwareUsingTechnique(techniqueId),
    getDataSources(techniqueId),
    getMitigations(techniqueId),
    listByMitre(techniqueId),
  ]);

  // PHASE 2: Web intelligence (slower, richer)
  const techniqueName = mitreData.data?.name || techniqueId;
  const searchQueries = [
    `${techniqueName} attack technique detection`,
    `${techniqueId} threat hunting`,
    ...(industry ? [`${techniqueName} ${industry} attack`] : []),
  ];

  const vendorResults = await Promise.allSettled([
    searchVendorReports('mandiant', techniqueName),
    searchVendorReports('microsoft', techniqueName),
    searchVendorReports('crowdstrike', techniqueName),
    searchVendorReports('elastic', techniqueName),
    searchVendorReports('dfir_report', techniqueName),
    searchVendorReports('red_canary', techniqueName),
  ]);

  // PHASE 3: FUSE
  return fuseIntelligence({
    technique: mitreData,
    actors: groups,
    malware: software,
    telemetry_requirements: dataSources,
    mitigations: mitigations,
    existing_detections: existingDetections,
    vendor_reports: extractSuccessful(vendorResults),
    industry_relevance: filterByIndustry(groups, industry),
    regional_relevance: filterByRegion(groups, region),
  });
}
```

**Output:**
```typescript
interface FusedTTPIntelligence {
  technique: {
    id: string;
    name: string;
    tactic: string;
    description: string;
  };
  actors_using: Array<{
    name: string;
    aliases: string[];
    motivation: string;
    relevance: 'direct' | 'related';
    source: string;          // 'mitre' | 'vendor_report'
  }>;
  malware_using: Array<{
    name: string;
    type: string;
    source: string;
  }>;
  recent_campaigns: Array<{
    title: string;
    vendor: string;
    url: string;
    date: string;
    relevance_snippet: string;
  }>;
  detection_coverage: {
    total_rules: number;
    by_source: Record<string, number>;
    gap_status: 'covered' | 'partial' | 'gap';
  };
  telemetry_requirements: {
    data_sources: string[];
    event_ids: string[];
    feasibility_notes: string;
  };
  mitigations: string[];
  confidence: 'high' | 'medium' | 'low';
  sources_consulted: string[];
  last_updated: string;
}
```

### ═══════════════════════════════════════════
### CORRELATION TOOL 2: `ti_actor_full_profile`
### ═══════════════════════════════════════════

**Purpose:** Given an actor name, build the most complete profile possible by fusing MITRE ATT&CK data with live vendor reporting.

**Input:**
```typescript
{
  type: 'object',
  properties: {
    actor: { type: 'string', description: 'Threat actor name (e.g., APT29, Lazarus Group)' },
    include_iocs: { type: 'boolean', description: 'Also pivot for IOCs via OTX/abuse.ch (default: false)' },
  },
  required: ['actor'],
}
```

**Implementation Flow:**
```typescript
async function actorFullProfile(actor: string, includeIOCs = false) {
  // PHASE 1: Structured
  const [mitreGroup, otxActor] = await Promise.all([
    getThreotGroup(actor),
    otxSearchActor(actor),
  ]);

  // PHASE 2: Vendor reports about this actor
  const vendorSearches = await Promise.allSettled(
    PRIORITY_VENDORS.map(v => searchVendorReports(v, actor))
  );

  // PHASE 3: IOC pivot (optional)
  let iocData = null;
  if (includeIOCs && otxActor.success) {
    iocData = await pivotExpandIOCs(
      otxActor.data.iocs,
      actor,
      otxActor.data.malware_families[0]
    );
  }

  // PHASE 4: Technique coverage assessment
  const techniques = mitreGroup.data?.techniques || [];
  const coverageChecks = await Promise.all(
    techniques.slice(0, 20).map(t => listByMitre(t.technique_id))
  );

  return fuseActorProfile({
    mitre: mitreGroup,
    otx: otxActor,
    vendor_reports: extractSuccessful(vendorSearches),
    iocs: iocData,
    coverage: buildCoverageMatrix(techniques, coverageChecks),
  });
}
```

### ═══════════════════════════════════════════
### CORRELATION TOOL 3: `ti_hunt_package`
### ═══════════════════════════════════════════

**Purpose:** THE ULTIMATE TOOL. Given a client context + threat scenario, produce a complete hunt package: actors, TTPs, detections, gaps, and queries — all backed by multi-source intelligence.

**Input:**
```typescript
{
  type: 'object',
  properties: {
    industry: { type: 'string', description: 'Client industry' },
    region: { type: 'string', description: 'Client region' },
    scenario: { type: 'string', description: 'Threat scenario (e.g., "ransomware", "espionage", "supply-chain")' },
    log_sources: {
      type: 'array',
      items: { type: 'string' },
      description: 'Available log sources (e.g., ["sysmon", "crowdstrike", "azure_ad"])'
    },
    max_techniques: { type: 'number', description: 'Max techniques to analyze (default: 15)' },
  },
  required: ['industry', 'region', 'scenario'],
}
```

**Output:**
```typescript
interface HuntPackage {
  client_context: { industry: string; region: string; scenario: string };
  threat_actors: Array<{
    name: string;
    relevance: 'primary' | 'secondary';
    reason: string;
  }>;
  priority_techniques: Array<{
    id: string;
    name: string;
    tactic: string;
    actors_using: string[];
    detection_status: 'covered' | 'partial' | 'gap';
    detection_count: number;
    data_source_available: boolean;
    priority: 'P1' | 'P2' | 'P3';
  }>;
  detection_gaps: Array<{
    technique_id: string;
    technique_name: string;
    reason: string;
    recommended_data_source: string;
  }>;
  vendor_intelligence: Array<{
    vendor: string;
    report_title: string;
    url: string;
    relevance: string;
  }>;
  suggested_queries: Array<{
    technique_id: string;
    query_type: 'kql' | 'sigma' | 'spl';
    query: string;
    description: string;
  }>;
  coverage_score: {
    total_techniques: number;
    covered: number;
    partial: number;
    gaps: number;
    percentage: number;
  };
  generated_at: string;
}
```

### ═══════════════════════════════════════════
### CORRELATION TOOL 4: `ti_report_ingest`
### ═══════════════════════════════════════════

**Purpose:** Take a raw threat report URL from ANY source, extract ALL intelligence markers, and automatically correlate with existing knowledge.

**Input:**
```typescript
{
  type: 'object',
  properties: {
    url: { type: 'string', description: 'URL of any threat intelligence report' },
    auto_correlate: { type: 'boolean', description: 'Auto-correlate extracted TTPs with MCP data (default: true)' },
    auto_pivot_iocs: { type: 'boolean', description: 'Auto-pivot extracted IOCs through OTX/abuse.ch (default: false)' },
  },
  required: ['url'],
}
```

**Implementation:**
```typescript
async function ingestReport(url: string, autoCorrelate = true, autoPivot = false) {
  // 1. Fetch and parse the report
  const html = await fetchWithRetry(url);
  const bodyText = extractArticleBody(html);

  // 2. Extract ALL intelligence markers
  const markers = extractIntelMarkers(bodyText);

  // 3. Auto-correlate with MITRE ATT&CK
  let correlations = null;
  if (autoCorrelate && markers.techniques.length > 0) {
    correlations = await Promise.all(
      markers.techniques.map(t => multiSourceTTPLookup(t))
    );
  }

  // 4. Auto-pivot IOCs
  let iocEnrichment = null;
  if (autoPivot && markers.iocs.length > 0) {
    iocEnrichment = await pivotExpandIOCs(
      markers.iocs.map(i => ({ type: i.type, value: i.value }))
    );
  }

  // 5. Log to knowledge graph
  await addLearning({
    topic: 'report_ingestion',
    insight: `Ingested report: ${markers.title} — ${markers.techniques.length} TTPs, ${markers.iocs.length} IOCs, ${markers.actors.length} actors`,
    source: url,
    tags: [...markers.actors, ...markers.techniques],
  });

  return { markers, correlations, iocEnrichment };
}
```

### ═══════════════════════════════════════════
### CORRELATION TOOL 5: `ti_daily_brief`
### ═══════════════════════════════════════════

**Purpose:** Generate a daily threat intelligence brief by scanning recent reports from priority vendors and recent IOC feeds.

**Input:**
```typescript
{
  type: 'object',
  properties: {
    industries: {
      type: 'array',
      items: { type: 'string' },
      description: 'Client industries to filter relevance',
    },
    hours_lookback: { type: 'number', description: 'How many hours to look back (default: 24)' },
    vendors: {
      type: 'array',
      items: { type: 'string' },
      description: 'Specific vendors to check (default: top 6)',
    },
  },
}
```

---

## SHARED UTILITIES TO BUILD

### A. RSS Parser

```typescript
// Used by ALL vendor/government/research tools
interface RSSItem {
  title: string;
  link: string;
  pubDate: string;
  description: string;
  categories: string[];
  content: string;           // Full content if available (content:encoded)
}

function parseRSS(xml: string): RSSItem[] {
  // Parse both RSS 2.0 and Atom feeds
  // Handle CDATA sections
  // Normalize dates to ISO-8601
  // Strip HTML from descriptions
}
```

### B. HTML Article Extractor

```typescript
// Extracts main article body from HTML, stripping navigation, headers, footers, ads
function extractArticleBody(html: string): string {
  // Strategy:
  // 1. Look for <article> tag
  // 2. Fallback to largest <div> with most <p> children
  // 3. Strip all HTML tags, normalize whitespace
  // 4. Remove boilerplate (cookie notices, share buttons text, etc.)
}
```

### C. Intel Marker Extractor

```typescript
// THE CORE EXTRACTION ENGINE — used everywhere
interface IntelMarkers {
  techniques: string[];      // MITRE T-IDs
  cves: string[];
  actors: string[];
  malware: string[];
  tools: string[];           // Cobalt Strike, Mimikatz, etc.
  iocs: Array<{ type: string; value: string }>;
  industries: string[];      // Mentioned target industries
  regions: string[];         // Mentioned target regions
}

function extractIntelMarkers(text: string): IntelMarkers {
  // 1. Regex extraction for structured patterns (T-IDs, CVEs, IOCs)
  // 2. Keyword matching for actors (against MITRE group names + aliases)
  // 3. Keyword matching for malware (against known families)
  // 4. Keyword matching for tools (against LOLBAS + common tools list)
  // 5. IOC extraction + defanging
  // 6. Industry/region keyword matching
}

// Actor name list for matching (build from MITRE data)
const KNOWN_ACTORS = [
  'APT28', 'APT29', 'APT38', 'APT41', 'Lazarus', 'Lazarus Group',
  'FIN7', 'FIN11', 'MuddyWater', 'Turla', 'Sandworm',
  'Volt Typhoon', 'Midnight Blizzard', 'Scattered Spider',
  // ... populate from mitre_groups table at startup
];

// Known malware families for matching
const KNOWN_MALWARE = [
  'Cobalt Strike', 'Mimikatz', 'Emotet', 'QakBot', 'TrickBot',
  'IcedID', 'BumbleBee', 'SystemBC', 'Sliver', 'Brute Ratel',
  // ... populate from mitre_software table at startup
];
```

### D. Confidence Scorer

```typescript
function scoreConfidence(result: any): 'high' | 'medium' | 'low' {
  let score = 0;

  // Source reliability
  if (result.sources_consulted?.length >= 3) score += 3;
  if (result.mitre_confirmed) score += 2;
  if (result.vendor_count >= 2) score += 2;
  if (result.ioc_count > 0) score += 1;
  if (result.cve_confirmed) score += 1;

  if (score >= 6) return 'high';
  if (score >= 3) return 'medium';
  return 'low';
}
```

---

## SELF-TESTING & VALIDATION FRAMEWORK

### Test Contract 1: Tool Registration

```typescript
// Every tool module MUST export:
// 1. An array of ToolDefinition[]
// 2. A count number
// 3. Each tool must have: name, description, inputSchema, handler

test('all vendor tools register correctly', () => {
  for (const tool of vendorTools) {
    expect(tool.name).toMatch(/^[a-z_]+$/);        // snake_case
    expect(tool.description).toBeTruthy();
    expect(tool.inputSchema.type).toBe('object');
    expect(typeof tool.handler).toBe('function');
  }
});
```

### Test Contract 2: Response Envelope

```typescript
// Every threat intel tool MUST return IntelResult<T>
test('all tools return IntelResult envelope', async () => {
  const result = await tool.handler({ query: 'test' });
  expect(result).toHaveProperty('source');
  expect(result).toHaveProperty('success');
  expect(result).toHaveProperty('queried_at');
  expect(typeof result.success).toBe('boolean');
  if (!result.success) {
    expect(result).toHaveProperty('error');
  }
});
```

### Test Contract 3: Extraction Accuracy

```typescript
// Intel marker extraction must be accurate
test('extractIntelMarkers finds T-IDs', () => {
  const text = 'The actor used T1059.001 (PowerShell) and T1053.005 for persistence';
  const markers = extractIntelMarkers(text);
  expect(markers.techniques).toContain('T1059.001');
  expect(markers.techniques).toContain('T1053.005');
});

test('extractIntelMarkers finds CVEs', () => {
  const text = 'Exploiting CVE-2024-3400 in Palo Alto GlobalProtect';
  const markers = extractIntelMarkers(text);
  expect(markers.cves).toContain('CVE-2024-3400');
});

test('extractIntelMarkers handles defanged IOCs', () => {
  const text = 'C2 at 192[.]168[.]1[.]1 and hxxps://evil[.]com/payload';
  const markers = extractIntelMarkers(text);
  expect(markers.iocs).toContainEqual({ type: 'ip', value: '192.168.1.1' });
  expect(markers.iocs).toContainEqual({ type: 'url', value: 'https://evil.com/payload' });
});
```

### Test Contract 4: Error Resilience

```typescript
// Tools MUST NOT throw — always return structured errors
test('tool handles network failure gracefully', async () => {
  // Mock fetch to reject
  const result = await tool.handler({ query: 'test' });
  expect(result.success).toBe(false);
  expect(result.error).toBeTruthy();
  expect(result.data).toBeNull();
});
```

### Test Contract 5: Caching

```typescript
// Verify caching works and respects TTLs
test('vendor search results are cached', async () => {
  const r1 = await tool.handler({ query: 'APT29' });
  const r2 = await tool.handler({ query: 'APT29' });
  // Second call should be faster (cached)
  expect(r2.queried_at).toBe(r1.queried_at); // Same timestamp = cache hit
});
```

### Test Contract 6: Correlation Integrity

```typescript
// Correlation tools must produce valid fused output
test('ti_multi_source_ttp_lookup produces fused result', async () => {
  const result = await multiSourceTTPLookup('T1059.001');
  expect(result.technique.id).toBe('T1059.001');
  expect(result.actors_using.length).toBeGreaterThan(0);
  expect(result.detection_coverage).toHaveProperty('total_rules');
  expect(result.sources_consulted.length).toBeGreaterThan(1);
  expect(result.confidence).toMatch(/high|medium|low/);
});
```

---

## ENVIRONMENT VARIABLES TO ADD

```bash
# Add to Claude Desktop config or .env
# All optional — tools degrade gracefully without keys

# Existing
OTX_API_KEY=<key>

# New (optional — most vendors don't need keys for public blogs)
NVD_API_KEY=<key>           # Higher rate limits on NVD
MALPEDIA_API_KEY=<key>      # Required for Malpedia API
RECORDED_FUTURE_KEY=<key>   # If available
GROUP_IB_KEY=<key>          # If available
```

---

## IMPLEMENTATION ORDER (RECOMMENDED)

Build in this sequence for fastest time-to-value:

```
PHASE 1 — Foundation (Build First)
  ├── src/tools/threat-intel/vendors/types.ts         (shared types)
  ├── RSS parser utility
  ├── HTML article extractor utility
  ├── Intel marker extractor utility
  └── Confidence scorer utility

PHASE 2 — High-Value Vendors (Immediate ROI)
  ├── mandiant.ts
  ├── microsoft.ts
  ├── crowdstrike.ts
  ├── elastic.ts
  ├── unit42.ts
  └── kaspersky.ts

PHASE 3 — Government Sources
  ├── cisa-alerts.ts
  ├── ncsc-uk.ts
  └── Joint advisory search tool

PHASE 4 — Research Sources
  ├── dfir-report.ts
  ├── red-canary.ts
  ├── volexity.ts
  └── huntress.ts

PHASE 5 — Correlation Engine (The Brain)
  ├── ti_multi_source_ttp_lookup
  ├── ti_actor_full_profile
  ├── ti_hunt_package
  ├── ti_report_ingest
  └── ti_daily_brief

PHASE 6 — Exploit Intelligence
  ├── epss.ts
  ├── nvd_cve_lookup
  └── Vulnerability research tools

PHASE 7 — Community & Feeds
  ├── malpedia.ts
  ├── sans-isc.ts
  ├── bleepingcomputer.ts
  └── Remaining sources

PHASE 8 — Registration & Testing
  ├── Update src/tools/threat-intel/index.ts
  ├── Update src/tools/index.ts
  ├── Run full test suite
  └── Verify all tools appear in MCP tool listing
```

---

## CRITICAL RULES FOR CODE GENERATION

1. **NEVER create a new MCP server.** You are adding tools to the existing Harris HawkEye server.
2. **ALWAYS use `defineTool()` from `../registry.js`** — do not create your own tool registration.
3. **ALWAYS return `IntelResult<T>`** — every tool must follow the response envelope.
4. **ALWAYS cache results** using `withCache()` from `./cache.js`.
5. **NEVER throw exceptions** — always catch and return `makeErr()`.
6. **ALWAYS extract intel markers** (T-IDs, CVEs, IOCs) from fetched content.
7. **ALWAYS generate `pivot_suggestions`** — every result should suggest the next logical analysis step.
8. **ALWAYS use TypeScript strict mode** — no `any` types unless absolutely necessary.
9. **ALWAYS handle rate limits** — implement backoff for 429 responses.
10. **ALWAYS filter false positive IOCs** — exclude common domains, private IPs, example IPs.
11. **Build vendor tools as a FACTORY** — use `createVendorSearchTool(config)` and `createVendorFetchTool(config)` to avoid code duplication across 18+ vendors.
12. **Populate actor/malware name lists at startup** from the MITRE database tables — do not hardcode.

---

## FINAL VALIDATION CHECKLIST

Before considering any tool complete, verify:

```
□ Tool registers in MCP tool listing
□ Tool returns IntelResult<T> envelope
□ Tool caches successful results
□ Tool handles network errors gracefully (returns makeErr, never throws)
□ Tool extracts intel markers from text content
□ Tool generates meaningful pivot_suggestions
□ Tool has correct inputSchema with descriptions
□ Tool name follows snake_case convention with source prefix
□ Tool description is operationally useful (not generic)
□ Correlation tools fan out to 2+ sources minimum
□ All TypeScript compiles with strict mode
□ npm run build succeeds
□ npm run test passes
□ Tool appears in Claude Desktop when MCP server starts
```

---

*This prompt produces 50+ new MCP tools across 7 tiers plus a 5-tool correlation engine that fuses intelligence from 70+ sources into actionable, detection-ready output.*
