# Implementation Plan: Bundle Playwright + Prepare for Public npm Distribution

## Overview
Bundle Playwright into Harris HawkEye MCP as 3 security-focused web research tools, refactor for public distribution via npm, and handle database/rules distribution cleanly.

---

## Phase A: Foundation — Centralized Path Resolution (3 files)

### A1. Create `src/paths.ts`
- Centralized path resolution for DB, rules, MITRE STIX bundle
- Default data directory: `~/.harris-hawkeye/`
- Respects env vars: `HHE_DATA_DIR`, `DETECTIONS_DB_PATH`, `HHE_RULES_DIR`
- Auto-creates directories if missing

### A2. Refactor `src/db/connection.ts`
- Replace internal `getDbPath()` with import from `src/paths.ts`
- DB defaults to `~/.harris-hawkeye/detections.db` instead of OS temp dir

### A3. Refactor `src/index.ts`
- Export `main()` function instead of calling it immediately at module load
- Replace hardcoded STIX path (`rules/elastic/...`) with `paths.getMitreStixPath()`
- Keep all existing auto-indexing logic intact

---

## Phase B: Playwright Integration — 3 New Tools (6 files)

### B1. Create `src/tools/threat-intel/web/types.ts`
- `WebSearchResult` — query, engine, results array (title, url, snippet)
- `WebReadResult` — url, title, clean text, intel_markers
- `WebExtractResult` — url, extracted_intelligence, confidence, pivot_suggestions

### B2. Create `src/tools/threat-intel/web/browser.ts`
- Lazy singleton: browser launches on first `web_*` tool call, not at startup
- Dynamic `import('playwright-chromium')` — server starts fine without Playwright installed
- Auto-cleanup: 5-minute idle timeout closes browser to save memory
- SIGINT/SIGTERM cleanup handler
- `getBrowser()`, `createContext()`, `closeBrowser()` exports

### B3. Create `src/tools/threat-intel/web/web-search.ts`
- Tool: `web_search`
- DuckDuckGo HTML search (no API key needed)
- Inputs: `query` (string), `max_results` (number, default 10, max 20)
- Returns: URLs + titles + snippets
- Cached 30 minutes
- Fallback extraction if DDG DOM selectors change

### B4. Create `src/tools/threat-intel/web/web-read.ts`
- Tool: `web_read`
- Navigate to URL, wait for JS render, extract clean text
- Reuses existing `extractArticleBody()` from `vendors/utils.ts`
- Reuses existing `extractIntelMarkers()` for auto-detection of TTPs/IOCs
- Cached 4 hours (same as vendor blog TTL)
- 60k char text cap

### B5. Create `src/tools/threat-intel/web/web-extract.ts`
- Tool: `web_extract_intel`
- Navigate + extract structured threat intelligence
- Returns: techniques with context, CVEs, actors, malware, tools, IOCs
- Confidence scoring via existing `scoreVendorConfidence()`
- Pivot suggestions for chained analysis
- Replaces the broken `ti_report_ingest` for most use cases

### B6. Create `src/tools/threat-intel/web/index.ts`
- Aggregator: exports `webTools` array + `webToolCount`

---

## Phase C: Tool Registration (2 files)

### C1. Edit `src/tools/threat-intel/index.ts`
- Import `webTools` from `./web/index.js`
- Spread into `threatIntelTools` array
- Update `threatIntelToolCount`

### C2. Edit `src/tools/index.ts`
- Add web tool count to `registerAllTools()` log output
- Add to `getToolsSummary()` byModule

---

## Phase D: CLI Entry Point (2 files)

### D1. Create `src/cli.ts`
- New entry point with argument parsing (Node.js `util.parseArgs`)
- Subcommands:
  - `--init` — full first-run setup (clone rules, install browser, build DB)
  - `--install-browser` — install Playwright Chromium only
  - `--index` — re-index detection rules
  - `--status` — print DB stats, browser status, rule counts
  - `--version` / `-v` — print version
  - `--help` / `-h` — print usage
- Default (no args): start MCP server via existing `main()`

### D2. Create `src/postinstall.ts`
- Runs after `npm install`
- Prints setup instructions: "Run `harris-hawkeye --init` to complete setup"
- Never fails (wrapped in try/catch)

---

## Phase E: Distribution Prep (4 files)

### E1. Update `package.json`
- Version bump to `2.0.0`
- `bin` → `dist/cli.js` (new entry point)
- Add `optionalDependencies: { "playwright-chromium": "^1.50.0" }`
- Update `files`: `["dist", "data/attack-v18.1.0.json.gz", "README.md", "LICENSE"]`
- Add `postinstall` script

### E2. Update `.gitignore`
- Add `playwright-browsers/`, `.harris-hawkeye/`

### E3. Rewrite `README.md`
- Remove all hardcoded personal paths
- Add npm install instructions
- Add `--init` workflow documentation
- Add Claude Desktop config snippet
- Add tool reference for new `web_*` tools

### E4. Add `LICENSE` file
- Apache-2.0 (matches current package.json)

---

## Phase F: Build & Test

### F1. Build and verify
- `npm run build` — compile all new TypeScript
- Verify no import errors

### F2. Test new tools
- Test `web_search` with a sample query
- Test `web_read` on a known URL
- Test `web_extract_intel` on a CISA advisory
- Test CLI flags (`--help`, `--version`, `--status`)

### F3. Package verification
- `npm pack` — verify package contents are under 10MB
- Verify `bin` entry works: `npx . --help`

---

## File Summary

| # | Action | File |
|---|--------|------|
| 1 | CREATE | `src/paths.ts` |
| 2 | EDIT | `src/db/connection.ts` |
| 3 | EDIT | `src/index.ts` |
| 4 | CREATE | `src/tools/threat-intel/web/types.ts` |
| 5 | CREATE | `src/tools/threat-intel/web/browser.ts` |
| 6 | CREATE | `src/tools/threat-intel/web/web-search.ts` |
| 7 | CREATE | `src/tools/threat-intel/web/web-read.ts` |
| 8 | CREATE | `src/tools/threat-intel/web/web-extract.ts` |
| 9 | CREATE | `src/tools/threat-intel/web/index.ts` |
| 10 | EDIT | `src/tools/threat-intel/index.ts` |
| 11 | EDIT | `src/tools/index.ts` |
| 12 | CREATE | `src/cli.ts` |
| 13 | CREATE | `src/postinstall.ts` |
| 14 | EDIT | `package.json` |
| 15 | EDIT | `.gitignore` |
| 16 | REWRITE | `README.md` |
| 17 | CREATE | `LICENSE` |

**New files:** 9 | **Edited files:** 6 | **Rewritten files:** 2

---

## Key Design Decisions

1. **`playwright-chromium` in `optionalDependencies`** — server starts without it, only `web_*` tools fail gracefully
2. **Lazy browser singleton** — no startup cost, 5-min idle timeout
3. **Dynamic import** — `import('playwright-chromium')` only when web tools are called
4. **Database NOT shipped in npm** — built on first run via `--init`, or users bring their own
5. **MITRE STIX bundle shipped** — ~4MB compressed, always available
6. **`~/.harris-hawkeye/`** — XDG-style user data directory, no temp dir
7. **Single `bin` entry** — `harris-hawkeye` command handles both CLI and MCP server

---
---

# Efficient Analysis Tools — Implementation Plan

## Goal
Add token-optimized analysis tools to the MCP. Fix existing broken tools first, then add 5 new lightweight tools.

## Strategy: Fix First, Then Extend

**Why this order:** If we add new lightweight tools BEFORE fixing the data quality bugs, the new tools inherit the same garbage data. The `analyze_coverage` bug proves that `mitre_tactics` and `mitre_techniques` columns contain inconsistent formats. Fix parsing first, then build on clean data.

**Order: Phase A (fix bugs) → Phase B (fix perf) → Phase C (add tools) → Phase D (register) → Phase E (docs)**

---

## Phase A: Fix `analyze_coverage` Data Quality Bug

**File:** `src/tools/detections/index.ts` — lines 244-282

**Root Cause (confirmed from live `analyze_coverage()` output):**

The `mitre_tactics` column stores data in 3+ inconsistent formats across source types:
- Sigma: `["discovery", "execution"]` — valid JSON array
- KQL: `["InitialAccess", "CommandAndControl"]` — valid JSON, PascalCase
- Splunk ESCU: `"Command And Control"` — plain string, NOT a JSON array
- Some KQL: `"Persistence"` — plain string, NOT a JSON array

When code does `JSON.parse("Persistence")`, it returns the string `"Persistence"`. Then `for (const t of "Persistence")` iterates **characters**: `P`, `e`, `r`, `s`, `i`, `s`, `t`, `e`, `n`, `c`, `e`.

Same for `mitre_techniques`: rows storing `"T1059"` instead of `["T1059"]` produce `"T"`, `"1"`, `"0"`, `"5"`, `"9"`.

**Fix — Add 3 helper functions near top of file (after imports):**

```typescript
/** Safely parse JSON that might be an array OR a bare string */
function safeParseArray(jsonStr: string | null): string[] {
  if (!jsonStr) return [];
  try {
    const parsed = JSON.parse(jsonStr);
    if (Array.isArray(parsed)) return parsed;
    if (typeof parsed === 'string') return [parsed];
    return [];
  } catch {
    return jsonStr.trim() ? [jsonStr.trim()] : [];
  }
}

/** Normalize tactic names across inconsistent casing/format */
function normalizeTactic(raw: string): string {
  return raw
    .replace(/([a-z])([A-Z])/g, '$1 $2')  // Split PascalCase
    .replace(/_/g, ' ')                     // Split underscores
    .toLowerCase()
    .trim();
}

/** Validate technique ID format */
function isValidTechniqueId(id: string): boolean {
  return /^T\d{4}(\.\d{3})?$/.test(id);
}
```

**Fix — Replace the parsing loop in `analyzeCoverage` handler (lines 261-270):**

OLD:
```typescript
for (const t of techniques) {
  techniqueCounts[t] = (techniqueCounts[t] || 0) + 1;
}
for (const t of tactics) {
  tacticCounts[t] = (tacticCounts[t] || 0) + 1;
}
```

NEW:
```typescript
for (const row of results) {
  const techniques = safeParseArray(row.mitre_techniques);
  const tactics = safeParseArray(row.mitre_tactics);

  for (const t of techniques) {
    if (isValidTechniqueId(t)) {
      techniqueCounts[t] = (techniqueCounts[t] || 0) + 1;
    }
  }
  for (const t of tactics) {
    const normalized = normalizeTactic(t);
    if (normalized.length > 2) {
      tacticCounts[normalized] = (tacticCounts[normalized] || 0) + 1;
    }
  }
}
```

**Expected result:** Clean `tactic_coverage` with ~12 canonical tactic names (no `"C"`, `"o"`, `"m"` single-char garbage). Clean `top_techniques` with only valid T-IDs (no `"1"`, `"2"`, `"T"`).

---

## Phase B: Fix `identify_gaps` Performance

**File:** `src/tools/detections/index.ts` — lines 286-343

**Current:** Runs 6-8 separate `SELECT COUNT(*)` queries in a loop. 8 SQL round-trips.

**Fix — Replace the loop (lines 323-333) with single-query approach:**

```typescript
const allDetections = runQuery<{ mitre_techniques: string }>(
  'SELECT mitre_techniques FROM detections WHERE mitre_techniques IS NOT NULL'
);

const coverage: Record<string, number> = {};
for (const technique of targetTechniques) {
  coverage[technique] = 0;
}

for (const row of allDetections) {
  const techniques = safeParseArray(row.mitre_techniques);
  for (const t of techniques) {
    for (const target of targetTechniques) {
      if (t === target || t.startsWith(target + '.')) {
        coverage[target]++;
      }
    }
  }
}
```

**Benefit:** 1 query instead of 8. Also correctly counts sub-techniques.

---

## Phase C: Add 5 New Lightweight Tools

All in `src/tools/detections/index.ts`, following the exact `defineTool` pattern.

### C1: `get_technique_count` (~50 bytes output)

**Purpose:** Get just the detection count for one technique.
**Saves:** `list_by_mitre(T1059.001, limit=50)` returns 50 full objects (~5KB). This returns `{technique_id: "T1059.001", count: 243}` (50 bytes). **100x saving.**

```typescript
const getTechniqueCount = defineTool({
  name: 'get_technique_count',
  description: 'Just the count for one technique (~50 bytes)',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., T1059)' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id } = args as { technique_id: string };
    const result = runQuery<{ count: number }>(
      'SELECT COUNT(*) as count FROM detections WHERE mitre_techniques LIKE ?',
      [`%${technique_id.toUpperCase()}%`]
    );
    return { technique_id, count: result[0]?.count || 0 };
  },
});
```

### C2: `get_coverage_summary` (~200 bytes output)

**Purpose:** Just tactic coverage percentages.
**Saves:** `analyze_coverage` returns 3KB+ of dirty data. This returns ~12 clean tactic percentages. **15x saving.**

```typescript
const getCoverageSummary = defineTool({
  name: 'get_coverage_summary',
  description: 'Get tactic coverage percentages only (~200 bytes). Lightweight alternative to analyze_coverage.',
  inputSchema: {
    type: 'object',
    properties: {
      source: { type: 'string', description: 'Optional: filter by source type (sigma, splunk_escu, elastic, kql)' },
    },
  },
  handler: async (args) => {
    const { source } = args as { source?: string };
    let sql = 'SELECT mitre_tactics FROM detections WHERE mitre_tactics IS NOT NULL';
    const params: unknown[] = [];
    if (source) { sql += ' AND source_type = ?'; params.push(source); }

    const results = runQuery<{ mitre_tactics: string }>(sql, params);
    const tacticCounts: Record<string, number> = {};
    let total = 0;

    for (const row of results) {
      for (const t of safeParseArray(row.mitre_tactics)) {
        const norm = normalizeTactic(t);
        if (norm.length > 2) { tacticCounts[norm] = (tacticCounts[norm] || 0) + 1; total++; }
      }
    }

    const summary: Record<string, string> = {};
    for (const [tactic, count] of Object.entries(tacticCounts).sort((a, b) => b[1] - a[1])) {
      summary[tactic] = Math.round((count / total) * 100) + '%';
    }
    return summary;
  },
});
```

### C3: `get_technique_ids` (~200 bytes output)

**Purpose:** Get only technique IDs matching filters (no full detection objects).
**Saves:** `list_by_mitre_tactic` / `list_by_severity` return full objects. This returns just T-IDs. **25x saving.**

```typescript
const getTechniqueIds = defineTool({
  name: 'get_technique_ids',
  description: 'Get only technique IDs matching filters (no full objects, ~200 bytes). Use for fast enumeration.',
  inputSchema: {
    type: 'object',
    properties: {
      source: { type: 'string', description: 'Filter by source: sigma, splunk_escu, elastic, kql' },
      tactic: { type: 'string', description: 'Filter by tactic: execution, persistence, etc.' },
      severity: { type: 'string', description: 'Filter by severity: critical, high, medium, low' },
    },
  },
  handler: async (args) => {
    const { source, tactic, severity } = args as { source?: string; tactic?: string; severity?: string };
    let sql = 'SELECT mitre_techniques FROM detections WHERE mitre_techniques IS NOT NULL';
    const params: unknown[] = [];
    if (source) { sql += ' AND source_type = ?'; params.push(source); }
    if (severity) { sql += ' AND LOWER(severity) = ?'; params.push(severity.toLowerCase()); }
    if (tactic) { sql += ' AND LOWER(mitre_tactics) LIKE ?'; params.push('%' + tactic.toLowerCase() + '%'); }

    const results = runQuery<{ mitre_techniques: string }>(sql, params);
    const ids = new Set<string>();
    for (const row of results) {
      for (const t of safeParseArray(row.mitre_techniques)) {
        if (isValidTechniqueId(t)) ids.add(t);
      }
    }
    return { count: ids.size, technique_ids: Array.from(ids).sort() };
  },
});
```

### C4: `get_top_gaps` (~300 bytes output)

**Purpose:** Top 5 gap technique IDs for a threat profile.
**Saves:** `identify_gaps` returns full structure with all techniques. This returns just the top 5 weakest. **5x saving.**

```typescript
const getTopGaps = defineTool({
  name: 'get_top_gaps',
  description: 'Get top 5 gap technique IDs for a threat profile (~300 bytes). Lightweight alternative to identify_gaps.',
  inputSchema: {
    type: 'object',
    properties: {
      profile: { type: 'string', description: 'Threat profile: ransomware, apt, initial-access, persistence, credential-access, defense-evasion' },
    },
    required: ['profile'],
  },
  handler: async (args) => {
    const { profile } = args as { profile: string };
    const profileTechniques: Record<string, string[]> = {
      'ransomware': ['T1486', 'T1490', 'T1489', 'T1083', 'T1082', 'T1059', 'T1047', 'T1021'],
      'apt': ['T1566', 'T1059', 'T1053', 'T1547', 'T1055', 'T1003', 'T1021', 'T1041'],
      'initial-access': ['T1566', 'T1190', 'T1133', 'T1078', 'T1195', 'T1189'],
      'persistence': ['T1547', 'T1053', 'T1136', 'T1543', 'T1574', 'T1546'],
      'credential-access': ['T1003', 'T1558', 'T1552', 'T1555', 'T1110', 'T1557'],
      'defense-evasion': ['T1055', 'T1027', 'T1070', 'T1562', 'T1036', 'T1218'],
    };
    const targets = profileTechniques[profile.toLowerCase()];
    if (!targets) return { error: 'Unknown profile. Available: ' + Object.keys(profileTechniques).join(', ') };

    const allDet = runQuery<{ mitre_techniques: string }>(
      'SELECT mitre_techniques FROM detections WHERE mitre_techniques IS NOT NULL'
    );
    const counts: Record<string, number> = {};
    for (const t of targets) counts[t] = 0;
    for (const row of allDet) {
      for (const t of safeParseArray(row.mitre_techniques)) {
        for (const target of targets) {
          if (t === target || t.startsWith(target + '.')) counts[target]++;
        }
      }
    }
    const sorted = Object.entries(counts).sort((a, b) => a[1] - b[1]).slice(0, 5);
    return { profile, top_gaps: sorted.map(([tid, count]) => ({ technique_id: tid, detection_count: count })) };
  },
});
```

### C5: `suggest_detections` (~2KB output)

**Purpose:** Detection suggestions for a technique — rule counts, log sources, processes, coverage status. One call replaces 4+ chained calls.
**Saves:** Currently need `list_by_mitre` + `get_detection` × N + `lookup_mitre_technique` + `get_data_sources` = 4+ calls, ~20KB+. This returns a **2KB summary in one call. 10x saving.**

```typescript
const suggestDetections = defineTool({
  name: 'suggest_detections',
  description: 'Get detection suggestions for a technique — existing rules summary, logsource requirements, and coverage status (~2KB). Saves 4+ tool calls.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., T1059.001)' },
      source: { type: 'string', description: 'Optional: filter by source type' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id, source } = args as { technique_id: string; source?: string };
    const tid = technique_id.toUpperCase();
    let sql = `SELECT source_type, severity, logsource_category, logsource_product,
               name, process_names, data_sources
               FROM detections WHERE mitre_techniques LIKE ?`;
    const params: unknown[] = ['%' + tid + '%'];
    if (source) { sql += ' AND source_type = ?'; params.push(source); }

    const results = runQuery<{
      source_type: string; severity: string; logsource_category: string;
      logsource_product: string; name: string; process_names: string; data_sources: string;
    }>(sql, params);

    const bySeverity: Record<string, number> = {};
    const bySource: Record<string, number> = {};
    const logsources = new Set<string>();
    const processes = new Set<string>();
    const dataSources = new Set<string>();
    const topRules: string[] = [];

    for (const r of results) {
      bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1;
      bySource[r.source_type] = (bySource[r.source_type] || 0) + 1;
      if (r.logsource_category) logsources.add(r.logsource_category);
      if (r.logsource_product) logsources.add(r.logsource_product);
      for (const p of safeParseArray(r.process_names)) processes.add(p);
      for (const d of safeParseArray(r.data_sources)) dataSources.add(d);
      if (topRules.length < 5) topRules.push(r.name);
    }

    return {
      technique_id: tid,
      total_rules: results.length,
      coverage_status: results.length === 0 ? 'NO_RULES' : results.length < 3 ? 'LOW' : results.length < 10 ? 'MODERATE' : 'GOOD',
      by_severity: bySeverity,
      by_source: bySource,
      log_sources_needed: Array.from(logsources),
      processes_monitored: Array.from(processes),
      data_sources: Array.from(dataSources),
      sample_rules: topRules,
    };
  },
});
```

---

## Phase D: Export & Register

Add all 5 tools to the export array at line ~618:

```typescript
export const detectionTools: ToolDefinition[] = [
  searchDetections,
  getDetection,
  listByMitre,
  listBySeverity,
  getStats,
  analyzeCoverage,
  identifyGaps,
  cveToDetection,
  yaraToSigma,
  sigmaToKQL,
  listByProcessName,
  listByCve,
  listByLogsource,
  listByDataSource,
  listByMitreTactic,
  // --- Efficient Analysis Tools (token-optimized) ---
  getTechniqueCount,
  getCoverageSummary,
  getTechniqueIds,
  getTopGaps,
  suggestDetections,
];
```

---

## Phase E: Update CLAUDE.md

Add to Tier 1 tools:

```
**Efficient Analysis (token-optimized):** get_technique_count, get_coverage_summary, get_technique_ids, get_top_gaps, suggest_detections — *always prefer these over full-object tools when you only need counts, IDs, or summaries*
```

Add to ANTI-PATTERNS:

```
- Use `list_by_mitre` when you only need a count — use `get_technique_count` instead (50B vs 5KB+)
- Use `analyze_coverage` when you only need tactic percentages — use `get_coverage_summary` instead (200B vs 3KB)
```

---

## Token Savings Summary

| Task | Old Way | New Way | Savings |
|------|---------|---------|---------|
| "How many rules for T1059?" | `list_by_mitre(T1059)` → 5KB+ | `get_technique_count(T1059)` → 50B | **100x** |
| "Which tactics are weakest?" | `analyze_coverage()` → 3KB dirty | `get_coverage_summary()` → 200B clean | **15x** |
| "List all techniques for execution" | `list_by_mitre_tactic(execution)` → 10KB+ | `get_technique_ids(tactic=execution)` → 200B | **50x** |
| "Top gaps for ransomware?" | `identify_gaps(ransomware)` → 500B full | `get_top_gaps(ransomware)` → 300B top-5 | **2x** |
| "What detections exist for T1547.009?" | 4+ tool calls → 20KB+ | `suggest_detections(T1547.009)` → 2KB | **10x** |

---

## Files Changed

| File | Action | Changes |
|------|--------|---------|
| `src/tools/detections/index.ts` | EDIT | Add 3 helpers, fix 2 handlers, add 5 tools, update exports |
| `CLAUDE.md` | EDIT | Add Efficient Analysis tier, update anti-patterns |

**No other files touched. No schema changes. No new dependencies.**

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| `safeParseArray` changes `analyze_coverage` output | Same shape, just cleaned values. Not a breaking change. |
| Tactic normalization merges duplicate keys | Intentional — "Persistence" and "persistence" ARE the same. |
| New tools increase tool count | Only 5 new. MCP handles 100+. |
| `identify_gaps` single query loads all rows | 11,814 rows × ~200B = ~2.3MB. sql.js handles this in memory. |
