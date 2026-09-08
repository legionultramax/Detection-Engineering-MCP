// Detection Tools - Search, filter, and analyze security detections
import { defineTool, ToolDefinition } from '../registry.js';
import { runQuery } from '../../db/connection.js';
import { cveToDetectionTool, handleCVEToDetection } from './cve-detection.js';
import { handleYARAToSigma } from './yara-to-sigma.js';
import { handleSigmaToKQL } from './sigma-to-kql.js';

interface Detection {
  id: string;
  name: string;
  description: string;
  source_type: string;
  severity: string;
  status: string;
  author: string;
  mitre_tactics: string;
  mitre_techniques: string;
  tags: string;
  query: string;
  logsource_product: string;
  logsource_category: string;
  logsource_service: string;
  data_sources: string;
  process_names: string;
  file_paths_found: string;
  registry_paths: string;
  platforms: string;
  cves: string;
  false_positives: string;
}

/**
 * Columns searched, and how much a hit in each is worth.
 *
 * The weights encode a simple claim: a match in a structured field is better
 * evidence than a match in free text. A rule whose *name* is "Mimikatz
 * Execution" is a better answer for "mimikatz" than one that happens to mention
 * it in a description, and a match on mitre_techniques for "T1059" is exact
 * rather than incidental. search_text is the catch-all concatenation, so it is
 * weighted lowest — almost everything matches it.
 */
const SEARCH_COLUMNS: Array<{ column: string; weight: number }> = [
  { column: 'name', weight: 100 },
  { column: 'mitre_techniques', weight: 80 },
  { column: 'cves', weight: 80 },
  { column: 'process_names', weight: 45 },
  { column: 'tags', weight: 40 },
  { column: 'analytic_stories', weight: 35 },
  { column: 'description', weight: 30 },
  { column: 'mitre_tactics', weight: 25 },
  { column: 'registry_paths', weight: 20 },
  { column: 'file_paths_found', weight: 20 },
  { column: 'data_sources', weight: 15 },
  { column: 'kql_keywords', weight: 15 },
  { column: 'kql_tags', weight: 15 },
  { column: 'kql_category', weight: 15 },
  { column: 'platforms', weight: 5 },
  { column: 'search_text', weight: 10 },
];

interface ScoredDetection extends Detection {
  score: number;
}

// Substring search with relevance ranking.
//
// Two things this deliberately is not. It is not FTS5 — the sql.js WASM build
// ships without it, and the previous description claimed otherwise, which meant
// a model was told it had full-text search when it had a LIKE scan. And it no
// longer sorts alphabetically: ORDER BY name returned the first 20 matches by
// name, so "mimikatz" surfaced whatever sorted earliest rather than whatever
// was most relevant.
//
// Multi-word queries were also broken. "%credential dumping lsass%" is a single
// substring and matches almost nothing, so any query longer than one word
// silently returned few or no results. Terms are now AND-ed independently and
// their scores summed, with a bonus when the full phrase appears intact.
const searchDetections = defineTool({
  name: 'search_detections',
  description:
    'Search detection rules by keyword across name, description, tags, MITRE techniques, CVEs, ' +
    'process names, registry paths, data sources and more. Multi-word queries match rules ' +
    'containing every term. Results are ranked by relevance — matches in the rule name, MITRE ' +
    'technique or CVE rank above matches in free-text description. Substring matching, so ' +
    '"powershell" matches "powershell.exe"; it is not stemmed or semantic, so synonyms and word ' +
    'variants do not match. Covers Sigma, Splunk ESCU, Elastic and KQL rules.',
  inputSchema: {
    type: 'object',
    properties: {
      query: {
        type: 'string',
        description:
          'Search terms. Multiple words are AND-ed: "lsass dump" returns rules mentioning both. ' +
          'Accepts technique IDs (T1003.001) and CVE IDs directly.',
      },
      source: { type: 'string', description: 'Filter by source: sigma, splunk_escu, elastic, kql' },
      severity: { type: 'string', description: 'Filter by severity: critical, high, medium, low' },
      limit: { type: 'number', description: 'Maximum results to return (default: 20)' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query, source, severity, limit = 20 } = args as {
      query: string; source?: string; severity?: string; limit?: number
    };

    const raw = String(query ?? '').trim();
    if (!raw) return { error: true, message: 'No search terms provided.' };

    // Terms of one or two characters match nearly every row and only add noise.
    const terms = raw.toLowerCase().split(/\s+/).filter(t => t.length > 2);
    const effectiveTerms = terms.length > 0 ? terms : [raw.toLowerCase()];
    const phrase = raw.toLowerCase();

    const scoreParts: string[] = [];
    const scoreParams: unknown[] = [];
    const whereClauses: string[] = [];
    const whereParams: unknown[] = [];

    for (const term of effectiveTerms) {
      const like = `%${term}%`;
      // Score: every column hit contributes its weight, per term.
      for (const { column, weight } of SEARCH_COLUMNS) {
        scoreParts.push(`(CASE WHEN lower(COALESCE(${column}, '')) LIKE ? THEN ${weight} ELSE 0 END)`);
        scoreParams.push(like);
      }
      // An exact name match is a different kind of answer from a substring hit.
      scoreParts.push(`(CASE WHEN lower(COALESCE(name, '')) = ? THEN 500 ELSE 0 END)`);
      scoreParams.push(term);
      scoreParts.push(`(CASE WHEN lower(COALESCE(name, '')) LIKE ? THEN 60 ELSE 0 END)`);
      scoreParams.push(`${term}%`);

      // Every term must appear somewhere, or the row is not a match at all.
      const cols = SEARCH_COLUMNS.map(c => `lower(COALESCE(${c.column}, '')) LIKE ?`).join(' OR ');
      whereClauses.push(`(${cols})`);
      for (const _ of SEARCH_COLUMNS) whereParams.push(like);
    }

    // Reward the intact phrase, so "lateral movement" outranks a rule that
    // merely mentions both words in unrelated places.
    if (effectiveTerms.length > 1) {
      scoreParts.push(`(CASE WHEN lower(COALESCE(name, '')) LIKE ? THEN 250 ELSE 0 END)`);
      scoreParams.push(`%${phrase}%`);
      scoreParts.push(`(CASE WHEN lower(COALESCE(search_text, '')) LIKE ? THEN 80 ELSE 0 END)`);
      scoreParams.push(`%${phrase}%`);
    }

    let sql =
      `SELECT id, name, description, source_type, severity, mitre_techniques,
              (${scoreParts.join(' + ')}) AS score
       FROM detections
       WHERE ${whereClauses.join(' AND ')}`;
    const params: unknown[] = [...scoreParams, ...whereParams];

    if (source) { sql += ' AND source_type = ?'; params.push(source); }
    if (severity) { sql += ' AND severity = ?'; params.push(severity); }

    // Severity breaks ties so that, among equally relevant rules, the more
    // serious one is offered first.
    sql += `
       ORDER BY score DESC,
                CASE lower(COALESCE(severity, ''))
                  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                  WHEN 'low' THEN 3 ELSE 4 END,
                name
       LIMIT ?`;
    params.push(limit);

    const results = runQuery<ScoredDetection>(sql, params);

    return {
      count: results.length,
      query: raw,
      terms: effectiveTerms,
      ranking: 'Relevance-scored substring match. Name, MITRE technique and CVE hits outrank ' +
        'description hits. Not full-text search: no stemming, no synonyms.',
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        description: d.description?.substring(0, 200),
        source: d.source_type,
        severity: d.severity,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
        score: d.score,
      })),
    };
  },
});

// Get detection by ID — returns all enriched fields for elite rule selection
const getDetection = defineTool({
  name: 'get_detection',
  description: 'Get full details of a specific detection by ID. Returns query logic, logsource (product/category/service), data_sources, process_names, platforms, CVEs, and false_positives. Use this to extract detection conditions for kill-chain correlation.',
  inputSchema: {
    type: 'object',
    properties: {
      id: { type: 'string', description: 'Detection ID' },
    },
    required: ['id'],
  },
  handler: async (args) => {
    const { id } = args as { id: string };
    const results = runQuery<Detection>('SELECT * FROM detections WHERE id = ?', [id]);

    if (results.length === 0) {
      return { error: 'Detection not found' };
    }

    const d = results[0];
    const parseSafe = (v: string) => { try { return JSON.parse(v); } catch { return []; } };
    return {
      id: d.id,
      name: d.name,
      description: d.description,
      source: d.source_type,
      severity: d.severity,
      status: d.status,
      author: d.author,
      tactics: d.mitre_tactics ? parseSafe(d.mitre_tactics) : [],
      techniques: d.mitre_techniques ? parseSafe(d.mitre_techniques) : [],
      tags: d.tags ? parseSafe(d.tags) : [],
      // Logsource context — use to validate anchor field compatibility in kill-chain
      logsource: {
        product:  d.logsource_product  || null,
        category: d.logsource_category || null,
        service:  d.logsource_service  || null,
      },
      // Telemetry requirements — cross-check against environment before deploying
      data_sources:    d.data_sources    ? parseSafe(d.data_sources)    : [],
      // Artifact specificity — higher = more targeted rule (prefer non-empty for kill-chain phases)
      process_names:   d.process_names   ? parseSafe(d.process_names)   : [],
      file_paths:      d.file_paths_found ? parseSafe(d.file_paths_found) : [],
      registry_paths:  d.registry_paths  ? parseSafe(d.registry_paths)  : [],
      platforms:       d.platforms       ? parseSafe(d.platforms)       : [],
      cves:            d.cves            ? parseSafe(d.cves)            : [],
      false_positives: d.false_positives || null,
      query: d.query,
    };
  },
});

// List detections by MITRE technique — includes logsource + artifact fields for elite rule selection
const listByMitre = defineTool({
  name: 'list_by_mitre',
  description: 'List detections mapped to a MITRE ATT&CK technique ID. Returns logsource (product/category), data_sources, and process_names per rule — use these to rank candidates before calling get_detection. Rules with non-empty process_names are more artifact-specific than generic ones.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., T1059 or T1059.001)' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id, limit = 50 } = args as { technique_id: string; limit?: number };

    const results = runQuery<Detection>(
      `SELECT id, name, source_type, severity, mitre_techniques,
              logsource_product, logsource_category, data_sources, process_names, platforms
       FROM detections
       WHERE mitre_techniques LIKE ?
       ORDER BY severity DESC, name
       LIMIT ?`,
      [`%${technique_id.toUpperCase()}%`, limit]
    );

    const parseSafe = (v: string) => { try { return JSON.parse(v); } catch { return []; } };
    return {
      technique: technique_id,
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        severity: d.severity,
        logsource_product:  d.logsource_product  || null,
        logsource_category: d.logsource_category || null,
        data_sources: d.data_sources ? parseSafe(d.data_sources) : [],
        process_names: d.process_names ? parseSafe(d.process_names) : [],
        platforms: d.platforms ? parseSafe(d.platforms) : [],
      })),
    };
  },
});

// List detections by severity
const listBySeverity = defineTool({
  name: 'list_by_severity',
  description: 'List detections filtered by severity level',
  inputSchema: {
    type: 'object',
    properties: {
      severity: { type: 'string', description: 'Severity: critical, high, medium, low' },
      source: { type: 'string', description: 'Optional source filter' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
    required: ['severity'],
  },
  handler: async (args) => {
    const { severity, source, limit = 50 } = args as { severity: string; source?: string; limit?: number };
    
    let sql = 'SELECT id, name, source_type, severity, mitre_techniques FROM detections WHERE severity = ?';
    const params: unknown[] = [severity];
    
    if (source) {
      sql += ' AND source_type = ?';
      params.push(source);
    }
    
    sql += ' ORDER BY name LIMIT ?';
    params.push(limit);
    
    const results = runQuery<Detection>(sql, params);
    
    return {
      severity,
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      })),
    };
  },
});

// Get detection statistics
const getStats = defineTool({
  name: 'get_stats',
  description: 'Get statistics about indexed detections including counts by source, severity, and MITRE coverage',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    const total = runQuery<{ count: number }>('SELECT COUNT(*) as count FROM detections')[0]?.count || 0;
    const bySource = runQuery<{ source_type: string; count: number }>(
      'SELECT source_type, COUNT(*) as count FROM detections GROUP BY source_type'
    );
    const bySeverity = runQuery<{ severity: string; count: number }>(
      'SELECT severity, COUNT(*) as count FROM detections GROUP BY severity ORDER BY count DESC'
    );
    
    return {
      total_detections: total,
      by_source: Object.fromEntries(bySource.map(r => [r.source_type, r.count])),
      by_severity: Object.fromEntries(bySeverity.map(r => [r.severity, r.count])),
    };
  },
});

// Parse a TEXT column that should hold a JSON array of strings, but in legacy
// rows may hold a scalar like "CommandAndControl" (which JSON.parse returns as
// a string — iterating that yields one char per element). Always returns an array.
function parseStringList(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.filter(v => typeof v === 'string');
    if (typeof parsed === 'string') return [parsed];
    return [];
  } catch {
    return typeof raw === 'string' ? [raw] : [];
  }
}

// Canonical MITRE tactic slugs. Legacy ingest produced variants like
// "CommandAndControl", "Command and Control", "command and control", "CommandandControl".
// Normalize all to the lowercase-hyphenated form ATT&CK uses.
const TACTIC_CANONICAL: ReadonlySet<string> = new Set([
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]);
function normalizeTactic(raw: string): string | null {
  if (!raw || typeof raw !== 'string') return null;
  const slug = raw
    .trim()
    .replace(/([a-z])([A-Z])/g, '$1-$2')  // CommandAndControl -> Command-And-Control
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .toLowerCase();
  return TACTIC_CANONICAL.has(slug) ? slug : null;
}

// Shared threat profile map — used by identify_gaps and get_top_gaps
const PROFILE_TECHNIQUES: Record<string, string[]> = {
  'ransomware':        ['T1486', 'T1490', 'T1489', 'T1083', 'T1082', 'T1059', 'T1047', 'T1021'],
  'apt':               ['T1566', 'T1059', 'T1053', 'T1547', 'T1055', 'T1003', 'T1021', 'T1041'],
  'initial-access':    ['T1566', 'T1190', 'T1133', 'T1078', 'T1195', 'T1189'],
  'persistence':       ['T1547', 'T1053', 'T1136', 'T1543', 'T1574', 'T1546'],
  'credential-access': ['T1003', 'T1558', 'T1552', 'T1555', 'T1110', 'T1557'],
  'defense-evasion':   ['T1055', 'T1027', 'T1070', 'T1562', 'T1036', 'T1218'],
};

// Analyze MITRE coverage — tactic stats, top 10 techniques, weak spots (~2KB)
const analyzeCoverage = defineTool({
  name: 'analyze_coverage',
  description: 'Get MITRE ATT&CK coverage stats: tactic breakdown, top 10 covered techniques, and weak-spot tactics (coverage < 50% of best tactic). Returns ~2KB. Filter by source_type to scope to a single rule source.',
  inputSchema: {
    type: 'object',
    properties: {
      source_type: { type: 'string', description: 'Filter by source: sigma, splunk_escu, elastic, kql' },
    },
  },
  handler: async (args) => {
    const { source_type } = args as { source_type?: string };

    let sql = 'SELECT mitre_techniques, mitre_tactics FROM detections WHERE mitre_techniques IS NOT NULL';
    const params: unknown[] = [];

    if (source_type) {
      sql += ' AND source_type = ?';
      params.push(source_type);
    }

    const results = runQuery<{ mitre_techniques: string; mitre_tactics: string }>(sql, params);

    const techniqueCounts: Record<string, number> = {};
    const tacticCounts: Record<string, number> = {};

    for (const row of results) {
      for (const t of parseStringList(row.mitre_techniques)) {
        techniqueCounts[t] = (techniqueCounts[t] || 0) + 1;
      }
      for (const raw of parseStringList(row.mitre_tactics)) {
        const norm = normalizeTactic(raw);
        if (norm) tacticCounts[norm] = (tacticCounts[norm] || 0) + 1;
      }
    }

    const sortedTactics = Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]);
    const maxCount = sortedTactics[0]?.[1] || 1;
    const weakSpots = sortedTactics
      .filter(([, c]) => c < maxCount * 0.5)
      .map(([tactic]) => tactic);

    return {
      total_detections_with_mitre: results.length,
      unique_techniques: Object.keys(techniqueCounts).length,
      tactic_coverage: tacticCounts,
      top_techniques: Object.entries(techniqueCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([id, count]) => ({ technique: id, count })),
      weak_spots: weakSpots,
    };
  },
});

// Identify coverage gaps for a threat profile
const identifyGaps = defineTool({
  name: 'identify_gaps',
  description: 'Find detection gaps for a threat profile (ransomware, apt, initial-access, persistence, credential-access, defense-evasion). Returns per-technique rule counts and zero-coverage gap IDs. Use source_type to scope to a specific rule source. Call with no arguments to list available profiles and a coverage overview across all of them.',
  inputSchema: {
    type: 'object',
    properties: {
      profile: {
        type: 'string',
        description: 'Threat profile: ransomware, apt, initial-access, persistence, credential-access, defense-evasion. Omit to get an overview across all profiles.',
      },
      source_type: {
        type: 'string',
        description: 'Optional: filter by source (sigma, splunk_escu, elastic, kql)',
      },
    },
  },
  handler: async (args) => {
    const { profile, source_type } = args as { profile?: string; source_type?: string };

    if (!profile) {
      // Overview mode — summary per profile so callers can pick one.
      const overview: Record<string, { techniques: number; covered: number; gaps: number; coverage_pct: number }> = {};
      for (const [name, techs] of Object.entries(PROFILE_TECHNIQUES)) {
        let covered = 0;
        for (const t of techs) {
          let sql = 'SELECT COUNT(*) as count FROM detections WHERE mitre_techniques LIKE ?';
          const params: unknown[] = [`%${t}%`];
          if (source_type) { sql += ' AND source_type = ?'; params.push(source_type); }
          if ((runQuery<{ count: number }>(sql, params)[0]?.count || 0) > 0) covered++;
        }
        overview[name] = {
          techniques: techs.length,
          covered,
          gaps: techs.length - covered,
          coverage_pct: Math.round((covered / techs.length) * 100),
        };
      }
      return {
        available_profiles: Object.keys(PROFILE_TECHNIQUES),
        source_type: source_type || 'all',
        overview,
        next_step: 'Re-call identify_gaps with profile="<name>" to get per-technique gap details.',
      };
    }

    const targetTechniques = PROFILE_TECHNIQUES[profile.toLowerCase()];
    if (!targetTechniques) {
      return {
        error: `Unknown profile: ${profile}. Available: ${Object.keys(PROFILE_TECHNIQUES).join(', ')}`,
      };
    }

    const coverage: Record<string, number> = {};
    const gaps: string[] = [];

    for (const technique of targetTechniques) {
      let sql = 'SELECT COUNT(*) as count FROM detections WHERE mitre_techniques LIKE ?';
      const params: unknown[] = [`%${technique}%`];
      if (source_type) { sql += ' AND source_type = ?'; params.push(source_type); }
      const count = runQuery<{ count: number }>(sql, params)[0]?.count || 0;
      coverage[technique] = count;
      if (count === 0) gaps.push(technique);
    }

    return {
      profile,
      source_type: source_type || 'all',
      target_techniques: targetTechniques,
      coverage,
      gaps,
      gap_count: gaps.length,
      coverage_percentage: Math.round(
        ((targetTechniques.length - gaps.length) / targetTechniques.length) * 100
      ),
    };
  },
});

// ── Surgical micro-tools ─────────────────────────────────────────────────────

// get_technique_count — single count, ~50B response
const getTechniqueCount = defineTool({
  name: 'get_technique_count',
  description: 'Get the detection rule count for a single MITRE technique ID (~50 bytes). Use this as a fast pre-check before pulling full detection objects.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., T1059 or T1059.001)' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id } = args as { technique_id: string };
    if (!technique_id?.trim()) return { error: 'technique_id is required' };
    const tid = technique_id.toUpperCase().trim();
    const count = runQuery<{ count: number }>(
      'SELECT COUNT(*) as count FROM detections WHERE mitre_techniques LIKE ?',
      [`%${tid}%`]
    )[0]?.count || 0;
    return { technique_id: tid, count };
  },
});

// get_coverage_summary — tactic rule counts only, ~200B response
const getCoverageSummary = defineTool({
  name: 'get_coverage_summary',
  description: 'Get tactic-level detection counts as a compact object (~200 bytes). Faster and smaller than analyze_coverage. Use for quick orientation before deeper analysis.',
  inputSchema: {
    type: 'object',
    properties: {
      source_type: { type: 'string', description: 'Optional: filter by source (sigma, splunk_escu, elastic, kql)' },
    },
  },
  handler: async (args) => {
    const { source_type } = args as { source_type?: string };
    let sql = 'SELECT mitre_tactics FROM detections WHERE mitre_tactics IS NOT NULL';
    const params: unknown[] = [];
    if (source_type) { sql += ' AND source_type = ?'; params.push(source_type); }

    const rows = runQuery<{ mitre_tactics: string }>(sql, params);
    const tacticCounts: Record<string, number> = {};
    for (const row of rows) {
      const tactics = JSON.parse(row.mitre_tactics || '[]') as string[];
      for (const t of tactics) tacticCounts[t] = (tacticCounts[t] || 0) + 1;
    }
    return tacticCounts;
  },
});

// get_technique_ids — deduplicated ID list only, ~200B response
const getTechniqueIds = defineTool({
  name: 'get_technique_ids',
  description: 'Get a deduplicated flat list of MITRE technique IDs covered by detection rules (~200 bytes). No full objects. Filter by source_type, tactic, or severity to narrow scope.',
  inputSchema: {
    type: 'object',
    properties: {
      source_type: { type: 'string', description: 'Filter by source: sigma, splunk_escu, elastic, kql' },
      tactic:      { type: 'string', description: 'Filter by MITRE tactic (e.g., execution, persistence, defense-evasion)' },
      severity:    { type: 'string', description: 'Filter by severity: critical, high, medium, low' },
    },
  },
  handler: async (args) => {
    const { source_type, tactic, severity } = args as {
      source_type?: string; tactic?: string; severity?: string;
    };

    let sql = 'SELECT mitre_techniques, mitre_tactics FROM detections WHERE mitre_techniques IS NOT NULL';
    const params: unknown[] = [];
    if (source_type) { sql += ' AND source_type = ?'; params.push(source_type); }
    if (severity)    { sql += ' AND severity = ?';    params.push(severity); }

    const rows = runQuery<{ mitre_techniques: string; mitre_tactics: string }>(sql, params);
    const seen = new Set<string>();
    const tacticNorm = tactic?.toLowerCase().replace(/[\s_]/g, '-');

    for (const row of rows) {
      if (tacticNorm) {
        const rowTactics = (JSON.parse(row.mitre_tactics || '[]') as string[])
          .map(t => t.toLowerCase().replace(/[\s_]/g, '-'));
        if (!rowTactics.some(t => t.includes(tacticNorm))) continue;
      }
      const techniques = JSON.parse(row.mitre_techniques || '[]') as string[];
      for (const tid of techniques) seen.add(tid);
    }

    return Array.from(seen).sort();
  },
});

// get_top_gaps — top 5 gap IDs only, ~300B response
const getTopGaps = defineTool({
  name: 'get_top_gaps',
  description: 'Get the top 5 uncovered (or least-covered) technique IDs for a threat profile (~300 bytes). Returns only IDs — use as a fast triage signal before calling identify_gaps for full detail.',
  inputSchema: {
    type: 'object',
    properties: {
      threat_profile: {
        type: 'string',
        description: 'Threat profile: ransomware, apt, initial-access, persistence, credential-access, defense-evasion',
      },
    },
    required: ['threat_profile'],
  },
  handler: async (args) => {
    const { threat_profile } = args as { threat_profile: string };
    const targetTechniques = PROFILE_TECHNIQUES[threat_profile.toLowerCase()];
    if (!targetTechniques) {
      return {
        error: `Unknown profile: ${threat_profile}. Available: ${Object.keys(PROFILE_TECHNIQUES).join(', ')}`,
      };
    }

    const scored = targetTechniques.map(technique => ({
      technique_id: technique,
      count: runQuery<{ count: number }>(
        'SELECT COUNT(*) as count FROM detections WHERE mitre_techniques LIKE ?',
        [`%${technique}%`]
      )[0]?.count || 0,
    }));

    // Zero-coverage first, then fewest rules
    scored.sort((a, b) => a.count - b.count);
    const top5 = scored.slice(0, 5);

    return {
      threat_profile,
      top_gaps: top5.map(s => s.technique_id),
      counts: Object.fromEntries(top5.map(s => [s.technique_id, s.count])),
    };
  },
});

// suggest_detections — lean stubs only, ~2KB response
const suggestDetections = defineTool({
  name: 'suggest_detections',
  description: 'Get detection ideas for a MITRE technique ID as lean stubs (name, source, severity, log hint — no raw query content). ~2KB for up to 10 results. Use to find what rules exist before pulling full content with get_detection.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: {
        type: 'string',
        description: 'MITRE technique ID (e.g., T1059 or T1059.001)',
      },
      source_type: {
        type: 'string',
        description: 'Optional: filter by source (sigma, splunk_escu, elastic, kql)',
      },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id, source_type } = args as { technique_id: string; source_type?: string };
    if (!technique_id?.trim()) return { error: 'technique_id is required' };

    const tid = technique_id.toUpperCase().trim();
    let sql = `SELECT id, name, source_type, severity, mitre_tactics,
                      logsource_category, logsource_product, data_sources
               FROM detections WHERE mitre_techniques LIKE ?`;
    const params: unknown[] = [`%${tid}%`];
    if (source_type) { sql += ' AND source_type = ?'; params.push(source_type); }
    sql += ' ORDER BY severity DESC, name LIMIT 10';

    const rows = runQuery<{
      id: string; name: string; source_type: string; severity: string;
      mitre_tactics: string; logsource_category: string;
      logsource_product: string; data_sources: string;
    }>(sql, params);

    if (rows.length === 0) return { technique_id: tid, count: 0, detections: [] };

    return {
      technique_id: tid,
      count: rows.length,
      detections: rows.map(r => {
        // Build a minimal log hint — no full data_sources arrays
        let log_hint = '';
        if (r.logsource_product && r.logsource_category) {
          log_hint = `${r.logsource_product}/${r.logsource_category}`;
        } else if (r.logsource_category) {
          log_hint = r.logsource_category;
        } else if (r.data_sources) {
          try { log_hint = (JSON.parse(r.data_sources) as string[])[0] || ''; } catch { /**/ }
        }
        const tactics = r.mitre_tactics
          ? (JSON.parse(r.mitre_tactics) as string[]).slice(0, 2)
          : [];
        return { id: r.id, name: r.name, source: r.source_type, severity: r.severity, tactics, log_hint };
      }),
    };
  },
});

// CVE to Detection - Generate detection queries from CVE
const cveToDetection = defineTool({
  name: 'cve_to_detection',
  description: 'Convert a CVE into actionable SIEM detection logic. Fetches CVE details from NVD, maps to MITRE ATT&CK techniques, and generates detection queries in KQL (Sentinel), Splunk SPL, and Sigma formats with threat hunting hypotheses, false positive considerations, and response actions.',
  inputSchema: {
    type: 'object',
    properties: {
      cve_id: { type: 'string', description: 'CVE identifier (e.g., CVE-2024-1234)' },
    },
    required: ['cve_id'],
  },
  handler: async (args) => {
    const result = await handleCVEToDetection(args as { cve_id: string });
    return result;
  },
});

// YARA to Sigma Converter
const yaraToSigma = defineTool({
  name: 'convert_yara_to_sigma',
  description: 'Convert a YARA rule to an approximate Sigma rule. Best-effort conversion focused on string/hex conditions mapped to process_creation logs (CommandLine). Always include a warning that manual review is required.',
  inputSchema: {
    type: 'object',
    properties: {
      yara_rule: { type: 'string', description: 'The full YARA rule text to convert' },
      logsource_category: { type: 'string', description: 'Sigma logsource category (default: process_creation)' },
      product: { type: 'string', description: 'Target product (default: windows)' },
      title_override: { type: 'string', description: 'Custom title for the generated Sigma rule' },
    },
    required: ['yara_rule'],
  },
  handler: async (args) => {
    const result = handleYARAToSigma(args as {
      yara_rule: string;
      logsource_category?: string;
      product?: string;
      title_override?: string;
    });
    return result;
  },
});

// Sigma to KQL Converter
const sigmaToKQL = defineTool({
  name: 'convert_sigma_to_kql',
  description: 'Convert Sigma detection rules to Kibana Query Language (KQL) for Elastic Stack (Kibana, Elasticsearch). Uses Elastic Common Schema (ECS) field mappings and simple field:value syntax. Supports modifiers, wildcards, and complex conditions.',
  inputSchema: {
    type: 'object',
    properties: {
      sigma_rule: {
        type: 'string',
        description: 'The full Sigma rule in YAML format'
      },
      timeframe: {
        type: 'string',
        description: 'Time window for the query (default: 24h). Examples: 1h, 7d, 30d'
      },
      target_platform: {
        type: 'string',
        description: 'Target platform: elastic (Elastic Stack/Kibana) - default: elastic'
      },
      include_comments: {
        type: 'boolean',
        description: 'Include explanatory comments in KQL output (default: true)'
      },
    },
    required: ['sigma_rule'],
  },
  handler: async (args) => {
    const result = handleSigmaToKQL(args as {
      sigma_rule: string;
      timeframe?: string;
      target_platform?: string;
      include_comments?: boolean;
    });
    return result;
  },
});

// List detections by process name (e.g., "powershell.exe", "mimikatz.exe")
const listByProcessName = defineTool({
  name: 'list_by_process_name',
  description: 'Find detection rules that reference a specific process name or executable. Uses the process_names field extracted during indexing.',
  inputSchema: {
    type: 'object',
    properties: {
      process: { type: 'string', description: 'Process or executable name (e.g., powershell.exe, mimikatz.exe)' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
    required: ['process'],
  },
  handler: async (args) => {
    const { process: procName, limit = 50 } = args as { process: string; limit?: number };
    const results = runQuery<Detection>(
      `SELECT id, name, source_type, severity, mitre_techniques, process_names
       FROM detections WHERE process_names LIKE ? ORDER BY severity DESC, name LIMIT ?`,
      [`%${procName.toLowerCase()}%`, limit]
    );
    return {
      process: procName,
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        severity: d.severity,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      })),
    };
  },
});

// List detections by CVE identifier
const listByCve = defineTool({
  name: 'list_by_cve',
  description: 'Find detection rules tagged with a specific CVE identifier across all rule sources.',
  inputSchema: {
    type: 'object',
    properties: {
      cve_id: { type: 'string', description: 'CVE identifier (e.g., CVE-2024-1234 or just 2024-1234)' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
    required: ['cve_id'],
  },
  handler: async (args) => {
    const { cve_id, limit = 50 } = args as { cve_id: string; limit?: number };
    const results = runQuery<Detection>(
      `SELECT id, name, source_type, severity, mitre_techniques, cves
       FROM detections WHERE cves LIKE ? ORDER BY severity DESC, name LIMIT ?`,
      [`%${cve_id.toUpperCase()}%`, limit]
    );
    return {
      cve_id,
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        severity: d.severity,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      })),
    };
  },
});

// List detections by logsource (Sigma-specific)
const listByLogsource = defineTool({
  name: 'list_by_logsource',
  description: 'Filter Sigma detection rules by logsource category, product, or service (e.g., product=windows, category=process_creation, service=sysmon).',
  inputSchema: {
    type: 'object',
    properties: {
      product: { type: 'string', description: 'Log source product (e.g., windows, linux, aws, azure)' },
      category: { type: 'string', description: 'Log source category (e.g., process_creation, network_connection, registry_event)' },
      service: { type: 'string', description: 'Log source service (e.g., sysmon, security, system, powershell)' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
  },
  handler: async (args) => {
    const { product, category, service, limit = 50 } = args as {
      product?: string; category?: string; service?: string; limit?: number
    };

    if (!product && !category && !service) {
      return { error: 'Provide at least one of: product, category, or service' };
    }

    const conditions: string[] = [];
    const params: unknown[] = [];

    if (product) { conditions.push('logsource_product LIKE ?'); params.push(`%${product}%`); }
    if (category) { conditions.push('logsource_category LIKE ?'); params.push(`%${category}%`); }
    if (service) { conditions.push('logsource_service LIKE ?'); params.push(`%${service}%`); }

    params.push(limit);

    const results = runQuery<Detection>(
      `SELECT id, name, source_type, severity, mitre_techniques, logsource_category, logsource_product, logsource_service
       FROM detections WHERE ${conditions.join(' AND ')} ORDER BY severity DESC, name LIMIT ?`,
      params
    );

    return {
      filter: { product, category, service },
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        severity: d.severity,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      })),
    };
  },
});

// List detections by data source requirement
const listByDataSource = defineTool({
  name: 'list_by_data_source',
  description: 'Find detection rules that require a specific data source or log type (e.g., Sysmon Events, Process Creation Events, DeviceProcessEvents).',
  inputSchema: {
    type: 'object',
    properties: {
      data_source: { type: 'string', description: 'Data source or log type name (e.g., Sysmon Events, DeviceProcessEvents, AWS CloudTrail)' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
    required: ['data_source'],
  },
  handler: async (args) => {
    const { data_source, limit = 50 } = args as { data_source: string; limit?: number };
    const results = runQuery<Detection>(
      `SELECT id, name, source_type, severity, mitre_techniques, data_sources
       FROM detections WHERE data_sources LIKE ? ORDER BY severity DESC, name LIMIT ?`,
      [`%${data_source}%`, limit]
    );
    return {
      data_source,
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        severity: d.severity,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      })),
    };
  },
});

// List detections by MITRE tactic name
const listByMitreTactic = defineTool({
  name: 'list_by_mitre_tactic',
  description: 'List all detections mapped to a MITRE ATT&CK tactic (e.g., execution, persistence, defense_evasion, credential_access).',
  inputSchema: {
    type: 'object',
    properties: {
      tactic: { type: 'string', description: 'MITRE tactic name (e.g., execution, persistence, defense_evasion, lateral_movement)' },
      source: { type: 'string', description: 'Optional source filter: sigma, splunk_escu, elastic, kql' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
    required: ['tactic'],
  },
  handler: async (args) => {
    const { tactic, source, limit = 50 } = args as { tactic: string; source?: string; limit?: number };

    let sql = `SELECT id, name, source_type, severity, mitre_techniques, mitre_tactics
               FROM detections WHERE mitre_tactics LIKE ?`;
    const params: unknown[] = [`%${tactic.toLowerCase()}%`];

    if (source) {
      sql += ' AND source_type = ?';
      params.push(source);
    }

    sql += ' ORDER BY severity DESC, name LIMIT ?';
    params.push(limit);

    const results = runQuery<Detection>(sql, params);
    return {
      tactic,
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        severity: d.severity,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      })),
    };
  },
});

export const detectionTools: ToolDefinition[] = [
  searchDetections,
  getDetection,
  listByMitre,
  listBySeverity,
  getStats,
  analyzeCoverage,
  identifyGaps,
  // Surgical micro-tools
  getTechniqueCount,
  getCoverageSummary,
  getTechniqueIds,
  getTopGaps,
  suggestDetections,
  // Rule conversion (drafts only)
  cveToDetection,
  yaraToSigma,
  sigmaToKQL,
  listByProcessName,
  listByCve,
  listByLogsource,
  listByDataSource,
  listByMitreTactic,
];

export const detectionToolCount = detectionTools.length;
