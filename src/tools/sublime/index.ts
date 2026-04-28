// Sublime Security Detection Rules — MCP Tools
//
// Tools:
//   sublime_search      — Full-text search across all Sublime rules
//   sublime_get_rule    — Get a specific rule by ID with full MQL source
//   sublime_sync        — Trigger a git pull + re-index
//   sublime_get_stats   — Summary statistics

import { defineTool, type ToolDefinition } from '../registry.js';
import {
  searchSublimeRules,
  getSublimeRule,
  getSublimeStats,
  syncSublimeRepo,
  indexSublimeRules,
  needsSublimeSync,
  type SublimeRuleRow,
} from '../../db/sublime-rules.js';

// ── Helpers ───────────────────────────────────────────────────────────────

function safeParseJson<T>(json: string | null, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

function formatRule(row: SublimeRuleRow) {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    severity: row.severity,
    author: row.author,
    attack_category: row.logsource_category,
    mitre_techniques: safeParseJson<string[]>(row.mitre_techniques, []),
    tags: safeParseJson<string[]>(row.tags, []),
    data_sources: safeParseJson<string[]>(row.data_sources, []),
    references: safeParseJson<string[]>(row.refs, []),
    last_updated: row.updated_at,
  };
}

// ── Tool 1: sublime_search ────────────────────────────────────────────────

const sublimeSearch = defineTool({
  name: 'sublime_search',
  description:
    'Search Sublime Security email detection rules by keyword, attack type, MITRE technique, or detection method. Returns matching rules with severity, category, and MITRE mapping. Use to find email-layer detections for phishing, BEC, malware delivery, and credential theft.',
  inputSchema: {
    type: 'object',
    properties: {
      query: {
        type: 'string',
        description:
          'Search term — rule name, attack type (e.g., "credential phishing", "BEC"), MITRE T-ID (e.g., "T1566"), detection method (e.g., "YARA"), or keyword in the MQL source',
      },
      severity: {
        type: 'string',
        enum: ['critical', 'high', 'medium', 'low'],
        description: 'Optional: filter by severity level',
      },
      limit: {
        type: 'number',
        description: 'Maximum results to return (default: 20, max: 100)',
      },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query, severity, limit = 20 } = args as {
      query: string;
      severity?: string;
      limit?: number;
    };

    const maxLimit = Math.min(limit, 100);
    // Over-fetch to account for severity post-filter
    let rows = searchSublimeRules(query, severity ? maxLimit * 4 : maxLimit);

    if (severity) {
      rows = rows.filter((r) => r.severity === severity);
    }

    rows = rows.slice(0, maxLimit);

    if (rows.length === 0) {
      return {
        query,
        count: 0,
        message: `No Sublime Security rules found matching "${query}"`,
        rules: [],
      };
    }

    return {
      query,
      count: rows.length,
      filters: { severity: severity || null },
      rules: rows.map(formatRule),
    };
  },
});

// ── Tool 2: sublime_get_rule ──────────────────────────────────────────────

const sublimeGetRule = defineTool({
  name: 'sublime_get_rule',
  description:
    'Get a specific Sublime Security rule by its ID, including the full MQL (Message Query Language) detection source, MITRE techniques, and metadata. Use after sublime_search to inspect the complete rule logic.',
  inputSchema: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        description:
          'Rule ID from sublime_search (e.g., "sublime_d00893ba-a65a-5b04-88d1-f35512eae291")',
      },
    },
    required: ['id'],
  },
  handler: async (args) => {
    const { id } = args as { id: string };
    const row = getSublimeRule(id);

    if (!row) {
      return { error: `Sublime Security rule not found: ${id}` };
    }

    return {
      ...formatRule(row),
      mql_source: row.query,
      file_path: row.file_path,
    };
  },
});

// ── Tool 3: sublime_sync ──────────────────────────────────────────────────

const sublimeSync = defineTool({
  name: 'sublime_sync',
  description:
    'Sync the Sublime Security rules repository (git pull) and re-index all rules into the detection database. Run this to pick up newly published rules. Returns the count of rules indexed and any parse errors.',
  inputSchema: {
    type: 'object',
    properties: {
      force: {
        type: 'boolean',
        description:
          'Force a re-index even if the repository was recently synced (default: false)',
      },
    },
  },
  handler: async (args) => {
    const { force = false } = args as { force?: boolean };

    if (!force && !needsSublimeSync()) {
      const stats = getSublimeStats();
      return {
        action: 'skipped',
        message: `Already indexed. ${stats.total_rules} Sublime rules in database. Set force=true to re-index.`,
        stats,
      };
    }

    const syncResult = await syncSublimeRepo();
    const indexResult = await indexSublimeRules();

    return {
      action: syncResult.action,
      repo_path: syncResult.path,
      rules_indexed: indexResult.rules_indexed,
      errors: indexResult.errors.length > 0 ? indexResult.errors : undefined,
      error_count: indexResult.errors.length,
    };
  },
});

// ── Tool 4: sublime_get_stats ─────────────────────────────────────────────

const sublimeGetStats = defineTool({
  name: 'sublime_get_stats',
  description:
    'Get summary statistics about indexed Sublime Security rules: total count, severity breakdown, attack type distribution, top MITRE techniques, and last sync timestamp.',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    const stats = getSublimeStats();

    if (stats.total_rules === 0) {
      return {
        ...stats,
        message:
          'No Sublime Security rules indexed yet. Use sublime_sync to clone and index the repository.',
      };
    }

    return stats;
  },
});

// ── Exports ───────────────────────────────────────────────────────────────

export const sublimeTools: ToolDefinition[] = [
  sublimeSearch,
  sublimeGetRule,
  sublimeSync,
  sublimeGetStats,
];

export const sublimeToolCount = sublimeTools.length;
