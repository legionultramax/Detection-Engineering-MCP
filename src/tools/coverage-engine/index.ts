// Coverage Engine MCP Tools
// Automated ATT&CK Detection Coverage Engine
//
// Tools:
//   coverage_ingest_log      — Parse + map a sample log to MITRE data sources
//   coverage_assess_session  — Run full coverage assessment (the core engine)
//   coverage_gaps_detail     — Detailed gap report with remediation
//   coverage_compare         — Compare two coverage sessions (before/after)
//   coverage_recommend       — Pareto-optimal log source recommendations

import { defineTool, type ToolDefinition } from '../registry.js';
import { parseLog, parseStructuredInput } from './parser.js';
import { mapTelemetry } from './mapper.js';
import { assessCoverage, compareCoverage, recommendLogSources } from './assessor.js';
import {
  createCoverageSession,
  addSessionTelemetry,
  getSession,
  getSessionCoverage,
  getSessionTelemetry,
  listSessions,
  getMappingStats,
  getAllMappings,
} from '../../db/coverage-engine.js';

// ── Tool 1: coverage_ingest_log ────────────────────────────────────────────

const coverageIngestLog = defineTool({
  name: 'coverage_ingest_log',
  description:
    'Ingest a sample log into a coverage assessment session. Parses the log to extract event source, event ID, and fields, then maps to MITRE ATT&CK data sources and data components. Supports Windows Event XML, Sysmon, JSON (EDR/Cloud), auditd key-value, and CEF formats. You can also provide event_source + event_id + fields directly instead of a raw log. Creates a new session if session_id is not provided.',
  inputSchema: {
    type: 'object',
    properties: {
      session_id: {
        type: 'string',
        description: 'Session ID to add this log to. If omitted, a new session is created.',
      },
      session_name: {
        type: 'string',
        description: 'Name for a new session (used only when creating a new session).',
      },
      raw_log: {
        type: 'string',
        description: 'Raw log text to parse. Provide this OR (event_source + event_id).',
      },
      event_source: {
        type: 'string',
        description: 'Event source identifier (e.g., "windows_security", "sysmon", "crowdstrike", "mde", "linux_auditd", "aws_cloudtrail", "azure_ad"). Use with event_id instead of raw_log.',
      },
      event_id: {
        type: 'string',
        description: 'Event ID (e.g., "4688", "1", "ProcessRollup2", "DeviceProcessEvents"). Use with event_source.',
      },
      fields: {
        type: 'array',
        description: 'Optional: list of field names present in the log. If omitted with raw_log, fields are auto-extracted. If omitted with event_source+event_id, all fields from the mapping are assumed.',
      },
    },
    required: [],
  },
  handler: async (args) => {
    const {
      session_id,
      session_name,
      raw_log,
      event_source,
      event_id,
      fields,
    } = args as {
      session_id?: string;
      session_name?: string;
      raw_log?: string;
      event_source?: string;
      event_id?: string;
      fields?: string[];
    };

    // Parse the log
    let parsed;
    if (raw_log) {
      parsed = parseLog(raw_log);
    } else if (event_source && event_id) {
      parsed = parseStructuredInput(event_source, event_id, fields);
    } else {
      return {
        error: true,
        message: 'Provide either raw_log (to auto-parse) or event_source + event_id (structured input).',
      };
    }

    // Map to MITRE data sources
    const fieldsToCheck = parsed.fields.length > 0 ? parsed.fields : (fields || []);
    const mapping = mapTelemetry(parsed.event_source, parsed.event_id, fieldsToCheck);

    // Create or reuse session
    const sid = session_id || `session_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    if (!session_id) {
      createCoverageSession(
        sid,
        session_name || `Coverage Assessment ${new Date().toISOString().split('T')[0]}`,
        `Auto-created session for ${parsed.event_source}:${parsed.event_id}`
      );
    }

    // Store each mapping as a telemetry entry
    if (mapping.success) {
      for (const m of mapping.mappings) {
        addSessionTelemetry(
          sid,
          m.event_source,
          m.event_id,
          raw_log || null,
          fieldsToCheck,
          m.mitre_data_source,
          m.mitre_data_component,
          m.field_coverage_pct,
          m.quality_tier
        );
      }
    }

    return {
      session_id: sid,
      parsed: {
        event_source: parsed.event_source,
        event_id: parsed.event_id,
        format_detected: parsed.format_detected,
        fields_extracted: parsed.fields.length,
      },
      mapping: mapping.success
        ? {
            mapped: true,
            data_components: mapping.mappings.map(m => ({
              data_source: m.mitre_data_source,
              data_component: m.mitre_data_component,
              field_coverage_pct: m.field_coverage_pct,
              quality_tier: m.quality_tier,
              critical_fields_missing: m.fields_critical_missing,
            })),
          }
        : {
            mapped: false,
            message: mapping.message,
          },
      hint: mapping.success
        ? 'Log ingested. Add more logs to the same session, then call coverage_assess_session to run the full assessment.'
        : 'Log could not be mapped. Try providing event_source and event_id directly.',
    };
  },
});

// ── Tool 2: coverage_assess_session ────────────────────────────────────────

const coverageAssessSession = defineTool({
  name: 'coverage_assess_session',
  description:
    'Run a full MITRE ATT&CK coverage assessment for a session. For each technique in the ATT&CK matrix, determines if it is COVERED (data + rules exist), DETECTABLE (data exists but no rules), PARTIAL (some data sources present), or GAP (no data sources). This is the core engine that answers: what can we detect, what can\'t we detect, and what logs are missing.',
  inputSchema: {
    type: 'object',
    properties: {
      session_id: {
        type: 'string',
        description: 'Session ID to assess. Must have ingested logs via coverage_ingest_log first.',
      },
    },
    required: ['session_id'],
  },
  handler: async (args) => {
    const { session_id } = args as { session_id: string };

    const session = getSession(session_id);
    if (!session) {
      return { error: true, message: `Session ${session_id} not found. Create one via coverage_ingest_log first.` };
    }

    const telemetry = getSessionTelemetry(session_id);
    if (telemetry.length === 0) {
      return { error: true, message: `Session ${session_id} has no ingested logs. Use coverage_ingest_log to add logs first.` };
    }

    const result = assessCoverage(session_id);

    return {
      session_id: result.session_id,
      summary: {
        total_techniques_assessed: result.total_techniques,
        covered: result.covered,
        detectable: result.detectable,
        partial: result.partial,
        gap: result.gap,
        coverage_pct: result.coverage_pct,
        alert_pct: result.alert_pct,
      },
      four_state_explanation: {
        COVERED: `${result.covered} techniques — have both telemetry AND detection rules`,
        DETECTABLE: `${result.detectable} techniques — have telemetry but NO rules (write rules for these!)`,
        PARTIAL: `${result.partial} techniques — some but not all required data sources present`,
        GAP: `${result.gap} techniques — no relevant data sources present at all`,
      },
      by_tactic: result.by_tactic,
      top_priority_gaps: result.top_gaps.slice(0, 10),
      telemetry_ingested: telemetry.length,
      next_steps: [
        result.detectable > 0
          ? `${result.detectable} techniques are DETECTABLE — use search_detections or WAT-40 to write rules`
          : null,
        result.gap > 0
          ? `${result.gap} techniques are GAPs — call coverage_recommend to find which log sources close the most gaps`
          : null,
        'Use coverage_gaps_detail for the full prioritized gap table',
      ].filter(Boolean),
    };
  },
});

// ── Tool 3: coverage_gaps_detail ───────────────────────────────────────────

const coverageGapsDetail = defineTool({
  name: 'coverage_gaps_detail',
  description:
    'Get detailed gap report for a coverage session. Shows every technique that is GAP or PARTIAL, with exactly which data sources are missing and remediation steps. Filterable by tactic and coverage status.',
  inputSchema: {
    type: 'object',
    properties: {
      session_id: {
        type: 'string',
        description: 'Session ID (must have run coverage_assess_session first)',
      },
      status_filter: {
        type: 'string',
        description: 'Filter by coverage status: GAP, PARTIAL, DETECTABLE, COVERED, or omit for all non-COVERED',
      },
      tactic_filter: {
        type: 'string',
        description: 'Filter by MITRE tactic (e.g., "execution", "persistence", "credential-access")',
      },
      limit: {
        type: 'number',
        description: 'Max results to return (default: 50)',
      },
    },
    required: ['session_id'],
  },
  handler: async (args) => {
    const { session_id, status_filter, tactic_filter, limit } = args as {
      session_id: string;
      status_filter?: string;
      tactic_filter?: string;
      limit?: number;
    };

    let coverage = getSessionCoverage(session_id, status_filter);

    if (!status_filter) {
      // Default: show everything except COVERED
      coverage = coverage.filter(r => r.coverage_status !== 'COVERED');
    }

    if (tactic_filter) {
      coverage = coverage.filter(r => {
        const tactic = (r.tactic as string || '').toLowerCase().replace(/[\s-]+/g, '-');
        return tactic.includes(tactic_filter.toLowerCase().replace(/[\s-]+/g, '-'));
      });
    }

    const maxResults = limit || 50;
    coverage = coverage.slice(0, maxResults);

    // Parse JSON fields for cleaner output
    const formatted = coverage.map(r => ({
      technique_id: r.technique_id,
      technique_name: r.technique_name,
      tactic: r.tactic,
      status: r.coverage_status,
      detection_rules: r.detection_rules_available,
      field_quality: r.field_quality,
      data_sources_present: safeParseJson(r.data_sources_present as string, []),
      data_sources_missing: safeParseJson(r.data_sources_missing as string, []),
      remediation: r.remediation,
    }));

    return {
      session_id,
      total_results: formatted.length,
      filters_applied: {
        status: status_filter || 'non-COVERED',
        tactic: tactic_filter || 'all',
      },
      gaps: formatted,
    };
  },
});

// ── Tool 4: coverage_compare ───────────────────────────────────────────────

const coverageCompare = defineTool({
  name: 'coverage_compare',
  description:
    'Compare coverage between two assessment sessions. Shows which techniques improved (GAP→PARTIAL→DETECTABLE→COVERED) and how many gaps were closed. Use to answer: "If I add Sysmon, how much does my coverage improve?"',
  inputSchema: {
    type: 'object',
    properties: {
      session_before: {
        type: 'string',
        description: 'Session ID of the baseline (before)',
      },
      session_after: {
        type: 'string',
        description: 'Session ID of the comparison (after adding new log sources)',
      },
    },
    required: ['session_before', 'session_after'],
  },
  handler: async (args) => {
    const { session_before, session_after } = args as {
      session_before: string;
      session_after: string;
    };

    for (const sid of [session_before, session_after]) {
      if (!getSession(sid)) {
        return { error: true, message: `Session ${sid} not found.` };
      }
    }

    const delta = compareCoverage(session_before, session_after);

    return {
      baseline_session: session_before,
      comparison_session: session_after,
      added_data_components: delta.added_components,
      gaps_closed: delta.gap_reduction,
      new_coverage_pct: delta.new_coverage_pct,
      techniques_improved: delta.techniques_improved.length,
      improvements: delta.techniques_improved.slice(0, 30),
    };
  },
});

// ── Tool 5: coverage_recommend ─────────────────────────────────────────────

const coverageRecommend = defineTool({
  name: 'coverage_recommend',
  description:
    'Pareto-optimal log source recommendations. Analyzes coverage gaps and ranks missing data sources by how many technique gaps they would close. Answers: "Enable these 5 log sources to close 80% of your gaps." Prioritizes by actor usage (techniques used by more actors = higher priority).',
  inputSchema: {
    type: 'object',
    properties: {
      session_id: {
        type: 'string',
        description: 'Session ID (must have run coverage_assess_session first)',
      },
      max_recommendations: {
        type: 'number',
        description: 'Maximum recommendations to return (default: 10)',
      },
    },
    required: ['session_id'],
  },
  handler: async (args) => {
    const { session_id, max_recommendations } = args as {
      session_id: string;
      max_recommendations?: number;
    };

    if (!getSession(session_id)) {
      return { error: true, message: `Session ${session_id} not found.` };
    }

    const recs = recommendLogSources(session_id, max_recommendations || 10);

    if (recs.length === 0) {
      return {
        session_id,
        message: 'No recommendations — either no gaps exist or gaps cannot be mapped to known log sources.',
        recommendations: [],
      };
    }

    // Calculate cumulative gap closure
    const totalGaps = recs.reduce((sum, r) => sum + r.techniques_closed, 0);
    let cumulative = 0;
    const formatted = recs.map((r, i) => {
      cumulative += r.techniques_closed;
      return {
        rank: i + 1,
        data_component: r.data_component,
        data_source: r.data_source,
        techniques_closed: r.techniques_closed,
        cumulative_closed: cumulative,
        priority_score: Math.round(r.priority_score * 10) / 10,
        enable_via: r.event_sources.map(s => `${s.event_source} Event ${s.event_id} (${s.event_name})`),
        sample_technique_ids: r.technique_ids.slice(0, 5),
      };
    });

    return {
      session_id,
      total_gap_techniques: totalGaps,
      recommendations: formatted,
      pareto_insight: formatted.length >= 3
        ? `Enabling the top 3 recommendations closes ${formatted[2]?.cumulative_closed || 0} technique gaps`
        : undefined,
    };
  },
});

// ── Bonus Tool: coverage_list_mappings ──────────────────────────────────────

const coverageListMappings = defineTool({
  name: 'coverage_list_mappings',
  description:
    'List all known telemetry-to-MITRE mappings (Event ID → Data Source/Component). Use to see which event sources/IDs the coverage engine understands. Also shows session statistics.',
  inputSchema: {
    type: 'object',
    properties: {
      event_source_filter: {
        type: 'string',
        description: 'Filter by event source (e.g., "sysmon", "windows_security", "mde")',
      },
    },
    required: [],
  },
  handler: async (args) => {
    const { event_source_filter } = args as { event_source_filter?: string };

    const stats = getMappingStats();
    let mappings = getAllMappings();

    if (event_source_filter) {
      mappings = mappings.filter(m =>
        m.event_source.toLowerCase().includes(event_source_filter.toLowerCase())
      );
    }

    const formatted = mappings.map(m => ({
      event_source: m.event_source,
      event_id: m.event_id,
      event_name: m.event_name,
      data_source: m.mitre_data_source,
      data_component: m.mitre_data_component,
      quality: m.detection_quality,
      critical_fields: safeParseJson(m.fields_critical, []),
    }));

    const sessions = listSessions();

    return {
      stats,
      mappings: formatted,
      total_displayed: formatted.length,
      recent_sessions: sessions.slice(0, 5).map(s => ({
        session_id: s.session_id,
        name: s.name,
        created_at: s.created_at,
        techniques_full: s.total_techniques_full,
        techniques_gap: s.total_techniques_gap,
      })),
    };
  },
});

// ────────────────────────────────────────────────────────────────────────────
// Export
// ────────────────────────────────────────────────────────────────────────────

function safeParseJson<T>(val: string | null | undefined, fallback: T): T {
  if (!val) return fallback;
  try {
    return JSON.parse(val);
  } catch {
    return fallback;
  }
}

export const coverageEngineTools: ToolDefinition[] = [
  coverageIngestLog,
  coverageAssessSession,
  coverageGapsDetail,
  coverageCompare,
  coverageRecommend,
  coverageListMappings,
];

export const coverageEngineToolCount = coverageEngineTools.length;
