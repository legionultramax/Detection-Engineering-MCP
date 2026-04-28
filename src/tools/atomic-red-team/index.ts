// Atomic Red Team (ART) MCP Tools
// Provides adversary simulation test lookup, search, and detection validation
//
// Tools:
//   art_get_tests        — Get all ART tests for a MITRE technique
//   art_search           — Full-text search across all tests
//   art_get_test         — Get specific test by GUID
//   art_validate_technique — Cross-reference ART tests vs detection rules
//   art_get_stats        — Summary statistics
//   art_coverage_report  — Batch validation across multiple techniques

import { defineTool, type ToolDefinition } from '../registry.js';
import { runQuery } from '../../db/connection.js';
import {
  getTestsByTechnique,
  searchArtTests,
  getTestByGuid,
  getArtStats,
  type ARTTestRow,
} from '../../db/atomic-red-team.js';
import { mapConditionsToArt } from './condition-mapper.js';

// ── Tool 1: art_get_tests ────────────────────────────────────────────────

const artGetTests = defineTool({
  name: 'art_get_tests',
  description:
    'Get all Atomic Red Team adversary simulation tests for a MITRE ATT&CK technique. Returns test names, attack commands, cleanup commands, platforms, executor type, and input arguments. Use to understand the full attack surface for a technique.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: {
        type: 'string',
        description: 'MITRE technique ID (e.g., "T1059.001", "T1547.001")',
      },
      platform: {
        type: 'string',
        description:
          'Optional: filter by platform — windows, linux, macos, containers, iaas',
      },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id, platform } = args as {
      technique_id: string;
      platform?: string;
    };

    let tests = getTestsByTechnique(technique_id);

    if (platform) {
      tests = tests.filter((t) => {
        try {
          const platforms = JSON.parse(t.supported_platforms) as string[];
          return platforms.includes(platform.toLowerCase());
        } catch {
          return false;
        }
      });
    }

    if (tests.length === 0) {
      return {
        technique_id: technique_id.toUpperCase(),
        count: 0,
        message: `No Atomic Red Team tests found for ${technique_id}`,
        tests: [],
      };
    }

    return {
      technique_id: tests[0].technique_id,
      technique_name: tests[0].technique_name,
      count: tests.length,
      tests: tests.map((t) => ({
        guid: t.guid,
        number: t.test_number,
        name: t.test_name,
        description: t.description,
        platforms: safeParseJson(t.supported_platforms, []),
        executor: t.executor_name,
        elevation_required: t.elevation_required === 1,
        command: t.command,
        cleanup_command: t.cleanup_command || null,
        input_arguments: safeParseJson(t.input_arguments, null),
        has_dependencies: t.dependencies ? true : false,
      })),
    };
  },
});

// ── Tool 2: art_search ───────────────────────────────────────────────────

const artSearch = defineTool({
  name: 'art_search',
  description:
    'Full-text search across all Atomic Red Team tests (~1,770+). Searches test names, descriptions, commands, arguments, file paths, and binary names. Use to find tests by attack tool (e.g., "mimikatz"), binary (e.g., "certutil"), technique pattern (e.g., "registry run key"), or artifact (e.g., "powershell -enc").',
  inputSchema: {
    type: 'object',
    properties: {
      keyword: {
        type: 'string',
        description:
          'Search keyword (e.g., "mimikatz", "certutil", "registry", "download cradle", "webshell")',
      },
      platform: {
        type: 'string',
        description: 'Optional: filter by platform — windows, linux, macos',
      },
      executor: {
        type: 'string',
        description:
          'Optional: filter by executor — powershell, command_prompt, bash, sh, manual',
      },
      limit: {
        type: 'number',
        description: 'Maximum results to return (default: 30, max: 100)',
      },
    },
    required: ['keyword'],
  },
  handler: async (args) => {
    const {
      keyword,
      platform,
      executor,
      limit = 30,
    } = args as {
      keyword: string;
      platform?: string;
      executor?: string;
      limit?: number;
    };

    const maxLimit = Math.min(limit, 100);
    // Over-fetch to account for post-filtering
    let tests = searchArtTests(keyword, maxLimit * 3);

    if (platform) {
      tests = tests.filter((t) => {
        try {
          const platforms = JSON.parse(t.supported_platforms) as string[];
          return platforms.includes(platform.toLowerCase());
        } catch {
          return false;
        }
      });
    }

    if (executor) {
      tests = tests.filter((t) => t.executor_name === executor.toLowerCase());
    }

    tests = tests.slice(0, maxLimit);

    return {
      keyword,
      count: tests.length,
      filters_applied: {
        platform: platform || null,
        executor: executor || null,
      },
      tests: tests.map((t) => ({
        guid: t.guid,
        technique_id: t.technique_id,
        technique_name: t.technique_name,
        name: t.test_name,
        executor: t.executor_name,
        platforms: safeParseJson(t.supported_platforms, []),
        elevation_required: t.elevation_required === 1,
        description: t.description ? t.description.substring(0, 200) : null,
        command_preview: t.command ? t.command.substring(0, 400) : null,
      })),
    };
  },
});

// ── Tool 3: art_get_test ─────────────────────────────────────────────────

const artGetTest = defineTool({
  name: 'art_get_test',
  description:
    'Get full details of a specific Atomic Red Team test by its GUID. Returns complete attack command, cleanup command, input arguments with defaults, dependencies, and platform requirements.',
  inputSchema: {
    type: 'object',
    properties: {
      guid: {
        type: 'string',
        description: 'Atomic test GUID (UUID format)',
      },
    },
    required: ['guid'],
  },
  handler: async (args) => {
    const { guid } = args as { guid: string };
    const test = getTestByGuid(guid);

    if (!test) {
      return { error: `Atomic Red Team test not found: ${guid}` };
    }

    return {
      guid: test.guid,
      technique_id: test.technique_id,
      technique_name: test.technique_name,
      test_number: test.test_number,
      name: test.test_name,
      description: test.description,
      platforms: safeParseJson(test.supported_platforms, []),
      executor: {
        name: test.executor_name,
        command: test.command,
        cleanup_command: test.cleanup_command,
        elevation_required: test.elevation_required === 1,
      },
      input_arguments: safeParseJson(test.input_arguments, null),
      dependencies: safeParseJson(test.dependencies, null),
      dependency_executor_name: test.dependency_executor_name,
    };
  },
});

// ── Tool 4: art_validate_technique ───────────────────────────────────────

const artValidateTechnique = defineTool({
  name: 'art_validate_technique',
  description:
    'Cross-reference Atomic Red Team tests against existing detection rules for a MITRE technique. For each ART test, checks whether any detection rule in the repo matches the attack artifacts. Returns a per-test validation matrix with COVERED/GAP status and an overall coverage percentage. Use this to find blind spots in rules you thought were complete.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: {
        type: 'string',
        description: 'MITRE technique ID (e.g., "T1059.001")',
      },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id } = args as { technique_id: string };
    const tid = technique_id.toUpperCase().trim();

    // Get ART tests for this technique
    const artTests = getTestsByTechnique(tid);

    // Get detection rules for this technique (parent + sub-technique)
    const parentTid = tid.includes('.') ? tid.split('.')[0] : tid;
    const detections = runQuery<{
      id: string;
      name: string;
      source_type: string;
      severity: string;
      query: string;
    }>(
      `SELECT id, name, source_type, severity, query FROM detections
       WHERE mitre_techniques LIKE ? OR mitre_techniques LIKE ?`,
      [`%${tid}%`, `%${parentTid}%`]
    );

    if (artTests.length === 0 && detections.length === 0) {
      return {
        technique_id: tid,
        art_test_count: 0,
        detection_count: 0,
        message: 'No ART tests or detection rules found for this technique',
      };
    }

    if (artTests.length === 0) {
      return {
        technique_id: tid,
        art_test_count: 0,
        detection_count: detections.length,
        message: `No ART tests available for ${tid}, but ${detections.length} detection rules exist (cannot validate)`,
        detections_available: detections.map((d) => ({
          id: d.id,
          name: d.name,
          source: d.source_type,
          severity: d.severity,
        })),
      };
    }

    // For each ART test, check if any detection rule likely covers its artifacts
    const validation = artTests.map((test) => {
      const command = (test.command || '').toLowerCase();
      const testName = test.test_name.toLowerCase();
      const testDesc = (test.description || '').toLowerCase();

      // Extract meaningful tokens from the ART test command
      const allText = `${command} ${testName} ${testDesc}`;
      const tokens = extractSignificantTokens(allText);

      // Check each detection rule for artifact overlap
      const matchingDetections = detections.filter((d) => {
        const query = (d.query || '').toLowerCase();
        const ruleName = d.name.toLowerCase();
        const ruleText = `${query} ${ruleName}`;

        // A rule "matches" if it shares significant tokens with the test
        const matchCount = tokens.filter(
          (token) => ruleText.includes(token)
        ).length;

        // Require at least 2 token matches for meaningful overlap
        return matchCount >= 2;
      });

      const coverage =
        matchingDetections.length > 0 ? 'COVERED' : 'GAP';

      return {
        guid: test.guid,
        test_number: test.test_number,
        test_name: test.test_name,
        executor: test.executor_name,
        platforms: safeParseJson(test.supported_platforms, []),
        elevation_required: test.elevation_required === 1,
        command_preview: test.command
          ? test.command.substring(0, 200)
          : null,
        matching_detections: matchingDetections.map((d) => ({
          id: d.id,
          name: d.name,
          source: d.source_type,
          severity: d.severity,
        })),
        match_count: matchingDetections.length,
        coverage,
      };
    });

    const covered = validation.filter((v) => v.coverage === 'COVERED').length;
    const gaps = validation.filter((v) => v.coverage === 'GAP').length;
    const coveragePct =
      artTests.length > 0
        ? Math.round((covered / artTests.length) * 100)
        : 0;

    return {
      technique_id: tid,
      technique_name: artTests[0]?.technique_name || tid,
      art_test_count: artTests.length,
      detection_count: detections.length,
      covered_tests: covered,
      gap_tests: gaps,
      coverage_percentage: coveragePct,
      coverage_grade:
        coveragePct >= 80
          ? 'A'
          : coveragePct >= 60
            ? 'B'
            : coveragePct >= 40
              ? 'C'
              : coveragePct >= 20
                ? 'D'
                : 'F',
      validation_matrix: validation,
      gap_tests_detail: validation
        .filter((v) => v.coverage === 'GAP')
        .map((v) => ({
          guid: v.guid,
          test_name: v.test_name,
          executor: v.executor,
          command_preview: v.command_preview,
        })),
      detections_available: detections.map((d) => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        severity: d.severity,
      })),
    };
  },
});

// ── Tool 5: art_get_stats ────────────────────────────────────────────────

const artGetStatsTool = defineTool({
  name: 'art_get_stats',
  description:
    'Get summary statistics about indexed Atomic Red Team tests: total tests, techniques covered, breakdown by platform and executor type, top techniques by test count, and repository sync status.',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    return getArtStats();
  },
});

// ── Tool 6: art_coverage_report ──────────────────────────────────────────

const artCoverageReport = defineTool({
  name: 'art_coverage_report',
  description:
    'Batch validation of detection coverage across multiple MITRE techniques using Atomic Red Team tests. For each technique, checks if ART tests exist and if detection rules are present. Returns an overall coverage matrix, prioritized gaps, and per-technique status. Use for threat actor profile validation or coverage audits.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_ids: {
        type: 'array',
        description:
          'Array of MITRE technique IDs to validate (e.g., ["T1059.001", "T1547.001", "T1505.003"])',
      },
    },
    required: ['technique_ids'],
  },
  handler: async (args) => {
    const { technique_ids } = args as { technique_ids: string[] };

    const results: Array<{
      technique_id: string;
      technique_name: string;
      art_tests: number;
      detections: number;
      status: string;
    }> = [];

    let totalArtTests = 0;
    let totalDetections = 0;
    let techniquesWithTests = 0;
    let techniquesWithDetections = 0;
    let techniquesFullyGapped = 0;

    for (const tid of technique_ids) {
      const normalized = tid.toUpperCase().trim();
      const parentTid = normalized.includes('.') ? normalized.split('.')[0] : normalized;

      const artTests = getTestsByTechnique(normalized);
      const detections = runQuery<{
        id: string;
        name: string;
        source_type: string;
      }>(
        `SELECT id, name, source_type FROM detections
         WHERE mitre_techniques LIKE ? OR mitre_techniques LIKE ?`,
        [`%${normalized}%`, `%${parentTid}%`]
      );

      totalArtTests += artTests.length;
      totalDetections += detections.length;

      if (artTests.length > 0) techniquesWithTests++;
      if (detections.length > 0) techniquesWithDetections++;

      let status: string;
      if (artTests.length === 0 && detections.length === 0) {
        status = 'NO_DATA';
      } else if (artTests.length === 0) {
        status = 'NO_ART_TESTS';
      } else if (detections.length === 0) {
        status = 'DETECTION_GAP';
        techniquesFullyGapped++;
      } else {
        status = 'HAS_COVERAGE';
      }

      results.push({
        technique_id: normalized,
        technique_name: artTests[0]?.technique_name || normalized,
        art_tests: artTests.length,
        detections: detections.length,
        status,
      });
    }

    // Sort: DETECTION_GAP first (highest priority), then by art_tests descending
    const priorityGaps = results
      .filter((r) => r.status === 'DETECTION_GAP')
      .sort((a, b) => b.art_tests - a.art_tests);

    return {
      summary: {
        techniques_checked: technique_ids.length,
        techniques_with_art_tests: techniquesWithTests,
        techniques_with_detections: techniquesWithDetections,
        techniques_fully_gapped: techniquesFullyGapped,
        total_art_tests: totalArtTests,
        total_detections: totalDetections,
      },
      techniques: results,
      priority_gaps: priorityGaps,
      recommendation:
        techniquesFullyGapped > 0
          ? `${techniquesFullyGapped} technique(s) have ART simulation tests but ZERO detection rules. These are your highest-priority detection engineering targets.`
          : 'All techniques with ART tests have at least one detection rule. Run art_validate_technique per technique for deeper per-test validation.',
    };
  },
});

// ── Helper Functions ─────────────────────────────────────────────────────

function safeParseJson<T>(json: string | null, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

/**
 * Extract significant tokens from command text for artifact matching.
 * Filters out common noise words and short tokens.
 */
function extractSignificantTokens(text: string): string[] {
  const noise = new Set([
    'the', 'and', 'for', 'with', 'from', 'this', 'that', 'will', 'are',
    'not', 'can', 'has', 'was', 'were', 'been', 'have', 'had', 'its',
    'may', 'use', 'set', 'get', 'new', 'add', 'run', 'cmd', 'exe',
    'true', 'false', 'null', 'none', 'test', 'path', 'file', 'name',
    'type', 'value', 'string', 'default', 'description', 'object',
    'system', 'windows', 'linux', 'macos', 'force', 'error',
  ]);

  // Split on whitespace, special chars, and common separators
  const tokens = text
    .toLowerCase()
    .split(/[\s\\/|&;:,'"<>(){}[\]=+\-*!@#$%^~`]+/)
    .filter((t) => t.length >= 5) // Only tokens 5+ chars
    .filter((t) => !noise.has(t))
    .filter((t) => !/^\d+$/.test(t)); // Remove pure numbers

  // Deduplicate
  return [...new Set(tokens)];
}

// ── Tool 7: art_map_conditions ──────────────────────────────────────────

const artMapConditions = defineTool({
  name: 'art_map_conditions',
  description:
    'Static analysis: parse a Sigma rule\'s detection conditions and cross-reference each one field-by-field against Atomic Red Team test artifacts. Returns a structured match matrix showing which conditions are MATCHED (verified against ART command text), INFERRED (parent process from executor type), UNABLE_TO_VERIFY (registry/network/access mask — ART doesn\'t record these), or NOT_IN_ART (no test covers this pattern). Also identifies ART tests the rule would miss. Pure string analysis — never executes anything.',
  inputSchema: {
    type: 'object',
    properties: {
      sigma_rule: {
        type: 'string',
        description: 'Full Sigma rule YAML text (the complete rule, not just the detection block)',
      },
      technique_id: {
        type: 'string',
        description: 'MITRE technique ID to match against (e.g., "T1059.001", "T1140")',
      },
    },
    required: ['sigma_rule', 'technique_id'],
  },
  handler: async (args) => {
    const { sigma_rule, technique_id } = args as {
      sigma_rule: string;
      technique_id: string;
    };

    const result = mapConditionsToArt(sigma_rule, technique_id);

    // Format for MCP response — compact but complete
    return {
      parse_status: result.parseStatus,
      parse_warnings: result.parseWarnings.length > 0 ? result.parseWarnings : undefined,
      conditions_found: result.conditions.length,
      match_matrix: result.matchMatrix.map(m => ({
        field: m.condition.field,
        modifier: m.condition.modifier,
        values: m.condition.values,
        block: m.condition.block,
        is_filter: m.condition.isFilter,
        status: m.status,
        reason: m.reason,
        art_matches: m.artMatches.length > 0 ? m.artMatches : undefined,
      })),
      uncovered_art_tests: result.uncoveredArtTests.length > 0
        ? result.uncoveredArtTests.map(t => ({
            test_num: t.testNum,
            test_name: t.testName,
            guid: t.guid,
            command_preview: t.commandPreview,
            reason: t.reason,
          }))
        : undefined,
      summary: result.summary,
    };
  },
});

// ── Exports ──────────────────────────────────────────────────────────────

export const atomicRedTeamTools: ToolDefinition[] = [
  artGetTests,
  artSearch,
  artGetTest,
  artValidateTechnique,
  artGetStatsTool,
  artCoverageReport,
  artMapConditions,
];

export const atomicRedTeamToolCount = atomicRedTeamTools.length; // 7
