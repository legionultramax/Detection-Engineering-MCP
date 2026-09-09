// Coverage Assessor — Core Graph Traversal Engine
//
// Given a session's telemetry (data components present), traverses:
//   1. mitre_relationships (type=detects) → which techniques can be detected
//   2. For each technique, checks ALL required data components
//   3. Cross-references detection index → which techniques have rules
//   4. Classifies: COVERED / DETECTABLE / PARTIAL / GAP
//
// This is the heart of the coverage engine.

import { runQuery, getDb, saveDb } from '../../db/connection.js';
import {
  getSessionDataComponents,
  getSessionTelemetry,
  writeSessionCoverage,
  updateSessionStats,
} from '../../db/coverage-engine.js';

export interface CoverageResult {
  session_id: string;
  total_techniques: number;
  covered: number;       // Has data + has rules
  detectable: number;    // Has data + no rules
  partial: number;       // Some data sources present
  gap: number;           // No data sources present
  coverage_pct: number;  // (covered + detectable) / total
  alert_pct: number;     // covered / total (actually alerting)
  by_tactic: Record<string, { covered: number; detectable: number; partial: number; gap: number; total: number }>;
  top_gaps: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    missing_components: string[];
    actor_usage: number;
  }>;
}

/**
 * Run full coverage assessment for a session.
 * This is the core algorithm — Steps 1-6 from the architecture.
 */
export function assessCoverage(sessionId: string): CoverageResult {
  // Step 1: Collect all data components present in this session
  const presentComponents = getSessionDataComponents(sessionId);

  if (presentComponents.length === 0) {
    return emptyResult(sessionId);
  }

  // Resolve present components to their STIX IDs
  const componentStixIds = resolveComponentStixIds(presentComponents);

  // Get field quality info from session telemetry
  const telemetryRows = getSessionTelemetry(sessionId);
  const componentQuality = new Map<string, string>();
  for (const row of telemetryRows) {
    const comp = row.mapped_data_component as string;
    const quality = row.quality_tier as string;
    // Keep worst quality if multiple entries for same component
    const existing = componentQuality.get(comp);
    if (!existing || qualityRank(quality) < qualityRank(existing)) {
      componentQuality.set(comp, quality);
    }
  }

  // Step 2: Find ALL techniques detectable by present data components
  // Query: which techniques do our data components detect?
  const detectableTechniqueStixIds = new Set<string>();
  for (const stixId of componentStixIds.values()) {
    const rows = runQuery<{ target_ref: string }>(
      `SELECT DISTINCT target_ref FROM mitre_relationships
       WHERE relationship_type = 'detects' AND source_ref = ?`,
      [stixId]
    );
    for (const row of rows) {
      detectableTechniqueStixIds.add(row.target_ref);
    }
  }

  // Step 3: Get ALL techniques (our universe)
  const allTechniques = runQuery<{
    external_id: string;
    stix_id: string;
    name: string;
    tactics: string;
    is_deprecated: number;
  }>(
    `SELECT external_id, stix_id, name, tactics, is_deprecated
     FROM mitre_techniques_full
     WHERE is_deprecated = 0`
  );

  // Build technique map for fast lookup
  const techniqueMap = new Map<string, { external_id: string; stix_id: string; name: string; tactics: string[] }>();
  for (const t of allTechniques) {
    let tactics: string[] = [];
    try { tactics = JSON.parse(t.tactics || '[]'); } catch { /* */ }
    techniqueMap.set(t.stix_id, {
      external_id: t.external_id,
      stix_id: t.stix_id,
      name: t.name,
      tactics,
    });
  }

  // Step 3-4: For each technique, determine coverage status
  const byTactic: Record<string, { covered: number; detectable: number; partial: number; gap: number; total: number }> = {};
  let coveredCount = 0;
  let detectableCount = 0;
  let partialCount = 0;
  let gapCount = 0;

  const gapDetails: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    missing_components: string[];
    actor_usage: number;
  }> = [];

  // Begin bulk write
  const database = getDb();
  database.exec('BEGIN TRANSACTION');

  try {
    for (const [stixId, tech] of techniqueMap) {
      // Get ALL data components that can detect this technique
      const requiredComponents = runQuery<{ source_ref: string; name: string }>(
        `SELECT DISTINCT dc.stix_id as source_ref, dc.name
         FROM mitre_data_components dc
         JOIN mitre_relationships r ON r.source_ref = dc.stix_id
         WHERE r.target_ref = ? AND r.relationship_type = 'detects'`,
        [stixId]
      );

      const primaryTactic = tech.tactics[0] || 'unknown';

      // Ensure tactic entry exists
      if (!byTactic[primaryTactic]) {
        byTactic[primaryTactic] = { covered: 0, detectable: 0, partial: 0, gap: 0, total: 0 };
      }
      byTactic[primaryTactic].total++;

      if (requiredComponents.length === 0) {
        // Technique has no data component mapping in MITRE — skip (can't assess)
        continue;
      }

      // Check which required components are present
      const presentRequired = requiredComponents.filter(rc =>
        componentStixIds.has(rc.name)
      );
      const missingRequired = requiredComponents.filter(rc =>
        !componentStixIds.has(rc.name)
      );

      let status: string;
      let fieldQuality = 'unknown';

      if (presentRequired.length === 0) {
        // GAP — none of the required data components are present
        status = 'GAP';
        gapCount++;
        byTactic[primaryTactic].gap++;

        // Track gap details for prioritization
        const actorUsage = getActorUsageCount(stixId);
        gapDetails.push({
          technique_id: tech.external_id,
          technique_name: tech.name,
          tactic: primaryTactic,
          missing_components: missingRequired.map(rc => rc.name),
          actor_usage: actorUsage,
        });
      } else if (presentRequired.length > 0 && missingRequired.length > 0) {
        // PARTIAL — some but not all data components present
        status = 'PARTIAL';
        partialCount++;
        byTactic[primaryTactic].partial++;
        fieldQuality = getBestQuality(presentRequired.map(rc => rc.name), componentQuality);
      } else {
        // All required data components present — check field quality
        fieldQuality = getBestQuality(presentRequired.map(rc => rc.name), componentQuality);

        if (fieldQuality === 'degraded') {
          status = 'PARTIAL';
          partialCount++;
          byTactic[primaryTactic].partial++;
        } else {
          // Full data source coverage — check if detection rules exist
          const ruleCount = countDetectionRules(tech.external_id);

          if (ruleCount > 0) {
            status = 'COVERED';
            coveredCount++;
            byTactic[primaryTactic].covered++;
          } else {
            status = 'DETECTABLE';
            detectableCount++;
            byTactic[primaryTactic].detectable++;
          }
        }
      }

      // Step 5: Count detection rules
      const detectionRuleCount = countDetectionRules(tech.external_id);

      // Build remediation hint for non-covered techniques
      let remediation: string | null = null;
      if (status === 'GAP') {
        const needed = missingRequired.map(rc => rc.name).join(', ');
        remediation = `Enable log sources providing: ${needed}`;
      } else if (status === 'PARTIAL') {
        const needed = missingRequired.map(rc => rc.name).join(', ');
        remediation = missingRequired.length > 0
          ? `Add log sources for: ${needed}`
          : `Improve field coverage (enable critical fields in logging config)`;
      } else if (status === 'DETECTABLE') {
        remediation = `Write detection rule — telemetry is available but no rule exists`;
      }

      // Step 6: Write to session_coverage
      writeSessionCoverage(
        sessionId,
        tech.external_id,
        tech.name,
        primaryTactic,
        status,
        presentRequired.map(rc => rc.name),
        missingRequired.map(rc => rc.name),
        detectionRuleCount,
        fieldQuality,
        remediation
      );
    }

    database.exec('COMMIT');
  } catch (e) {
    database.exec('ROLLBACK');
    throw e;
  }

  saveDb();

  // Update session stats
  const totalAssessed = coveredCount + detectableCount + partialCount + gapCount;
  updateSessionStats(sessionId, coveredCount, partialCount, gapCount, detectableCount);

  // Sort gaps by actor usage (most-used techniques = highest priority gaps)
  gapDetails.sort((a, b) => b.actor_usage - a.actor_usage);

  return {
    session_id: sessionId,
    total_techniques: totalAssessed,
    covered: coveredCount,
    detectable: detectableCount,
    partial: partialCount,
    gap: gapCount,
    coverage_pct: totalAssessed > 0
      ? Math.round(((coveredCount + detectableCount) / totalAssessed) * 100)
      : 0,
    alert_pct: totalAssessed > 0
      ? Math.round((coveredCount / totalAssessed) * 100)
      : 0,
    by_tactic: byTactic,
    top_gaps: gapDetails.slice(0, 20),
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Coverage comparison between two sessions (or hypothetical additions)
// ────────────────────────────────────────────────────────────────────────────

export interface CoverageDelta {
  added_components: string[];
  techniques_improved: Array<{
    technique_id: string;
    technique_name: string;
    old_status: string;
    new_status: string;
  }>;
  gap_reduction: number;
  new_coverage_pct: number;
}

/**
 * Compare coverage between session_before and session_after.
 */
export function compareCoverage(sessionBefore: string, sessionAfter: string): CoverageDelta {
  const before = runQuery<{ technique_id: string; technique_name: string; coverage_status: string }>(
    'SELECT technique_id, technique_name, coverage_status FROM session_coverage WHERE session_id = ?',
    [sessionBefore]
  );
  const after = runQuery<{ technique_id: string; technique_name: string; coverage_status: string }>(
    'SELECT technique_id, technique_name, coverage_status FROM session_coverage WHERE session_id = ?',
    [sessionAfter]
  );

  const beforeMap = new Map(before.map(r => [r.technique_id, r]));
  const afterMap = new Map(after.map(r => [r.technique_id, r]));

  const compBefore = new Set(getSessionDataComponents(sessionBefore));
  const compAfter = new Set(getSessionDataComponents(sessionAfter));
  const addedComponents = [...compAfter].filter(c => !compBefore.has(c));

  const improved: CoverageDelta['techniques_improved'] = [];
  for (const [tid, afterRow] of afterMap) {
    const beforeRow = beforeMap.get(tid);
    if (beforeRow && statusRank(afterRow.coverage_status) > statusRank(beforeRow.coverage_status)) {
      improved.push({
        technique_id: tid,
        technique_name: afterRow.technique_name,
        old_status: beforeRow.coverage_status,
        new_status: afterRow.coverage_status,
      });
    }
  }

  const gapsBefore = before.filter(r => r.coverage_status === 'GAP').length;
  const gapsAfter = after.filter(r => r.coverage_status === 'GAP').length;

  const totalAfter = after.length;
  const coveredAfter = after.filter(r => r.coverage_status === 'COVERED' || r.coverage_status === 'DETECTABLE').length;

  return {
    added_components: addedComponents,
    techniques_improved: improved,
    gap_reduction: gapsBefore - gapsAfter,
    new_coverage_pct: totalAfter > 0 ? Math.round((coveredAfter / totalAfter) * 100) : 0,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Pareto-optimal recommendations: which log sources close the most gaps?
// ────────────────────────────────────────────────────────────────────────────

export interface CoverageRecommendation {
  data_component: string;
  data_source: string;
  event_sources: Array<{ event_source: string; event_id: string; event_name: string }>;
  techniques_closed: number;
  technique_ids: string[];
  priority_score: number;
}

export function recommendLogSources(sessionId: string, maxRecommendations: number = 10): CoverageRecommendation[] {
  // Get all GAP and PARTIAL techniques
  const gaps = runQuery<{ technique_id: string; data_sources_missing: string }>(
    `SELECT technique_id, data_sources_missing FROM session_coverage
     WHERE session_id = ? AND coverage_status IN ('GAP', 'PARTIAL')`,
    [sessionId]
  );

  // Count how many techniques each missing component would close
  const componentImpact = new Map<string, Set<string>>();
  for (const gap of gaps) {
    let missing: string[] = [];
    try { missing = JSON.parse(gap.data_sources_missing || '[]'); } catch { /* */ }
    for (const comp of missing) {
      if (!componentImpact.has(comp)) {
        componentImpact.set(comp, new Set());
      }
      componentImpact.get(comp)!.add(gap.technique_id);
    }
  }

  // For each component, find which event sources provide it
  const recommendations: CoverageRecommendation[] = [];
  for (const [component, techSet] of componentImpact) {
    // Look up event sources from telemetry_mappings
    const sources = runQuery<{ event_source: string; event_id: string; event_name: string; mitre_data_source: string }>(
      `SELECT event_source, event_id, event_name, mitre_data_source
       FROM telemetry_mappings WHERE mitre_data_component = ?`,
      [component]
    );

    // Get actor usage for priority scoring
    const actorUsage = [...techSet].reduce((sum, tid) => {
      return sum + getActorUsageCountByExtId(tid);
    }, 0);

    recommendations.push({
      data_component: component,
      data_source: sources[0]?.mitre_data_source || 'Unknown',
      event_sources: sources.map(s => ({
        event_source: s.event_source,
        event_id: s.event_id,
        event_name: s.event_name || '',
      })),
      techniques_closed: techSet.size,
      technique_ids: [...techSet],
      priority_score: techSet.size * (1 + actorUsage * 0.1), // Weight by actor usage
    });
  }

  // Sort by priority_score descending (most impact first)
  recommendations.sort((a, b) => b.priority_score - a.priority_score);

  return recommendations.slice(0, maxRecommendations);
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/**
 * Resolve data component names to their STIX IDs.
 * Returns a Map of component_name → stix_id for present components.
 */
function resolveComponentStixIds(componentNames: string[]): Map<string, string> {
  const result = new Map<string, string>();
  for (const name of componentNames) {
    const rows = runQuery<{ stix_id: string; name: string }>(
      `SELECT stix_id, name FROM mitre_data_components WHERE name = ?`,
      [name]
    );
    if (rows.length > 0) {
      result.set(name, rows[0].stix_id);
    } else {
      // Fuzzy match
      const fuzzy = runQuery<{ stix_id: string; name: string }>(
        `SELECT stix_id, name FROM mitre_data_components WHERE name LIKE ?`,
        [`%${name}%`]
      );
      if (fuzzy.length > 0) {
        result.set(name, fuzzy[0].stix_id);
      }
    }
  }
  return result;
}

function countDetectionRules(techniqueId: string): number {
  try {
    const rows = runQuery<{ cnt: number }>(
      `SELECT COUNT(*) as cnt FROM detections WHERE mitre_techniques LIKE ?`,
      [`%${techniqueId}%`]
    );
    return rows[0]?.cnt || 0;
  } catch {
    return 0;
  }
}

function getActorUsageCount(techniqueStixId: string): number {
  try {
    const rows = runQuery<{ cnt: number }>(
      `SELECT COUNT(DISTINCT source_ref) as cnt FROM mitre_relationships
       WHERE target_ref = ? AND relationship_type = 'uses'`,
      [techniqueStixId]
    );
    return rows[0]?.cnt || 0;
  } catch {
    return 0;
  }
}

function getActorUsageCountByExtId(techniqueExtId: string): number {
  try {
    const rows = runQuery<{ cnt: number }>(
      `SELECT COUNT(DISTINCT r.source_ref) as cnt
       FROM mitre_relationships r
       JOIN mitre_techniques_full t ON r.target_ref = t.stix_id
       WHERE t.external_id = ? AND r.relationship_type = 'uses'`,
      [techniqueExtId]
    );
    return rows[0]?.cnt || 0;
  } catch {
    return 0;
  }
}

function qualityRank(quality: string): number {
  switch (quality) {
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    case 'degraded': return 0;
    default: return -1;
  }
}

function getBestQuality(componentNames: string[], qualityMap: Map<string, string>): string {
  let best = 'unknown';
  let bestRank = -1;
  for (const name of componentNames) {
    const q = qualityMap.get(name) || 'unknown';
    const r = qualityRank(q);
    if (r > bestRank) {
      bestRank = r;
      best = q;
    }
  }
  return best;
}

function statusRank(status: string): number {
  switch (status) {
    case 'COVERED': return 4;
    case 'DETECTABLE': return 3;
    case 'PARTIAL': return 2;
    case 'GAP': return 1;
    default: return 0;
  }
}

function emptyResult(sessionId: string): CoverageResult {
  return {
    session_id: sessionId,
    total_techniques: 0,
    covered: 0,
    detectable: 0,
    partial: 0,
    gap: 0,
    coverage_pct: 0,
    alert_pct: 0,
    by_tactic: {},
    top_gaps: [],
  };
}
