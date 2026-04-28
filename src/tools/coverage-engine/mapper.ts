// Telemetry Mapper for Coverage Engine
// Maps parsed logs → telemetry_mappings table → MITRE Data Source + Component
// Scores field coverage (% of critical fields present)

import { lookupMapping, type TelemetryMapping } from '../../db/coverage-engine.js';

export interface MappedTelemetry {
  event_source: string;
  event_id: string;
  mitre_data_source: string;
  mitre_data_component: string;
  fields_present: string[];
  fields_critical_total: string[];
  fields_critical_present: string[];
  fields_critical_missing: string[];
  field_coverage_pct: number;
  quality_tier: 'high' | 'medium' | 'low' | 'degraded';
  mapping: TelemetryMapping;
}

export interface MappingResult {
  success: boolean;
  mappings: MappedTelemetry[];
  unmapped: boolean;
  message: string;
}

/**
 * Map a parsed log (event_source + event_id + field list) to MITRE Data Source/Component.
 * Returns all matching mappings (an event can map to multiple data components).
 */
export function mapTelemetry(
  eventSource: string,
  eventId: string,
  fieldsPresent: string[]
): MappingResult {
  const rows = lookupMapping(eventSource, eventId);

  if (rows.length === 0) {
    return {
      success: false,
      mappings: [],
      unmapped: true,
      message: `No telemetry mapping found for ${eventSource}:${eventId}. This event source/ID is not in the mapping table.`,
    };
  }

  // Normalize field names for case-insensitive comparison
  const normalizedPresent = new Set(fieldsPresent.map(f => f.toLowerCase()));

  const mappings: MappedTelemetry[] = rows.map(row => {
    const criticalFields: string[] = safeParseJson(row.fields_critical, []);
    const critPresent = criticalFields.filter(f => normalizedPresent.has(f.toLowerCase()));
    const critMissing = criticalFields.filter(f => !normalizedPresent.has(f.toLowerCase()));

    const coveragePct = criticalFields.length > 0
      ? Math.round((critPresent.length / criticalFields.length) * 100)
      : 100; // No critical fields defined = assume full coverage

    // Quality tier based on critical field coverage
    let qualityTier: 'high' | 'medium' | 'low' | 'degraded';
    if (coveragePct >= 80) {
      qualityTier = 'high';
    } else if (coveragePct >= 50) {
      qualityTier = 'medium';
    } else if (coveragePct > 0) {
      qualityTier = 'low';
    } else {
      qualityTier = 'degraded';
    }

    // Override: if the mapping itself is low quality, cap the tier
    if (row.detection_quality === 'low' && qualityTier === 'high') {
      qualityTier = 'medium';
    }

    return {
      event_source: eventSource,
      event_id: eventId,
      mitre_data_source: row.mitre_data_source,
      mitre_data_component: row.mitre_data_component,
      fields_present: fieldsPresent,
      fields_critical_total: criticalFields,
      fields_critical_present: critPresent,
      fields_critical_missing: critMissing,
      field_coverage_pct: coveragePct,
      quality_tier: qualityTier,
      mapping: row,
    };
  });

  return {
    success: true,
    mappings,
    unmapped: false,
    message: `Mapped ${eventSource}:${eventId} → ${mappings.length} data component(s)`,
  };
}

function safeParseJson<T>(val: string | null | undefined, fallback: T): T {
  if (!val) return fallback;
  try {
    return JSON.parse(val);
  } catch {
    return fallback;
  }
}
