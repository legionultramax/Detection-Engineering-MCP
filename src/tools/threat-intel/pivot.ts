/**
 * Unified Threat Intelligence Pivot Engine
 *
 * pivotExpandIOCs() fans out to abuse.ch and OTX in parallel,
 * auto-follows one depth level of pivot_suggestions — but ONLY those whose
 * confidence is 'high' or 'medium' (confidence gate).
 *
 * After the pivot completes, all medium + high-confidence IOCs are
 * automatically written to the knowledge graph as entities + relations,
 * closing the loop so every pivot permanently enriches tribal knowledge.
 *
 * Used by: ingest_advisory MCP tool (feeds extracted IOCs here automatically).
 */

import type {
  IntelResult,
  NormalizedIOC,
  PivotSuggestion,
  PivotResult,
  MalwareBazaarSample,
  ThreatFoxIOC,
  UrlhausURLResult,
  UrlhausHostResult,
  UrlhausTagResult,
  EnrichedIPResult,
  EnrichedDomainResult,
  EnrichedHashResult,
  EnrichedURLResult,
  EnrichedActorResult,
} from './types.js';

import {
  urlhausLookupURL,
  urlhausLookupHost,
  threatfoxSearchIOC,
  threatfoxSearchFamily,
  bazaarLookupHash,
  bazaarGetImphashSiblings,
  bazaarSearchFamily,
} from './abusech.js';

import {
  otxPivotIP,
  otxPivotDomain,
  otxPivotHash,
  otxPivotURL,
  otxSearchActor,
} from './otx.js';

// Knowledge graph — imported lazily to survive environments where DB is not initialised
import type { KGEntity } from '../../db/knowledge.js';

// ---------------------------------------------------------------------------
// Public input type
// ---------------------------------------------------------------------------

export interface PivotInput {
  iocs: Array<{ type: 'ip' | 'domain' | 'hash' | 'url'; value: string }>;
  actor?: string;
  malware_family?: string;
  techniques?: string[];
}

// ---------------------------------------------------------------------------
// Internal IOC registry with deduplication
// ---------------------------------------------------------------------------

class IOCRegistry {
  private map = new Map<string, NormalizedIOC>();

  add(ioc: NormalizedIOC): void {
    const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
    const existing = this.map.get(key);
    if (!existing) {
      this.map.set(key, { ...ioc });
      return;
    }
    for (const s of ioc.sources) {
      if (!existing.sources.includes(s)) existing.sources.push(s);
    }
    for (const t of ioc.tags) {
      if (!existing.tags.includes(t)) existing.tags.push(t);
    }
    existing.confidence     = scoreConfidence(existing.sources.length);
    existing.malware_family = existing.malware_family ?? ioc.malware_family;
    existing.mitre_techniques = [
      ...new Set([...(existing.mitre_techniques ?? []), ...(ioc.mitre_techniques ?? [])]),
    ];
    if (!existing.first_seen || (ioc.first_seen && ioc.first_seen < existing.first_seen)) {
      existing.first_seen = ioc.first_seen;
    }
  }

  addAll(iocs: NormalizedIOC[]): void {
    for (const ioc of iocs) this.add(ioc);
  }

  toSorted(): NormalizedIOC[] {
    return [...this.map.values()].sort(
      (a, b) => confidenceRank(b.confidence) - confidenceRank(a.confidence),
    );
  }

  has(type: string, value: string): boolean {
    return this.map.has(`${type}:${value.toLowerCase()}`);
  }

  /** Return only medium + high confidence IOCs for KG writes */
  confident(): NormalizedIOC[] {
    return this.toSorted().filter(ioc => ioc.confidence !== 'low');
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function scoreConfidence(sourceCount: number): NormalizedIOC['confidence'] {
  if (sourceCount >= 3) return 'high';
  if (sourceCount >= 2) return 'medium';
  return 'low';
}

function confidenceRank(c: NormalizedIOC['confidence']): number {
  return c === 'high' ? 3 : c === 'medium' ? 2 : 1;
}

function normalizeBazaarSamples(samples: MalwareBazaarSample[], sourceLabel: string): NormalizedIOC[] {
  return samples.map(s => ({
    type: 'hash' as const,
    value: s.sha256_hash,
    confidence: 'low' as const,
    sources: [sourceLabel],
    first_seen: s.first_seen,
    last_seen: s.last_seen,
    tags: s.tags ?? [],
    malware_family: s.signature ?? undefined,
  }));
}

function normalizeThreatFoxIOCs(iocs: ThreatFoxIOC[], sourceLabel: string): NormalizedIOC[] {
  return iocs.map(i => {
    const type: NormalizedIOC['type'] =
      i.ioc_type === 'sha256_hash' || i.ioc_type === 'md5_hash' ? 'hash'
      : i.ioc_type === 'ip:port' ? 'ip'
      : i.ioc_type === 'url' ? 'url'
      : 'domain';
    const value = i.ioc_type === 'ip:port' ? i.ioc.split(':')[0] : i.ioc;
    return {
      type,
      value,
      confidence: i.confidence_level >= 75 ? 'high' : i.confidence_level >= 50 ? 'medium' : 'low',
      sources: [sourceLabel],
      first_seen: i.first_seen,
      last_seen: i.last_seen ?? undefined,
      tags: i.tags ?? [],
      malware_family: i.malware_printable || undefined,
      threat_type: i.threat_type,
    } as NormalizedIOC;
  });
}

function normalizeOTXIPResult(result: EnrichedIPResult): NormalizedIOC {
  return {
    type: 'ip',
    value: result.ip,
    confidence: scoreConfidence(result.pulse_count),
    sources: ['otx'],
    tags: result.tags,
    malware_family: result.malware_families[0],
    mitre_techniques: result.mitre_techniques,
  };
}

function normalizeOTXDomainResult(result: EnrichedDomainResult): NormalizedIOC {
  return {
    type: 'domain',
    value: result.domain,
    confidence: scoreConfidence(result.pulse_count),
    sources: ['otx'],
    tags: result.tags,
    malware_family: result.malware_families[0],
    mitre_techniques: result.mitre_techniques,
  };
}

function normalizeOTXHashResult(result: EnrichedHashResult): NormalizedIOC {
  return {
    type: 'hash',
    value: result.hash,
    confidence: scoreConfidence(result.pulse_count),
    sources: ['otx'],
    tags: result.tags,
    malware_family: result.malware_families[0],
    mitre_techniques: result.mitre_techniques,
  };
}

function normalizeOTXURLResult(result: EnrichedURLResult): NormalizedIOC {
  return {
    type: 'url',
    value: result.url,
    confidence: scoreConfidence(result.pulse_count),
    sources: ['otx'],
    tags: result.tags,
    malware_family: result.malware_families[0],
  };
}

function normalizeActorIOCs(actor: EnrichedActorResult): NormalizedIOC[] {
  return Object.values(actor.iocs_by_type).flat();
}

function extractMeta(registry: IOCRegistry): {
  actors: string[];
  families: string[];
  techniques: string[];
} {
  const families   = new Set<string>();
  const techniques = new Set<string>();

  for (const ioc of registry.toSorted()) {
    if (ioc.malware_family) families.add(ioc.malware_family);
    for (const t of ioc.mitre_techniques ?? []) techniques.add(t);
  }

  return { actors: [], families: [...families], techniques: [...techniques] };
}

// ---------------------------------------------------------------------------
// Knowledge graph writer
// ---------------------------------------------------------------------------

interface KGWriteResult {
  entities_created: number;
  relations_created: number;
  error?: string;
}

/**
 * Persist medium + high-confidence IOCs to the knowledge graph.
 * Creates:
 *   - Entity per IOC (type='ioc')
 *   - Entity per malware family (type='malware_family') — if not existing
 *   - Entity per MITRE technique (type='mitre_technique') — if not existing
 *   - Relation: IOC → belongs_to → malware_family
 *   - Relation: IOC → uses_technique → mitre_technique
 *
 * Silently skips any row that already exists (upsert-safe via search).
 * Silently returns error info if DB is unavailable.
 */
async function writeIOCsToKnowledgeGraph(
  iocs: NormalizedIOC[],
  actors: string[],
  families: string[],
  techniques: string[],
): Promise<KGWriteResult> {
  // Lazy-load KG functions — avoids hard crash if DB is not yet initialised
  let createEntity: (e: Parameters<typeof import('../../db/knowledge.js')['createEntity']>[0]) => KGEntity;
  let createRelation: typeof import('../../db/knowledge.js')['createRelation'];
  let searchEntities: typeof import('../../db/knowledge.js')['searchEntities'];

  try {
    const kg = await import('../../db/knowledge.js');
    createEntity   = kg.createEntity;
    createRelation = kg.createRelation;
    searchEntities = kg.searchEntities;
  } catch {
    return { entities_created: 0, relations_created: 0, error: 'KG module unavailable' };
  }

  let entitiesCreated  = 0;
  let relationsCreated = 0;
  const now = new Date().toISOString();

  /** Upsert an entity and return its ID */
  function upsertEntity(
    type: string,
    name: string,
    description: string,
    properties?: Record<string, unknown>,
    reasoning?: string,
  ): string {
    try {
      const existing = searchEntities(name, type);
      if (existing.length > 0) return existing[0].id;

      const entity = createEntity({ type, name, description, properties, reasoning });
      entitiesCreated++;
      return entity.id;
    } catch {
      // If creation fails, return a deterministic fallback ID that won't create relations
      return `_failed_${type}_${name}`;
    }
  }

  function safeCreateRelation(
    sourceId: string,
    targetId: string,
    relationType: string,
    description: string,
    confidence: number,
  ): void {
    if (sourceId.startsWith('_failed_') || targetId.startsWith('_failed_')) return;
    try {
      createRelation({ source_id: sourceId, target_id: targetId, relation_type: relationType, description, confidence });
      relationsCreated++;
    } catch { /* non-fatal */ }
  }

  try {
    // 1. Create actor entities
    const actorEntityIds = new Map<string, string>();
    for (const actor of actors) {
      const id = upsertEntity(
        'threat_actor', actor,
        `Threat actor discovered via TI pivot engine on ${now}`,
        { source: 'pivot_engine', discovered_at: now },
      );
      actorEntityIds.set(actor, id);
    }

    // 2. Create malware family entities
    const familyEntityIds = new Map<string, string>();
    for (const family of families) {
      const id = upsertEntity(
        'malware_family', family,
        `Malware family discovered via TI pivot engine on ${now}`,
        { source: 'pivot_engine', discovered_at: now },
      );
      familyEntityIds.set(family, id);
    }

    // 3. Create MITRE technique entities
    const techniqueEntityIds = new Map<string, string>();
    for (const tid of techniques) {
      const id = upsertEntity(
        'mitre_technique', tid,
        `MITRE ATT&CK technique ${tid}`,
      );
      techniqueEntityIds.set(tid, id);
    }

    // 4. Create IOC entities + relations
    for (const ioc of iocs) {
      const confScore = ioc.confidence === 'high' ? 1.0 : 0.7;

      const iocId = upsertEntity(
        'ioc',
        ioc.value,
        `${ioc.type.toUpperCase()} indicator discovered via pivot engine`,
        {
          ioc_type: ioc.type,
          confidence: ioc.confidence,
          sources: ioc.sources,
          tags: ioc.tags,
          first_seen: ioc.first_seen,
          threat_type: ioc.threat_type,
          malware_family: ioc.malware_family,
        },
        `Discovered via ${ioc.sources.join(', ')} with ${ioc.confidence} confidence`,
      );

      // IOC → belongs_to → malware_family
      if (ioc.malware_family) {
        const famId = familyEntityIds.get(ioc.malware_family);
        if (famId) {
          safeCreateRelation(
            iocId, famId, 'belongs_to',
            `${ioc.value} attributed to malware family ${ioc.malware_family}`,
            confScore,
          );
        }
      }

      // IOC → uses_technique → MITRE technique
      for (const tid of ioc.mitre_techniques ?? []) {
        const techId = techniqueEntityIds.get(tid);
        if (techId) {
          safeCreateRelation(
            iocId, techId, 'uses_technique',
            `${ioc.value} associated with MITRE ${tid}`,
            0.8,
          );
        }
      }
    }

    return { entities_created: entitiesCreated, relations_created: relationsCreated };
  } catch (e) {
    return {
      entities_created: entitiesCreated,
      relations_created: relationsCreated,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

// ---------------------------------------------------------------------------
// Level-0 fan-out
// ---------------------------------------------------------------------------

async function level0FanOut(
  input: PivotInput,
  registry: IOCRegistry,
  allResults: Array<IntelResult<unknown>>,
  errors: string[],
): Promise<PivotSuggestion[]> {
  const tasks: Array<Promise<void>> = [];
  const suggestions: PivotSuggestion[] = [];

  for (const ioc of input.iocs) {
    tasks.push(
      (async () => {
        const results = await runIOCQuery(ioc.type, ioc.value);
        for (const res of results) {
          allResults.push(res);
          if (res.success && res.data !== null) {
            const normalized = extractNormalizedFromResult(ioc.type, ioc.value, res);
            registry.addAll(normalized);
          }
          if (res.error) errors.push(`[${res.source}] ${res.error}`);
          suggestions.push(...(res.pivot_suggestions ?? []));
        }
      })(),
    );
  }

  if (input.actor) {
    tasks.push(
      (async () => {
        const res = await otxSearchActor(input.actor!);
        allResults.push(res as IntelResult<unknown>);
        if (res.success && res.data) registry.addAll(normalizeActorIOCs(res.data));
        if (res.error) errors.push(`[otx] ${res.error}`);
        suggestions.push(...(res.pivot_suggestions ?? []));
      })(),
    );
  }

  if (input.malware_family) {
    tasks.push(
      (async () => {
        const [bazRes, tfRes] = await Promise.allSettled([
          bazaarSearchFamily(input.malware_family!),
          threatfoxSearchFamily(input.malware_family!),
        ]);
        if (bazRes.status === 'fulfilled') {
          allResults.push(bazRes.value as IntelResult<unknown>);
          if (bazRes.value.success && bazRes.value.data) {
            registry.addAll(normalizeBazaarSamples(bazRes.value.data, 'malwarebazaar:family'));
          }
          suggestions.push(...(bazRes.value.pivot_suggestions ?? []));
        }
        if (tfRes.status === 'fulfilled') {
          allResults.push(tfRes.value as IntelResult<unknown>);
          if (tfRes.value.success && tfRes.value.data) {
            registry.addAll(normalizeThreatFoxIOCs(tfRes.value.data, 'threatfox:family'));
          }
          suggestions.push(...(tfRes.value.pivot_suggestions ?? []));
        }
      })(),
    );
  }

  await Promise.allSettled(tasks);
  return suggestions;
}

async function runIOCQuery(
  type: 'ip' | 'domain' | 'hash' | 'url',
  value: string,
): Promise<Array<IntelResult<unknown>>> {
  switch (type) {
    case 'ip': {
      const [a, b] = await Promise.allSettled([otxPivotIP(value), threatfoxSearchIOC(value)]);
      return [
        a.status === 'fulfilled' ? a.value as IntelResult<unknown> : buildErrorResult('otx', String(a.reason)),
        b.status === 'fulfilled' ? b.value as IntelResult<unknown> : buildErrorResult('threatfox', String(b.reason)),
      ];
    }
    case 'domain': {
      const [a, b, c] = await Promise.allSettled([
        otxPivotDomain(value), threatfoxSearchIOC(value), urlhausLookupHost(value),
      ]);
      return [
        a.status === 'fulfilled' ? a.value as IntelResult<unknown> : buildErrorResult('otx', String(a.reason)),
        b.status === 'fulfilled' ? b.value as IntelResult<unknown> : buildErrorResult('threatfox', String(b.reason)),
        c.status === 'fulfilled' ? c.value as IntelResult<unknown> : buildErrorResult('urlhaus', String(c.reason)),
      ];
    }
    case 'hash': {
      const [a, b, c] = await Promise.allSettled([
        otxPivotHash(value), bazaarLookupHash(value), threatfoxSearchIOC(value),
      ]);
      return [
        a.status === 'fulfilled' ? a.value as IntelResult<unknown> : buildErrorResult('otx', String(a.reason)),
        b.status === 'fulfilled' ? b.value as IntelResult<unknown> : buildErrorResult('malwarebazaar', String(b.reason)),
        c.status === 'fulfilled' ? c.value as IntelResult<unknown> : buildErrorResult('threatfox', String(c.reason)),
      ];
    }
    case 'url': {
      const [a, b, c] = await Promise.allSettled([
        otxPivotURL(value), urlhausLookupURL(value), threatfoxSearchIOC(value),
      ]);
      return [
        a.status === 'fulfilled' ? a.value as IntelResult<unknown> : buildErrorResult('otx', String(a.reason)),
        b.status === 'fulfilled' ? b.value as IntelResult<unknown> : buildErrorResult('urlhaus', String(b.reason)),
        c.status === 'fulfilled' ? c.value as IntelResult<unknown> : buildErrorResult('threatfox', String(c.reason)),
      ];
    }
  }
}

function buildErrorResult(
  source: IntelResult<unknown>['source'],
  message: string,
): IntelResult<unknown> {
  return { source, success: false, data: null, error: message, queried_at: new Date().toISOString(), pivot_suggestions: [] };
}

function extractNormalizedFromResult(
  type: 'ip' | 'domain' | 'hash' | 'url',
  value: string,
  res: IntelResult<unknown>,
): NormalizedIOC[] {
  if (!res.success || res.data === null) return [];
  switch (res.source) {
    case 'otx':
      if (type === 'ip')     return [normalizeOTXIPResult(res.data as EnrichedIPResult)];
      if (type === 'domain') return [normalizeOTXDomainResult(res.data as EnrichedDomainResult)];
      if (type === 'hash')   return [normalizeOTXHashResult(res.data as EnrichedHashResult)];
      if (type === 'url')    return [normalizeOTXURLResult(res.data as EnrichedURLResult)];
      return [];
    case 'malwarebazaar':
      return normalizeBazaarSamples(res.data as MalwareBazaarSample[], 'malwarebazaar');
    case 'threatfox':
      return normalizeThreatFoxIOCs(res.data as ThreatFoxIOC[], 'threatfox');
    case 'urlhaus': {
      const d = res.data as UrlhausURLResult | UrlhausHostResult | UrlhausTagResult;
      const urlStatus = 'url_status' in d ? d.url_status : undefined;
      return [{
        type,
        value,
        confidence: urlStatus === 'online' ? 'high' : 'medium',
        sources: ['urlhaus'],
        tags: ('tags' in d ? (d.tags ?? []) : []) as string[],
      }];
    }
  }
}

// ---------------------------------------------------------------------------
// Level-1 auto-follow — CONFIDENCE GATED
// ---------------------------------------------------------------------------

/**
 * Expand one hop of pivot suggestions, but ONLY follow those with
 * confidence 'high' or 'medium'. 'low' suggestions are recorded in the
 * result's pivot_suggestions field for manual analyst follow-up.
 */
async function level1AutoFollow(
  suggestions: PivotSuggestion[],
  registry: IOCRegistry,
  allResults: Array<IntelResult<unknown>>,
  errors: string[],
): Promise<void> {
  const seen    = new Set<string>();
  const toQuery: PivotSuggestion[] = [];

  for (const s of suggestions) {
    if (!['imphash', 'actor', 'family'].includes(s.type)) continue;

    // ── CONFIDENCE GATE ──────────────────────────────────────────────────────
    // Only auto-follow 'high' and 'medium'. Skip 'low' (undefined defaults to
    // 'medium' — safe default for backwards compat with older suggestions).
    const eff = s.confidence ?? 'medium';
    if (eff === 'low') continue;
    // ─────────────────────────────────────────────────────────────────────────

    const key = `${s.type}:${s.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    toQuery.push(s);
  }

  const tasks = toQuery.map(s => async () => {
    try {
      switch (s.type) {
        case 'imphash': {
          const res = await bazaarGetImphashSiblings(s.value);
          allResults.push(res as IntelResult<unknown>);
          if (res.success && res.data) {
            registry.addAll(normalizeBazaarSamples(res.data, `malwarebazaar:imphash:${s.value}`));
          }
          if (res.error) errors.push(`[imphash pivot] ${res.error}`);
          break;
        }
        case 'actor': {
          const res = await otxSearchActor(s.value);
          allResults.push(res as IntelResult<unknown>);
          if (res.success && res.data) registry.addAll(normalizeActorIOCs(res.data));
          if (res.error) errors.push(`[actor pivot] ${res.error}`);
          break;
        }
        case 'family': {
          const [bazRes, tfRes] = await Promise.allSettled([
            bazaarSearchFamily(s.value, 25),
            threatfoxSearchFamily(s.value),
          ]);
          if (bazRes.status === 'fulfilled') {
            allResults.push(bazRes.value as IntelResult<unknown>);
            if (bazRes.value.success && bazRes.value.data) {
              registry.addAll(normalizeBazaarSamples(bazRes.value.data, `malwarebazaar:family:${s.value}`));
            }
          }
          if (tfRes.status === 'fulfilled') {
            allResults.push(tfRes.value as IntelResult<unknown>);
            if (tfRes.value.success && tfRes.value.data) {
              registry.addAll(normalizeThreatFoxIOCs(tfRes.value.data, `threatfox:family:${s.value}`));
            }
          }
          break;
        }
      }
    } catch (e) {
      errors.push(`[level-1 ${s.type}:${s.value}] ${e instanceof Error ? e.message : String(e)}`);
    }
  });

  // Max 8 concurrent level-1 requests
  const CONCURRENCY = 8;
  for (let i = 0; i < tasks.length; i += CONCURRENCY) {
    await Promise.allSettled(tasks.slice(i, i + CONCURRENCY).map(t => t()));
  }
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Unified IOC Pivot Engine.
 *
 * Workflow:
 *   Level 0: fan out to abuse.ch + OTX for all input IOCs simultaneously.
 *   Level 1: auto-follow imphash/actor/family suggestions — ONLY if confidence
 *            is 'high' or 'medium'. Low-confidence suggestions are surfaced for
 *            manual review but NOT automatically queried.
 *   Post:    all medium + high-confidence discovered IOCs are written to the
 *            knowledge graph as entities + relations, permanently enriching
 *            tribal knowledge for future analysts and agents.
 *
 * Cache: all underlying queries use TTL cache (OTX 2h, abuse.ch 30min),
 * so repeated pivots on the same advisory are near-instant on subsequent runs.
 *
 * @example
 * const result = await pivotExpandIOCs({
 *   iocs: [
 *     { type: 'ip',   value: '45.33.32.156' },
 *     { type: 'hash', value: 'e3b0c44298fc1c149...' },
 *   ],
 *   actor: 'APT29',
 *   malware_family: 'Cobalt Strike',
 * });
 * // result.discovered_iocs — confidence-sorted, deduplicated
 * // result.kg_write        — what was persisted to the knowledge graph
 */
export async function pivotExpandIOCs(
  input: PivotInput,
): Promise<PivotResult & { kg_write: KGWriteResult }> {
  const registry   = new IOCRegistry();
  const allResults: Array<IntelResult<unknown>> = [];
  const errors: string[] = [];

  // Level 0 — parallel fan-out
  const lvl0Suggestions = await level0FanOut(input, registry, allResults, errors);

  // Level 1 — confidence-gated auto-follow
  let depthReached = false;
  if (lvl0Suggestions.length > 0) {
    const followable = lvl0Suggestions.filter(s =>
      ['imphash', 'actor', 'family'].includes(s.type) &&
      (s.confidence ?? 'medium') !== 'low',
    );
    if (followable.length > 0) {
      depthReached = followable.length > 20;
      await level1AutoFollow(
        followable.slice(0, 20),
        registry,
        allResults,
        errors,
      );
    }
  }

  const { actors, families, techniques } = extractMeta(registry);

  // Post-pivot — write high+medium confidence IOCs to knowledge graph
  const confidentIOCs = registry.confident();
  const kgWrite = await writeIOCsToKnowledgeGraph(
    confidentIOCs,
    actors,
    families,
    techniques,
  );

  if (kgWrite.error) {
    errors.push(`[kg_write] ${kgWrite.error}`);
  }

  return {
    input_iocs: input.iocs,
    discovered_iocs: registry.toSorted(),
    actors,
    malware_families: families,
    mitre_techniques: techniques,
    source_results: allResults,
    errors,
    pivot_depth_reached: depthReached,
    queried_at: new Date().toISOString(),
    kg_write: kgWrite,
  };
}

// ---------------------------------------------------------------------------
// KGWriteResult type (re-exported so callers can use it)
// ---------------------------------------------------------------------------
export type { KGWriteResult };
