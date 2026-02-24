/**
 * AlienVault OTX Integration Module
 *
 * Provides functions for pivoting on indicators and extracting actor/campaign
 * intelligence from the Open Threat Exchange (OTX) platform.
 *
 * Authentication: OTX_API_KEY environment variable (required).
 * Rate limiting: 100 ms delay between bulk/paginated requests.
 * Caching: all enrichment results cached for OTX_TTL (2 hours).
 *          otxSubscribedPulsesFeed is NOT cached (time-sensitive).
 * All functions return IntelResult<T> — never throw.
 */

import type {
  IntelResult,
  PivotSuggestion,
  Confidence,
  NormalizedIOC,
  OTXIPGeneral,
  OTXDomainGeneral,
  OTXDomainPassiveDNS,
  OTXFileGeneral,
  OTXFileAnalysis,
  OTXURLGeneral,
  OTXSearchPulsesResponse,
  OTXPulseIndicatorsResponse,
  OTXPulse,
  OTXPulseWithIndicators,
  OTXIndicator,
  EnrichedIPResult,
  EnrichedDomainResult,
  EnrichedHashResult,
  EnrichedURLResult,
  EnrichedActorResult,
} from './types.js';

import { withCache, makeCacheKey, OTX_TTL } from './cache.js';

// ---------------------------------------------------------------------------
// Configuration & internal helpers
// ---------------------------------------------------------------------------

const OTX_BASE  = 'https://otx.alienvault.com/api/v1';
const PAGE_LIMIT = 100;

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getApiKey(): string {
  const key = process.env['OTX_API_KEY'];
  if (!key) {
    throw new Error(
      'OTX_API_KEY environment variable is not set. ' +
      'Get a key at https://otx.alienvault.com',
    );
  }
  return key;
}

/**
 * Authenticated GET to OTX API. Retries once on HTTP 429 after 5 s.
 */
async function otxGet<T>(path: string, query?: Record<string, string>): Promise<T> {
  const apiKey = getApiKey();
  const url    = new URL(`${OTX_BASE}${path}`);
  if (query) {
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
  }
  const opts: RequestInit = {
    method: 'GET',
    headers: { 'X-OTX-API-KEY': apiKey, Accept: 'application/json' },
  };
  let res = await fetch(url.toString(), opts);
  if (res.status === 429) {
    await sleep(5000);
    res = await fetch(url.toString(), opts);
  }
  if (!res.ok) {
    throw new Error(`OTX HTTP ${res.status} for ${url.pathname}: ${await res.text()}`);
  }
  return res.json() as Promise<T>;
}

function makeOk<T>(data: T, suggestions: PivotSuggestion[]): IntelResult<T> {
  return {
    source: 'otx',
    success: true,
    data,
    queried_at: new Date().toISOString(),
    pivot_suggestions: deduplicateSuggestions(suggestions),
  };
}

function makeErr<T>(message: string): IntelResult<T> {
  return {
    source: 'otx',
    success: false,
    data: null,
    error: message,
    queried_at: new Date().toISOString(),
    pivot_suggestions: [],
  };
}

// ---------------------------------------------------------------------------
// Shared extraction helpers
// ---------------------------------------------------------------------------

function extractAdversaries(pulses: OTXPulse[]): string[] {
  return [...new Set(pulses.map(p => p.adversary).filter(a => a.length > 0))];
}

function extractMalwareFamilies(pulses: OTXPulse[]): string[] {
  return [...new Set(pulses.flatMap(p => p.malware_families.map(m => m.id)).filter(Boolean))];
}

function extractMitreTechniques(pulses: OTXPulse[]): string[] {
  return [...new Set(
    pulses.flatMap(p => p.attack_ids.map(a => a.id)).filter(id => /^T\d{4}/.test(id)),
  )];
}

function extractTags(pulses: OTXPulse[]): string[] {
  return [...new Set(pulses.flatMap(p => p.tags))];
}

function topPulses(
  pulses: OTXPulse[],
  n = 5,
): Array<{ id: string; name: string; author: string; modified: string }> {
  return pulses.slice(0, n).map(p => ({
    id: p.id,
    name: p.name,
    author: p.author_name,
    modified: p.modified,
  }));
}

function deduplicateSuggestions(suggestions: PivotSuggestion[]): PivotSuggestion[] {
  const seen = new Set<string>();
  return suggestions.filter(s => {
    const key = `${s.type}:${s.value.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Derive confidence for an actor suggestion based on pulse count.
 *   > 10 pulses → high  (widely tracked actor)
 *   3–10 pulses → medium
 *   < 3 pulses  → low
 */
function actorConfidence(pulseCount: number): Confidence {
  if (pulseCount > 10) return 'high';
  if (pulseCount >= 3) return 'medium';
  return 'low';
}

/**
 * Build actor + family pivot suggestions from pulse-level context.
 */
function suggestionsFromPulseContext(
  adversaries: string[],
  families: string[],
  pulseCount: number,
  sourceTool: string,
): PivotSuggestion[] {
  const s: PivotSuggestion[] = [];
  const aConf = actorConfidence(pulseCount);

  for (const actor of adversaries.slice(0, 3)) {
    s.push({
      type: 'actor',
      value: actor,
      reason: `Threat actor attributed to this indicator via OTX (${pulseCount} pulses)`,
      source_tool: sourceTool,
      confidence: aConf,
    });
  }
  for (const fam of families.slice(0, 3)) {
    s.push({
      type: 'family',
      value: fam,
      reason: `Malware family associated with this indicator in OTX`,
      source_tool: sourceTool,
      confidence: pulseCount >= 3 ? 'medium' : 'low',
    });
  }
  return s;
}

// ---------------------------------------------------------------------------
// Paginator
// ---------------------------------------------------------------------------

async function fetchAllIndicators(pulseId: string): Promise<OTXIndicator[]> {
  const all: OTXIndicator[] = [];
  let page    = 1;
  let hasMore = true;

  while (hasMore) {
    const res = await otxGet<OTXPulseIndicatorsResponse>(
      `/pulses/${pulseId}/indicators`,
      { limit: String(PAGE_LIMIT), page: String(page) },
    );
    all.push(...res.results);
    hasMore = res.next !== null && res.results.length === PAGE_LIMIT;
    page++;
    if (hasMore) await sleep(100);
  }

  return all;
}

// ---------------------------------------------------------------------------
// Indicator Pivoting
// ---------------------------------------------------------------------------

/**
 * Full IP enrichment — general context + pulse attribution.
 *
 * Pivots FROM: an IP address from network logs, advisory, or sandbox.
 * Pivots TO:   actors (confidence from pulse count), families (medium/low).
 * Cache:       2 hours (OTX_TTL)
 *
 * @example
 * const result = await otxPivotIP('45.33.32.156');
 */
export async function otxPivotIP(ip: string): Promise<IntelResult<EnrichedIPResult>> {
  return withCache(
    makeCacheKey('otx', 'ip', ip),
    async () => {
      try {
        const general = await otxGet<OTXIPGeneral>(
          `/indicators/IPv4/${encodeURIComponent(ip)}/general`,
        );

        const pulses      = general.pulse_info.pulses;
        const pulseCount  = general.pulse_info.count;
        const adversaries = extractAdversaries(pulses);
        const families    = extractMalwareFamilies(pulses);
        const techniques  = extractMitreTechniques(pulses);
        const tags        = extractTags(pulses);

        const enriched: EnrichedIPResult = {
          ip,
          pulse_count: pulseCount,
          reputation: general.reputation,
          country: general.country_name,
          asn: general.asn,
          adversaries,
          malware_families: families,
          mitre_techniques: techniques,
          tags,
          top_pulses: topPulses(pulses),
        };

        const suggestions = suggestionsFromPulseContext(adversaries, families, pulseCount, 'otxPivotIP');

        if (pulseCount > 10) {
          suggestions.push({
            type: 'ip',
            value: ip,
            reason: `High-reputation malicious IP (${pulseCount} OTX pulses) — investigate associated domains`,
            source_tool: 'otxPivotIP',
            confidence: 'high',
          });
        }

        return makeOk(enriched, suggestions);
      } catch (e) {
        return makeErr(e instanceof Error ? e.message : String(e));
      }
    },
    OTX_TTL,
  );
}

/**
 * Domain enrichment — general context + passive DNS resolution history.
 *
 * Pivots FROM: a domain from an advisory, phishing email, or C2 traffic.
 * Pivots TO:   historical IPs (medium if < 5, high if recurring), actors.
 * Cache:       2 hours
 *
 * @example
 * const result = await otxPivotDomain('evil.example.com');
 */
export async function otxPivotDomain(domain: string): Promise<IntelResult<EnrichedDomainResult>> {
  return withCache(
    makeCacheKey('otx', 'domain', domain),
    async () => {
      try {
        const [general, passiveDNS] = await Promise.all([
          otxGet<OTXDomainGeneral>(`/indicators/domain/${encodeURIComponent(domain)}/general`),
          otxGet<OTXDomainPassiveDNS>(`/indicators/domain/${encodeURIComponent(domain)}/passive_dns`),
        ]);

        const pulses      = general.pulse_info.pulses;
        const pulseCount  = general.pulse_info.count;
        const adversaries = extractAdversaries(pulses);
        const families    = extractMalwareFamilies(pulses);
        const techniques  = extractMitreTechniques(pulses);
        const tags        = extractTags(pulses);

        const passiveIPs = [
          ...new Set(
            passiveDNS.passive_dns.filter(r => r.record_type === 'A').map(r => r.address),
          ),
        ];

        const enriched: EnrichedDomainResult = {
          domain,
          pulse_count: pulseCount,
          adversaries,
          malware_families: families,
          mitre_techniques: techniques,
          passive_dns_ips: passiveIPs,
          tags,
          top_pulses: topPulses(pulses),
        };

        const suggestions = suggestionsFromPulseContext(adversaries, families, pulseCount, 'otxPivotDomain');

        // Passive DNS IPs → suggest IP pivots
        for (const ip of passiveIPs.slice(0, 5)) {
          // If there are fewer unique IPs, each is a more reliable lead
          const ipConf: Confidence = passiveIPs.length <= 3 ? 'high' : 'medium';
          suggestions.push({
            type: 'ip',
            value: ip,
            reason: `Historical A record for ${domain} — check if IP is malicious`,
            source_tool: 'otxPivotDomain',
            confidence: ipConf,
          });
        }

        return makeOk(enriched, suggestions);
      } catch (e) {
        return makeErr(e instanceof Error ? e.message : String(e));
      }
    },
    OTX_TTL,
  );
}

/**
 * File hash enrichment — general context + malware analysis.
 *
 * Pivots FROM: a SHA256/MD5/SHA1 hash from an AV alert, sandbox, or advisory.
 * Pivots TO:   imphash (high), families (medium/low), actors.
 * Cache:       2 hours
 *
 * @example
 * const result = await otxPivotHash('e3b0c44298fc1c149...');
 */
export async function otxPivotHash(hash: string): Promise<IntelResult<EnrichedHashResult>> {
  return withCache(
    makeCacheKey('otx', 'hash', hash),
    async () => {
      try {
        const [general, analysis] = await Promise.all([
          otxGet<OTXFileGeneral>(`/indicators/file/${encodeURIComponent(hash)}/general`),
          otxGet<OTXFileAnalysis>(`/indicators/file/${encodeURIComponent(hash)}/analysis`),
        ]);

        const pulses      = general.pulse_info.pulses;
        const pulseCount  = general.pulse_info.count;
        const adversaries = extractAdversaries(pulses);
        const families    = extractMalwareFamilies(pulses);
        const techniques  = extractMitreTechniques(pulses);
        const tags        = extractTags(pulses);

        let imphash: string | undefined;
        let fileType: string | undefined;

        try {
          const info = analysis.analysis?.info?.results;
          if (info) {
            imphash  = info.imphash;
            fileType = info.file_type;
          }
        } catch { /* analysis shape varies */ }

        const enriched: EnrichedHashResult = {
          hash,
          pulse_count: pulseCount,
          malware_families: families,
          mitre_techniques: techniques,
          adversaries,
          tags,
          imphash,
          file_type: fileType,
          top_pulses: topPulses(pulses),
        };

        const suggestions = suggestionsFromPulseContext(adversaries, families, pulseCount, 'otxPivotHash');

        if (imphash) {
          suggestions.push({
            type: 'imphash',
            value: imphash,
            reason: 'PE import hash from OTX analysis — find sibling samples in MalwareBazaar',
            source_tool: 'otxPivotHash',
            confidence: 'high', // imphash from analysis is always reliable
          });
        }

        return makeOk(enriched, suggestions);
      } catch (e) {
        return makeErr(e instanceof Error ? e.message : String(e));
      }
    },
    OTX_TTL,
  );
}

/**
 * URL enrichment — pulse context for a specific URL.
 *
 * Pivots FROM: a URL from an advisory, phishing lure, or proxy log.
 * Pivots TO:   host domain (medium), families (confidence from pulse count).
 * Cache:       2 hours
 *
 * @example
 * const result = await otxPivotURL('http://c2.evil.com/beacon');
 */
export async function otxPivotURL(url: string): Promise<IntelResult<EnrichedURLResult>> {
  return withCache(
    makeCacheKey('otx', 'url', url),
    async () => {
      try {
        const general = await otxGet<OTXURLGeneral>('/indicators/url/general', {
          url: encodeURIComponent(url),
        });

        const pulses      = general.pulse_info.pulses;
        const pulseCount  = general.pulse_info.count;
        const adversaries = extractAdversaries(pulses);
        const families    = extractMalwareFamilies(pulses);
        const tags        = extractTags(pulses);

        const enriched: EnrichedURLResult = {
          url,
          pulse_count: pulseCount,
          adversaries,
          malware_families: families,
          tags,
          top_pulses: topPulses(pulses),
        };

        const suggestions = suggestionsFromPulseContext(adversaries, families, pulseCount, 'otxPivotURL');

        try {
          const host = new URL(url).hostname;
          suggestions.push({
            type: 'domain',
            value: host,
            reason: `Domain hosting this URL — check passive DNS history`,
            source_tool: 'otxPivotURL',
            confidence: 'medium',
          });
        } catch { /* URL parsing failed */ }

        return makeOk(enriched, suggestions);
      } catch (e) {
        return makeErr(e instanceof Error ? e.message : String(e));
      }
    },
    OTX_TTL,
  );
}

// ---------------------------------------------------------------------------
// Actor & Campaign Intelligence
// ---------------------------------------------------------------------------

/**
 * Search for all OTX pulses attributed to an actor name.
 * Deduplicates IOCs across pulses and returns a single enriched actor profile.
 *
 * Pivots FROM: an actor name from a threat report, ThreatFox, or OTX pulse.
 * Pivots TO:   top C2 IPs (high if pulse_count > 10, else medium),
 *              top domains (medium), malware families (medium).
 * Cache:       2 hours
 *
 * @example
 * const result = await otxSearchActor('APT29');
 */
export async function otxSearchActor(actorName: string): Promise<IntelResult<EnrichedActorResult>> {
  return withCache(
    makeCacheKey('otx', 'actor', actorName),
    async () => {
      try {
        const raw = await otxGet<OTXSearchPulsesResponse>('/search/pulses', {
          q: actorName,
          limit: '20',
          page: '1',
        });

        if (raw.results.length === 0) {
          return makeOk<EnrichedActorResult>(
            {
              actor: actorName,
              pulse_count: 0,
              ioc_count: 0,
              iocs_by_type: {},
              malware_families: [],
              mitre_techniques: [],
              targeted_countries: [],
              industries: [],
              tags: [],
            },
            [],
          );
        }

        // Fetch full indicators for each pulse (100ms delay)
        const pulsesWithIndicators: OTXPulseWithIndicators[] = [];
        for (const pulse of raw.results) {
          await sleep(100);
          try {
            const indicators = await fetchAllIndicators(pulse.id);
            pulsesWithIndicators.push({ ...pulse, indicators });
          } catch {
            pulsesWithIndicators.push({ ...pulse, indicators: pulse.indicators ?? [] });
          }
        }

        // Deduplicate IOCs across all pulses
        const iocMap = new Map<string, NormalizedIOC>();

        for (const pulse of pulsesWithIndicators) {
          for (const indicator of pulse.indicators) {
            const key     = indicator.indicator.toLowerCase();
            const iocType = mapOTXIndicatorType(indicator.type);
            if (!iocType) continue;

            const existing = iocMap.get(key);
            if (existing) {
              if (!existing.sources.includes('otx:' + pulse.id)) {
                existing.sources.push('otx:' + pulse.id);
              }
              existing.confidence = scoreConfidence(existing.sources.length);
            } else {
              iocMap.set(key, {
                type: iocType,
                value: indicator.indicator,
                confidence: 'low',
                sources: ['otx:' + pulse.id],
                first_seen: indicator.created,
                tags: pulse.tags,
                malware_family: pulse.malware_families[0]?.id,
                mitre_techniques: pulse.attack_ids
                  .map(a => a.id)
                  .filter(id => /^T\d{4}/.test(id)),
              });
            }
          }
        }

        const allIOCs = [...iocMap.values()].map(ioc => ({
          ...ioc,
          confidence: scoreConfidence(ioc.sources.length),
        }));

        const iocsByType: Record<string, NormalizedIOC[]> = {};
        for (const ioc of allIOCs) {
          if (!iocsByType[ioc.type]) iocsByType[ioc.type] = [];
          iocsByType[ioc.type].push(ioc);
        }
        for (const type of Object.keys(iocsByType)) {
          iocsByType[type].sort(
            (a, b) => confidenceRank(b.confidence) - confidenceRank(a.confidence),
          );
        }

        const allPulses  = raw.results;
        const families   = extractMalwareFamilies(allPulses);
        const techniques = extractMitreTechniques(allPulses);
        const countries  = [...new Set(allPulses.flatMap(p => p.targeted_countries))];
        const industries = [...new Set(allPulses.flatMap(p => p.industries))];
        const tags       = extractTags(allPulses);

        const enriched: EnrichedActorResult = {
          actor: actorName,
          pulse_count: raw.count,
          ioc_count: iocMap.size,
          iocs_by_type: iocsByType,
          malware_families: families,
          mitre_techniques: techniques,
          targeted_countries: countries,
          industries,
          tags,
        };

        const suggestions: PivotSuggestion[] = [];
        const actorConf: Confidence = actorConfidence(raw.count);

        for (const ioc of (iocsByType['ip'] ?? []).slice(0, 5)) {
          suggestions.push({
            type: 'ip',
            value: ioc.value,
            reason: `${actorName} C2 infrastructure (seen in ${ioc.sources.length} pulses)`,
            source_tool: 'otxSearchActor',
            confidence: ioc.confidence === 'high' ? 'high' : actorConf,
          });
        }
        for (const ioc of (iocsByType['domain'] ?? []).slice(0, 5)) {
          suggestions.push({
            type: 'domain',
            value: ioc.value,
            reason: `${actorName} domain (seen in ${ioc.sources.length} pulses)`,
            source_tool: 'otxSearchActor',
            confidence: ioc.confidence,
          });
        }
        for (const fam of families.slice(0, 3)) {
          suggestions.push({
            type: 'family',
            value: fam,
            reason: `Malware used by ${actorName}`,
            source_tool: 'otxSearchActor',
            confidence: 'medium',
          });
        }

        return makeOk(enriched, suggestions);
      } catch (e) {
        return makeErr(e instanceof Error ? e.message : String(e));
      }
    },
    OTX_TTL,
  );
}

/**
 * Retrieve all indicators from a specific OTX pulse (auto-paginated).
 *
 * Pivots FROM: a pulse ID from a search or shared report.
 * Pivots TO:   individual IOC types for further enrichment.
 * Cache:       2 hours
 *
 * @example
 * const result = await otxGetPulseIOCs('5b76c4a577c5c560e1000001');
 */
export async function otxGetPulseIOCs(
  pulseId: string,
): Promise<IntelResult<NormalizedIOC[]>> {
  return withCache(
    makeCacheKey('otx', 'pulse', pulseId),
    async () => {
      try {
        const raw = await fetchAllIndicators(pulseId);

        const seen = new Map<string, NormalizedIOC>();
        for (const indicator of raw) {
          const iocType = mapOTXIndicatorType(indicator.type);
          if (!iocType) continue;
          const key = indicator.indicator.toLowerCase();
          if (!seen.has(key)) {
            seen.set(key, {
              type: iocType,
              value: indicator.indicator,
              confidence: 'low',
              sources: [`otx:${pulseId}`],
              first_seen: indicator.created,
              tags: [],
            });
          }
        }

        const iocs = [...seen.values()];

        const byType: Record<string, NormalizedIOC[]> = {};
        for (const ioc of iocs) {
          if (!byType[ioc.type]) byType[ioc.type] = [];
          byType[ioc.type].push(ioc);
        }

        const suggestions: PivotSuggestion[] = [];
        for (const [type, group] of Object.entries(byType)) {
          for (const ioc of group.slice(0, 3)) {
            suggestions.push({
              type: ioc.type,
              value: ioc.value,
              reason: `IOC from pulse ${pulseId} — enrich with pivot function`,
              source_tool: 'otxGetPulseIOCs',
              confidence: 'medium',
            });
          }
          void type; // suppress unused-var lint
        }

        return makeOk(iocs, suggestions);
      } catch (e) {
        return makeErr(e instanceof Error ? e.message : String(e));
      }
    },
    OTX_TTL,
  );
}

/**
 * Fetch subscribed pulses modified since a given timestamp.
 * Used for ambient intel sync — run on a schedule (e.g. hourly).
 * NOT cached — time-sensitive by definition.
 *
 * @example
 * const since = new Date(Date.now() - 3600 * 1000); // last hour
 * const result = await otxSubscribedPulsesFeed(since);
 */
export async function otxSubscribedPulsesFeed(
  since: Date,
): Promise<IntelResult<OTXPulseWithIndicators[]>> {
  // Deliberately NOT cached — the caller wants pulses since a specific timestamp
  try {
    const modified_since = since.toISOString();
    const allPulses: OTXPulseWithIndicators[] = [];
    let page    = 1;
    let hasMore = true;

    while (hasMore) {
      const raw = await otxGet<OTXSearchPulsesResponse>('/pulses/subscribed', {
        modified_since,
        limit: '20',
        page: String(page),
      });
      allPulses.push(...raw.results);
      hasMore = raw.next !== null && raw.results.length === 20;
      page++;
      if (hasMore) await sleep(100);
    }

    const suggestions: PivotSuggestion[] = [];
    const seenActor  = new Set<string>();
    const seenFamily = new Set<string>();

    for (const pulse of allPulses) {
      if (pulse.adversary && !seenActor.has(pulse.adversary)) {
        seenActor.add(pulse.adversary);
        suggestions.push({
          type: 'actor',
          value: pulse.adversary,
          reason: `New pulse from ${pulse.author_name} attributed to ${pulse.adversary}`,
          source_tool: 'otxSubscribedPulsesFeed',
          // New pulses are medium by default until corroborated
          confidence: 'medium',
        });
      }
      for (const fam of pulse.malware_families) {
        if (!seenFamily.has(fam.id)) {
          seenFamily.add(fam.id);
          suggestions.push({
            type: 'family',
            value: fam.id,
            reason: 'Malware family in new subscribed pulse',
            source_tool: 'otxSubscribedPulsesFeed',
            confidence: 'medium',
          });
        }
      }
    }

    return {
      source: 'otx',
      success: true,
      data: allPulses,
      queried_at: new Date().toISOString(),
      pivot_suggestions: deduplicateSuggestions(suggestions),
    };
  } catch (e) {
    return makeErr(e instanceof Error ? e.message : String(e));
  }
}

// ---------------------------------------------------------------------------
// Type mapping utilities
// ---------------------------------------------------------------------------

function mapOTXIndicatorType(otxType: string): NormalizedIOC['type'] | null {
  switch (otxType.toLowerCase()) {
    case 'ipv4':
    case 'ipv6':
    case 'cidr':
      return 'ip';
    case 'domain':
    case 'hostname':
      return 'domain';
    case 'url':
      return 'url';
    case 'filehash-md5':
    case 'filehash-sha1':
    case 'filehash-sha256':
      return 'hash';
    default:
      return null;
  }
}

function scoreConfidence(sourceCount: number): NormalizedIOC['confidence'] {
  if (sourceCount >= 3) return 'high';
  if (sourceCount >= 2) return 'medium';
  return 'low';
}

function confidenceRank(c: NormalizedIOC['confidence']): number {
  return c === 'high' ? 3 : c === 'medium' ? 2 : 1;
}
