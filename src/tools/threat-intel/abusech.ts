/**
 * abuse.ch Integration Module
 *
 * Provides functions for querying three abuse.ch services:
 *  - URLhaus  : malicious URL intelligence
 *  - ThreatFox: IOC intelligence with confidence scoring
 *  - MalwareBazaar: malware sample database with imphash pivoting
 *
 * No API key required. No strict rate limits, but retries on HTTP 429.
 * All functions return IntelResult<T> — never throw.
 *
 * Caching: every successful result is stored for ABUSECH_TTL (30 min).
 */

import type {
  IntelResult,
  PivotSuggestion,
  Confidence,
  UrlhausURLResult,
  UrlhausHostResult,
  UrlhausTagResult,
  UrlhausURLEntry,
  UrlhausPayload,
  ThreatFoxIOC,
  ThreatFoxApiResponse,
  MalwareBazaarSample,
  MalwareBazaarApiResponse,
} from './types.js';

import { withCache, makeCacheKey, ABUSECH_TTL } from './cache.js';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const URLHAUS_BASE   = 'https://urlhaus-api.abuse.ch/v1';
const THREATFOX_BASE = 'https://threatfox-api.abuse.ch/api/v1';
const BAZAAR_BASE    = 'https://mb-api.abuse.ch/api/v1';

/** Sleep for ms milliseconds */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * POST with application/x-www-form-urlencoded body.
 * Retries once on HTTP 429 after a 2-second back-off.
 */
async function postForm<T>(url: string, params: Record<string, string>): Promise<T> {
  const body = new URLSearchParams(params).toString();
  const opts: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  };
  let res = await fetch(url, opts);
  if (res.status === 429) {
    await sleep(2000);
    res = await fetch(url, opts);
  }
  if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText} from ${url}`);
  return res.json() as Promise<T>;
}

/**
 * POST with application/json body.
 * Retries once on HTTP 429 after a 2-second back-off.
 */
async function postJson<T>(url: string, payload: Record<string, unknown>): Promise<T> {
  const opts: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  };
  let res = await fetch(url, opts);
  if (res.status === 429) {
    await sleep(2000);
    res = await fetch(url, opts);
  }
  if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText} from ${url}`);
  return res.json() as Promise<T>;
}

/** Build the standard result envelope */
function makeOk<T>(
  source: IntelResult<T>['source'],
  data: T,
  suggestions: PivotSuggestion[],
): IntelResult<T> {
  return {
    source,
    success: true,
    data,
    queried_at: new Date().toISOString(),
    pivot_suggestions: deduplicateSuggestions(suggestions),
  };
}

function makeErr<T>(source: IntelResult<T>['source'], message: string): IntelResult<T> {
  return {
    source,
    success: false,
    data: null,
    error: message,
    queried_at: new Date().toISOString(),
    pivot_suggestions: [],
  };
}

// ---------------------------------------------------------------------------
// Pivot suggestion builders
// ---------------------------------------------------------------------------

/**
 * Given URLhaus payloads, generate hash + imphash pivot suggestions.
 * Confidence is 'high' for imphash (very reliable pivot) and 'medium' for hashes.
 */
function payloadSuggestions(payloads: UrlhausPayload[]): PivotSuggestion[] {
  const suggestions: PivotSuggestion[] = [];
  const seenImphash = new Set<string>();
  const seenHash    = new Set<string>();

  for (const p of payloads) {
    if (p.response_sha256 && !seenHash.has(p.response_sha256)) {
      seenHash.add(p.response_sha256);
      suggestions.push({
        type: 'hash',
        value: p.response_sha256,
        reason: `Payload SHA256 delivered by this URL (filename: ${p.filename ?? 'unknown'})`,
        source_tool: 'urlhausLookupURL',
        confidence: 'medium',
      });
    }
    if (p.imphash && !seenImphash.has(p.imphash)) {
      seenImphash.add(p.imphash);
      suggestions.push({
        type: 'imphash',
        value: p.imphash,
        reason: 'PE import hash in URL payload — pivot to find sibling samples',
        source_tool: 'urlhausLookupURL',
        confidence: 'high', // imphash pivots are always high-value
      });
    }
    if (p.signature) {
      suggestions.push({
        type: 'family',
        value: p.signature,
        reason: `Payload identified as ${p.signature} by URLhaus signature`,
        source_tool: 'urlhausLookupURL',
        confidence: 'medium',
      });
    }
  }
  return suggestions;
}

/** Extract tag-based suggestions from a list of URLhaus URL entries. */
function tagSuggestionsFromURLEntries(
  entries: UrlhausURLEntry[],
  toolName: string,
): PivotSuggestion[] {
  const seen = new Set<string>();
  const suggestions: PivotSuggestion[] = [];
  for (const entry of entries) {
    for (const tag of entry.tags ?? []) {
      if (!seen.has(tag)) {
        seen.add(tag);
        suggestions.push({
          type: 'tag',
          value: tag,
          reason: `Malware tag observed on ${entry.url}`,
          source_tool: toolName,
          confidence: 'medium',
        });
      }
    }
  }
  return suggestions;
}

/**
 * Suggestions from a ThreatFox IOC result.
 * Confidence maps directly from ThreatFox's own confidence_level field.
 */
function threatFoxSuggestions(iocs: ThreatFoxIOC[], sourceTool: string): PivotSuggestion[] {
  const suggestions: PivotSuggestion[] = [];
  const seenFamily = new Set<string>();

  for (const ioc of iocs) {
    if (ioc.malware_printable && !seenFamily.has(ioc.malware_printable)) {
      seenFamily.add(ioc.malware_printable);
      // Map ThreatFox's 0-100 score → our three-tier confidence
      const confidence: Confidence =
        ioc.confidence_level >= 75 ? 'high'
        : ioc.confidence_level >= 50 ? 'medium'
        : 'low';
      suggestions.push({
        type: 'family',
        value: ioc.malware_printable,
        reason: `Malware family from ThreatFox (confidence ${ioc.confidence_level}/100)`,
        source_tool: sourceTool,
        confidence,
      });
    }
  }
  return suggestions;
}

/**
 * Suggestions from MalwareBazaar samples.
 * Imphash is always 'high' (structural pivot). Family and tags are 'medium'.
 */
function bazaarSuggestions(samples: MalwareBazaarSample[], sourceTool: string): PivotSuggestion[] {
  const suggestions: PivotSuggestion[] = [];
  const seenImphash = new Set<string>();
  const seenFamily  = new Set<string>();

  for (const s of samples) {
    if (s.imphash && !seenImphash.has(s.imphash)) {
      seenImphash.add(s.imphash);
      suggestions.push({
        type: 'imphash',
        value: s.imphash,
        reason: 'Shared PE import hash — likely same malware build pipeline',
        source_tool: sourceTool,
        confidence: 'high',
      });
    }
    if (s.signature && !seenFamily.has(s.signature)) {
      seenFamily.add(s.signature);
      suggestions.push({
        type: 'family',
        value: s.signature,
        reason: `Malware family signature from MalwareBazaar`,
        source_tool: sourceTool,
        confidence: 'medium',
      });
    }
    for (const tag of s.tags ?? []) {
      suggestions.push({
        type: 'tag',
        value: tag,
        reason: `Sample tag in MalwareBazaar — may have ThreatFox entries`,
        source_tool: sourceTool,
        confidence: 'low', // tags are low signal on their own
      });
    }
  }

  // Deduplicate before returning
  const seen = new Set<string>();
  return suggestions.filter(s => {
    const key = `${s.type}:${s.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ---------------------------------------------------------------------------
// URLhaus
// ---------------------------------------------------------------------------

/**
 * Look up a single URL in URLhaus.
 *
 * Pivots FROM: a URL seen in an advisory or sandbox report.
 * Pivots TO:   payload hashes (medium), imphashes (high), families (medium).
 * Cache:       30 min (ABUSECH_TTL)
 *
 * @example
 * const result = await urlhausLookupURL('http://evil.example.com/payload.exe');
 * // Follow up: bazaarLookupHash on any high-confidence hash suggestions
 */
export async function urlhausLookupURL(url: string): Promise<IntelResult<UrlhausURLResult>> {
  return withCache(
    makeCacheKey('abusech', 'urlhaus:url', url),
    async () => {
      try {
        const raw = await postForm<UrlhausURLResult>(`${URLHAUS_BASE}/url/`, { url });

        if (raw.query_status === 'no_results' || raw.query_status === 'is_phishing') {
          return makeOk('urlhaus', raw, []);
        }

        const suggestions: PivotSuggestion[] = [];

        if (raw.payloads && raw.payloads.length > 0) {
          suggestions.push(...payloadSuggestions(raw.payloads));
        }

        try {
          const host = new URL(url).hostname;
          if (host) {
            suggestions.push({
              type: 'domain',
              value: host,
              reason: 'Host of this malicious URL — may serve other payloads',
              source_tool: 'urlhausLookupURL',
              confidence: 'medium',
            });
          }
        } catch { /* URL parsing failed */ }

        for (const tag of raw.tags ?? []) {
          suggestions.push({
            type: 'tag',
            value: tag,
            reason: `URLhaus tag "${tag}" — search ThreatFox for correlated IOCs`,
            source_tool: 'urlhausLookupURL',
            confidence: 'low',
          });
        }

        return makeOk('urlhaus', raw, suggestions);
      } catch (e) {
        return makeErr('urlhaus', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

/**
 * Look up all malicious URLs on a host (IP or FQDN) in URLhaus.
 *
 * Pivots FROM: an IP or domain from network logs or an advisory.
 * Pivots TO:   unique tags → ThreatFox tag searches (medium confidence).
 * Cache:       30 min
 *
 * @example
 * const result = await urlhausLookupHost('192.0.2.1');
 */
export async function urlhausLookupHost(host: string): Promise<IntelResult<UrlhausHostResult>> {
  return withCache(
    makeCacheKey('abusech', 'urlhaus:host', host),
    async () => {
      try {
        const raw = await postForm<UrlhausHostResult>(`${URLHAUS_BASE}/host/`, { host });

        if (raw.query_status === 'no_results' || raw.query_status === 'is_phishing') {
          return makeOk('urlhaus', raw, []);
        }

        const suggestions = tagSuggestionsFromURLEntries(raw.urls ?? [], 'urlhausLookupHost');
        return makeOk('urlhaus', raw, suggestions);
      } catch (e) {
        return makeErr('urlhaus', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

/**
 * Search URLhaus for all URLs associated with a malware tag.
 *
 * Pivots FROM: a malware family name or campaign tag.
 * Pivots TO:   unique hosting IPs (medium), family cross-reference (medium).
 * Cache:       30 min
 *
 * @example
 * const result = await urlhausLookupTag('qakbot');
 */
export async function urlhausLookupTag(tag: string): Promise<IntelResult<UrlhausTagResult>> {
  return withCache(
    makeCacheKey('abusech', 'urlhaus:tag', tag),
    async () => {
      try {
        const raw = await postForm<UrlhausTagResult>(`${URLHAUS_BASE}/tag/`, { tag });

        if (raw.query_status === 'no_results') {
          return makeOk('urlhaus', raw, []);
        }

        const suggestions: PivotSuggestion[] = [];
        const seenHost = new Set<string>();

        for (const entry of raw.urls ?? []) {
          try {
            const host = new URL(entry.url).hostname;
            if (host && !seenHost.has(host)) {
              seenHost.add(host);
              suggestions.push({
                type: 'domain',
                value: host,
                reason: `Host serving "${tag}" malware downloads`,
                source_tool: 'urlhausLookupTag',
                confidence: 'medium',
              });
            }
          } catch { /* skip unparseable */ }
        }

        suggestions.push({
          type: 'family',
          value: tag,
          reason: 'Search MalwareBazaar for samples with this tag',
          source_tool: 'urlhausLookupTag',
          confidence: 'medium',
        });

        return makeOk('urlhaus', raw, suggestions);
      } catch (e) {
        return makeErr('urlhaus', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

// ---------------------------------------------------------------------------
// ThreatFox
// ---------------------------------------------------------------------------

/**
 * Search ThreatFox for any IOC type (IP:port, domain, URL, MD5, SHA256).
 *
 * Pivots FROM: any IOC extracted from an advisory.
 * Pivots TO:   malware family (confidence mapped from ThreatFox confidence_level).
 * Cache:       30 min
 *
 * @example
 * const result = await threatfoxSearchIOC('192.0.2.1:4444');
 */
export async function threatfoxSearchIOC(ioc: string): Promise<IntelResult<ThreatFoxIOC[]>> {
  return withCache(
    makeCacheKey('abusech', 'threatfox:ioc', ioc),
    async () => {
      try {
        const raw = await postJson<ThreatFoxApiResponse>(THREATFOX_BASE, {
          query: 'search_ioc',
          search_term: ioc,
        });
        const iocs = raw.data ?? [];
        return makeOk('threatfox', iocs, threatFoxSuggestions(iocs, 'threatfoxSearchIOC'));
      } catch (e) {
        return makeErr('threatfox', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

/**
 * Search ThreatFox for all IOCs associated with a malware family.
 *
 * Pivots FROM: a malware family name.
 * Pivots TO:   C2 IPs (confidence = family's confidence, ≥75 → high), payload hashes.
 * Cache:       30 min
 *
 * @example
 * const result = await threatfoxSearchFamily('AgentTesla');
 */
export async function threatfoxSearchFamily(family: string): Promise<IntelResult<ThreatFoxIOC[]>> {
  return withCache(
    makeCacheKey('abusech', 'threatfox:family', family),
    async () => {
      try {
        const raw = await postJson<ThreatFoxApiResponse>(THREATFOX_BASE, {
          query: 'search_malware',
          malware_family: family,
        });
        const iocs = raw.data ?? [];

        const suggestions: PivotSuggestion[] = [];
        const seenIP   = new Set<string>();
        const seenHash = new Set<string>();

        for (const ioc of iocs) {
          const confidence: Confidence =
            ioc.confidence_level >= 75 ? 'high'
            : ioc.confidence_level >= 50 ? 'medium'
            : 'low';

          if (ioc.ioc_type === 'ip:port') {
            const ip = ioc.ioc.split(':')[0];
            if (ip && !seenIP.has(ip)) {
              seenIP.add(ip);
              suggestions.push({
                type: 'ip',
                value: ip,
                reason: `${family} C2 server (ThreatFox confidence ${ioc.confidence_level}/100)`,
                source_tool: 'threatfoxSearchFamily',
                confidence,
              });
            }
          }
          if (ioc.ioc_type === 'sha256_hash' && !seenHash.has(ioc.ioc)) {
            seenHash.add(ioc.ioc);
            suggestions.push({
              type: 'hash',
              value: ioc.ioc,
              reason: `${family} payload SHA256`,
              source_tool: 'threatfoxSearchFamily',
              confidence,
            });
          }
        }

        return makeOk('threatfox', iocs, suggestions);
      } catch (e) {
        return makeErr('threatfox', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

/**
 * Search ThreatFox by tag.
 *
 * Pivots FROM: a campaign or role tag (e.g. "c2", "loader", "rat").
 * Pivots TO:   families (confidence mapped from ThreatFox confidence_level).
 * Cache:       30 min
 *
 * @example
 * const result = await threatfoxSearchTag('c2');
 */
export async function threatfoxSearchTag(tag: string): Promise<IntelResult<ThreatFoxIOC[]>> {
  return withCache(
    makeCacheKey('abusech', 'threatfox:tag', tag),
    async () => {
      try {
        const raw = await postJson<ThreatFoxApiResponse>(THREATFOX_BASE, {
          query: 'search_tag',
          tag,
        });
        const iocs = raw.data ?? [];
        return makeOk('threatfox', iocs, threatFoxSuggestions(iocs, 'threatfoxSearchTag'));
      } catch (e) {
        return makeErr('threatfox', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

/**
 * Retrieve ThreatFox recent IOC feed for the last N days.
 * NOT cached — recent feed is always fresh data.
 *
 * Pivots FROM: ambient threat intel sync.
 * Pivots TO:   high-confidence IOCs → hash lookups, family searches.
 *
 * @example
 * const result = await threatfoxGetRecentIOCs(1);
 */
export async function threatfoxGetRecentIOCs(
  days: 1 | 7 | 30,
): Promise<IntelResult<ThreatFoxIOC[]>> {
  // Deliberately NOT cached — the caller wants the freshest feed data
  try {
    const raw = await postJson<ThreatFoxApiResponse>(THREATFOX_BASE, {
      query: 'get_iocs',
      days,
    });
    const iocs = raw.data ?? [];

    // Only surface high-confidence suggestions from the ambient feed
    const highConf = iocs.filter(i => i.confidence_level >= 75);
    const suggestions: PivotSuggestion[] = highConf.slice(0, 10).map(i => ({
      type: (
        i.ioc_type === 'sha256_hash' || i.ioc_type === 'md5_hash' ? 'hash'
        : i.ioc_type === 'ip:port' ? 'ip'
        : 'domain'
      ) as PivotSuggestion['type'],
      value: i.ioc_type === 'ip:port' ? i.ioc.split(':')[0] : i.ioc,
      reason: `High-confidence recent IOC (${i.confidence_level}/100) for ${i.malware_printable}`,
      source_tool: 'threatfoxGetRecentIOCs',
      confidence: 'high' as Confidence,
    }));

    return makeOk('threatfox', iocs, suggestions);
  } catch (e) {
    return makeErr('threatfox', e instanceof Error ? e.message : String(e));
  }
}

// ---------------------------------------------------------------------------
// MalwareBazaar
// ---------------------------------------------------------------------------

/**
 * Look up a malware sample by SHA256, MD5, or SHA1.
 *
 * Pivots FROM: a file hash from an advisory, sandbox, or AV alert.
 * Pivots TO:   imphash (high), malware family (medium).
 * Cache:       30 min
 *
 * @example
 * const result = await bazaarLookupHash('e3b0c44298fc1c149afb...');
 */
export async function bazaarLookupHash(
  hash: string,
): Promise<IntelResult<MalwareBazaarSample[]>> {
  return withCache(
    makeCacheKey('abusech', 'bazaar:hash', hash),
    async () => {
      try {
        const raw = await postForm<MalwareBazaarApiResponse>(`${BAZAAR_BASE}/`, {
          query: 'get_info',
          hash,
        });
        if (raw.query_status !== 'ok' || !raw.data?.length) {
          return makeOk('malwarebazaar', [], []);
        }
        return makeOk('malwarebazaar', raw.data, bazaarSuggestions(raw.data, 'bazaarLookupHash'));
      } catch (e) {
        return makeErr('malwarebazaar', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

/**
 * Search MalwareBazaar for all samples matching a malware family / signature.
 *
 * Pivots FROM: a malware family name.
 * Pivots TO:   unique imphashes (high) → sibling samples.
 * Cache:       30 min
 *
 * @example
 * const result = await bazaarSearchFamily('Emotet');
 */
export async function bazaarSearchFamily(
  family: string,
  limit = 50,
): Promise<IntelResult<MalwareBazaarSample[]>> {
  return withCache(
    makeCacheKey('abusech', `bazaar:family:${limit}`, family),
    async () => {
      try {
        const raw = await postForm<MalwareBazaarApiResponse>(`${BAZAAR_BASE}/`, {
          query: 'get_siginfo',
          signature: family,
          limit: String(limit),
        });
        const samples = raw.data ?? [];
        return makeOk('malwarebazaar', samples, bazaarSuggestions(samples, 'bazaarSearchFamily'));
      } catch (e) {
        return makeErr('malwarebazaar', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

/**
 * Search MalwareBazaar for all samples with a specific tag.
 *
 * Pivots FROM: a campaign or capability tag.
 * Pivots TO:   malware families (medium), imphashes (high).
 * Cache:       30 min
 *
 * @example
 * const result = await bazaarSearchTag('keylogger');
 */
export async function bazaarSearchTag(
  tag: string,
  limit = 50,
): Promise<IntelResult<MalwareBazaarSample[]>> {
  return withCache(
    makeCacheKey('abusech', `bazaar:tag:${limit}`, tag),
    async () => {
      try {
        const raw = await postForm<MalwareBazaarApiResponse>(`${BAZAAR_BASE}/`, {
          query: 'get_taginfo',
          tag,
          limit: String(limit),
        });
        const samples = raw.data ?? [];
        return makeOk('malwarebazaar', samples, bazaarSuggestions(samples, 'bazaarSearchTag'));
      } catch (e) {
        return makeErr('malwarebazaar', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

/**
 * Retrieve the most recent MalwareBazaar submissions.
 * NOT cached — the caller wants the freshest feed data.
 *
 * Pivots FROM: ambient threat intel sync.
 * Pivots TO:   new families → family searches.
 *
 * @example
 * const result = await bazaarGetRecentSamples(25);
 */
export async function bazaarGetRecentSamples(
  limit: number,
): Promise<IntelResult<MalwareBazaarSample[]>> {
  const clampedLimit = Math.max(1, Math.min(limit, 100));
  // Deliberately NOT cached — ambient feed should always be fresh
  try {
    const raw = await postForm<MalwareBazaarApiResponse>(`${BAZAAR_BASE}/`, {
      query: 'get_recent',
      selector: 'time',
    });
    const samples = (raw.data ?? []).slice(0, clampedLimit);
    return makeOk('malwarebazaar', samples, bazaarSuggestions(samples.slice(0, 5), 'bazaarGetRecentSamples'));
  } catch (e) {
    return makeErr('malwarebazaar', e instanceof Error ? e.message : String(e));
  }
}

/**
 * Pivot on PE import hash (imphash) to find samples compiled from the same codebase.
 *
 * This is the ELITE pivot function — imphash links PE samples built from identical
 * source code, even when re-compiled. Finds sibling variants the actor forgot to
 * randomise.
 *
 * Pivots FROM: an imphash from bazaarLookupHash or OTX file analysis.
 * Pivots TO:   sibling SHA256 hashes (medium), attributed family (medium → high if unique).
 * Cache:       30 min
 *
 * @example
 * const result = await bazaarGetImphashSiblings('1234abcd...');
 */
export async function bazaarGetImphashSiblings(
  imphash: string,
  limit = 50,
): Promise<IntelResult<MalwareBazaarSample[]>> {
  return withCache(
    makeCacheKey('abusech', `bazaar:imphash:${limit}`, imphash),
    async () => {
      try {
        const raw = await postForm<MalwareBazaarApiResponse>(`${BAZAAR_BASE}/`, {
          query: 'get_imphash',
          imphash,
          limit: String(limit),
        });
        const samples = raw.data ?? [];

        const suggestions: PivotSuggestion[] = [];
        const seenFamily = new Set<string>();
        const seenHash   = new Set<string>();

        for (const s of samples) {
          if (s.signature && !seenFamily.has(s.signature)) {
            seenFamily.add(s.signature);
            suggestions.push({
              type: 'family',
              value: s.signature,
              reason: `Imphash sibling samples attributed to ${s.signature}`,
              source_tool: 'bazaarGetImphashSiblings',
              // If there's only one family across siblings → very reliable
              confidence: 'high',
            });
          }
          if (!seenHash.has(s.sha256_hash)) {
            seenHash.add(s.sha256_hash);
            suggestions.push({
              type: 'hash',
              value: s.sha256_hash,
              reason: `Sibling PE sample (same imphash ${imphash.substring(0, 8)}…)`,
              source_tool: 'bazaarGetImphashSiblings',
              confidence: 'medium',
            });
          }
        }

        return makeOk('malwarebazaar', samples, deduplicateSuggestions(suggestions));
      } catch (e) {
        return makeErr('malwarebazaar', e instanceof Error ? e.message : String(e));
      }
    },
    ABUSECH_TTL,
  );
}

// ---------------------------------------------------------------------------
// Shared utility
// ---------------------------------------------------------------------------

function deduplicateSuggestions(suggestions: PivotSuggestion[]): PivotSuggestion[] {
  const seen = new Set<string>();
  return suggestions.filter(s => {
    const key = `${s.type}:${s.value.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
