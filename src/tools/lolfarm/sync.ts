// LOLFarm live sync — pulls fresh data from upstream sources into the SQLite cache.
// Each fetcher is independent: a failure in one source never blocks the others.

import {
  cacheLOLDriver, cacheHijackLib, cacheLOLRMM,
  cacheLoFP, cacheWADCom, cacheLOTS, cacheMalAPI,
  LOLDriverEntry, HijackLibEntry, LOLRMMEntry,
  LoFPEntry, WADComEntry, LOTSEntry, MalAPIEntry,
  updateSyncStatus,
} from '../../db/lolfarm.js';
import { cacheLOLBAS, LOLBASEntry } from '../../db/threat-intel.js';
import { saveDb, runQuery } from '../../db/connection.js';
import { parse as parseYaml } from 'yaml';

// ---------------------------------------------------------------------------
// Upstream endpoints
// ---------------------------------------------------------------------------

// Four of these were wrong when this file was written — all four 404'd, and the
// repository paths they named do not exist. They were replaced only after the
// real upstream was located and its response shape inspected, because guessing
// a plausible-looking raw.githubusercontent path is how they broke in the
// first place. Verified against live responses on 2026-09-10; the status column
// records what each one actually returned.
const SOURCES = {
  drivers:    'https://www.loldrivers.io/api/drivers.json',           // 200, 687 entries
  hijacklibs: 'https://hijacklibs.net/api/hijacklibs.json',
  rmm:        'https://lolrmm.io/api/rmm_tools.json',                 // 200, 323 entries
  // LoFP is a Hugo site whose config declares home = ["HTML", "RSS", "JSON"],
  // so index.json is the whole dataset in one request: 3,360 pages, 1.4 MB.
  // Not SigmaHQ — the project is Justin Ibarra's, published from brokensound77.
  // Note the baseURL in docs/hugo.toml claims lofp.github.io, which 404s; the
  // site is actually served from the owner's user pages.
  lofp:       'https://brokensound77.github.io/LoFP/index.json',      // 200, 3,360 entries
  lolbas:     'https://lolbas-project.github.io/api/lolbas.json',     // 200, 244 entries
  // WADComs publishes no JSON. It is a Jekyll site whose content is one
  // Markdown file per technique with YAML front matter, so the "endpoint" is a
  // directory listing plus one raw fetch per entry — see fetchWADComs below.
  wadcoms:    'https://api.github.com/repos/WADComs/WADComs.github.io/contents/_wadcoms',
} as const;

/**
 * Sources with no machine-readable upstream, and what was actually checked.
 *
 * These are not transient failures, and reporting them as failures was
 * misleading: it invited retries against endpoints that will never exist, and
 * buried three permanent gaps among ordinary network noise. `syncOne` now
 * short-circuits them with a `no_upstream` status carrying the reason.
 *
 * Two of the three are worse than a plain 404 — lots-project.com and malapi.io
 * answer an unknown path with **HTTP 200 and an HTML page**. A URL guessed at
 * either host therefore fails inside `res.json()` with a syntax error about
 * an unexpected `<`, which reads like a corrupt payload rather than a wrong
 * path. `fetchJson` now rejects an HTML body explicitly for that reason.
 */
const NO_UPSTREAM: Record<string, string> = {
  lots:
    'No public data repository or API. lots-project.com serves HTML and returns ' +
    '200 for unknown paths; site URLs are hex-encoded (/site/2a2e6769746875622e696f). ' +
    'Only third-party re-exports exist, which would make freshness someone else\'s.',
  malapi:
    'No official repository or API. malapi.io serves HTML and returns 200 for ' +
    'unknown paths. Existing consumers (MalAPIReader, MalAPI-Hunter) each keep a ' +
    'private scrape, so adopting one would vendor a snapshot of unknown vintage.',
};

type SourceName = keyof typeof SOURCES | keyof typeof NO_UPSTREAM;

const FETCH_TIMEOUT_MS = 30_000;
const USER_AGENT = 'harris-hawkeye-mcp/1.0 (+lolfarm-sync)';

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

async function fetchJson<T = unknown>(url: string): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': USER_AGENT, 'Accept': 'application/json' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);

    // Guard against a soft 404 — a 200 carrying the site's HTML shell instead of
    // the requested resource. Several of these hosts do exactly that, and letting
    // it reach res.json() produces "Unexpected token '<'", which reads like a
    // corrupt payload rather than a wrong URL. Check the body, not just the
    // Content-Type: a static host will happily label an HTML 404 page as JSON.
    const body = await res.text();
    const head = body.trimStart().slice(0, 200).toLowerCase();
    if (head.startsWith('<!doctype') || head.startsWith('<html') || head.startsWith('<?xml')) {
      throw new Error(
        `expected JSON but got markup (HTTP ${res.status}, ${body.length} bytes) — ` +
        'the path is probably wrong; this host answers unknown paths with a page'
      );
    }
    try {
      return JSON.parse(body) as T;
    } catch (e) {
      throw new Error(`malformed JSON (${body.length} bytes): ${(e as Error).message}`);
    }
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function toStringArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string' && Boolean(x));
  if (typeof v === 'string' && v) return [v];
  return [];
}

// ---------------------------------------------------------------------------
// Per-source mappers — upstream shape → DB entry shape
// ---------------------------------------------------------------------------

function mapDriver(raw: Record<string, unknown>): LOLDriverEntry | null {
  const tags = raw.Tags as string[] | undefined;
  const samples = raw.KnownVulnerableSamples as Array<Record<string, unknown>> | undefined;
  const first = samples?.[0] ?? {};
  const id = (raw.Id as string) || (first.SHA256 as string);
  const name = (first.Filename as string) || (raw.Filename as string) || (raw.Name as string) ||
    (id ? `driver-${id.slice(0, 8)}` : undefined);
  if (!id || !name) return null;
  return {
    id,
    name,
    description: (raw.Description as string) || (first.Description as string),
    category: (raw.Category as string) || ((tags?.includes('malicious') ? 'malicious' : 'vulnerable')),
    hashes: {
      md5: first.MD5 as string,
      sha1: first.SHA1 as string,
      sha256: first.SHA256 as string,
      authentihash_sha256: first.Authentihash as string,
    },
    cve: toStringArray(first.CVE ?? raw.CVE),
    mitre_techniques: toStringArray(raw.MitreID),
    verified: raw.Verified === 'TRUE' || raw.Verified === true,
    resources: (raw.Resources as string[]) || [],
  };
}

function mapHijackLib(raw: Record<string, unknown>): HijackLibEntry | null {
  const name = raw.Name as string;
  if (!name) return null;
  const exes = (raw.VulnerableExecutables as Array<Record<string, unknown>> | undefined) ?? [];
  return {
    name,
    vendor: raw.Author as string,
    expected_locations: (raw.ExpectedLocations as string[]) || [],
    vulnerable_executables: exes.map(e => ({
      path: e.Path as string,
      type: (e.Type as HijackLibEntry['vulnerable_executables'] extends Array<infer U> | undefined ? U extends { type: infer T } ? T : never : never) || 'Sideloading',
      auto_elevate: e.AutoElevate as boolean,
      privilege_escalation: e.PrivilegeEscalation as boolean,
      condition: e.Condition as string,
    })),
    hijack_type: exes[0]?.Type as string,
    resources: (raw.Resources as string[]) || [],
  };
}

function mapRMM(raw: Record<string, unknown>): LOLRMMEntry | null {
  const name = (raw.Name as string) || (raw.Tool as string);
  if (!name) return null;
  const details = (raw.Details as Record<string, unknown>) ?? raw;
  return {
    name,
    vendor: (details.Vendor as string) || (raw.Vendor as string),
    description: (details.Description as string) || (raw.Description as string),
    executable_names: toStringArray(details.Filenames ?? details.Filename ?? raw.Filenames ?? raw.Filename),
    network_artifacts: {
      domains: toStringArray(details.Domains ?? details.Domain),
      ports: (details.Ports as number[]) || [],
      user_agents: toStringArray(details.UserAgents ?? details.UserAgent),
    },
    registry_artifacts: toStringArray(details.Registry),
    detection_guidance: (details.Detection as string) || (raw.Detection as string),
    mitre_techniques: toStringArray(raw.MitreID ?? details.MitreID),
    abuse_references: toStringArray(raw.Acknowledgement ?? raw.References ?? details.References),
  };
}

// --- LoFP -------------------------------------------------------------------
//
// The upstream is a Hugo search index, not a purpose-built API, so the shape is
// a page listing rather than a false-positive record:
//
//   { title: "- legitimate administrator scripts. filter known parent images.",
//     description: "",                       // always empty
//     permalink: "/LoFP/legitimate-admin.../",
//     tags: [ { title: "t1059.001", permalink: … }, { title: "sigma", … } ] }
//
// `title` is the false-positive text; `description` is never populated. `tags`
// mixes three kinds of value that have to be told apart by pattern, because
// Hugo flattens all taxonomies into one list: ATT&CK ids (t1059.001), rule
// sources (sigma, splunk, elastic) and platforms (windows, aws, azure, …).
//
// Nothing upstream corresponds to process_name, command_pattern,
// suppression_logic or confidence, so those stay null rather than being
// invented — a fabricated `confidence: 'possible'` on all 4,589 rows would make
// getLoFP's `ORDER BY confidence DESC` look meaningful when it ranks nothing.

const TECHNIQUE_TAG = /^t\d{4}(\.\d{3})?$/i;

/**
 * Placeholder false-positive texts, dropped rather than stored.
 *
 * Upstream rule authors write these into the false-positive field when they
 * have nothing to say, and LoFP collects each one into a single page carrying
 * every technique that used it — "unknown" alone is tagged with 277 techniques,
 * "unlikely" with 149. Kept, they would be the largest LoFP result for
 * hundreds of techniques while telling a tuner nothing at all. Matched exactly,
 * so genuinely terse entries ("ansible", "analyst testing") are preserved.
 */
const LOFP_PLACEHOLDERS = new Set([
  'unknown', 'unlikely', 'none', 'n/a', 'na', 'no', 'nothing', 'not applicable',
  'unknown.', 'none.', 'todo', 'tbd',
]);

/**
 * Fan one LoFP page out into one record per technique it is tagged with.
 *
 * `lolfarm_lofp.technique_id` is a single column and `getLoFP` selects on
 * equality, so the row shape the schema wants is (technique, fp text) — one
 * page tagged with six techniques is six rows.
 *
 * 1,432 of the 3,360 pages carry no technique tag at all, mostly from Splunk
 * rules that document a false positive without attributing it. They are stored
 * with an empty `technique_id` rather than dropped: `getLoFP` matches on
 * equality so it never returns them, but `searchLoFP` and `search_lolfarm`
 * match on description text and do. Dropping them cost all three certutil
 * false positives in the corpus, which is the kind of silence that reads as
 * "no known false positives" when the truth is "not attributed to a technique".
 */
function parseLoFP(data: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(data)) return [];
  const out: Array<Record<string, unknown>> = [];

  for (const page of data as Array<Record<string, unknown>>) {
    // Titles arrive lowercased and often carry the source rule's list marker.
    const text = String(page.title ?? '').replace(/^[-*]\s*/, '').trim();
    if (!text || LOFP_PLACEHOLDERS.has(text.replace(/\.$/, ''))) continue;

    const tags = Array.isArray(page.tags)
      ? (page.tags as Array<Record<string, unknown>>).map(t => String(t?.title ?? '').trim())
      : [];
    const techniques = [...new Set(
      tags.filter(t => TECHNIQUE_TAG.test(t)).map(t => t.toUpperCase())
    )];

    // The permalink is unique across all 3,360 pages, which makes it a stable
    // primary key under INSERT OR REPLACE — a re-sync updates rows rather than
    // accumulating duplicates. Slug plus technique keeps that per row.
    const slug = String(page.permalink ?? '').replace(/^\/LoFP\/|\/$/g, '') || text.slice(0, 60);

    // '' rather than null: the column is indexed and getLoFP compares with =,
    // where NULL would never match anything anyway, but '' keeps the value
    // sortable and makes "unattributed" visible in a SELECT rather than absent.
    if (techniques.length === 0) {
      out.push({ id: `${slug}::-`, technique_id: '', description: text });
      continue;
    }
    for (const tid of techniques) {
      out.push({ id: `${slug}::${tid}`, technique_id: tid, description: text });
    }
  }
  return out;
}

function mapLoFP(raw: Record<string, unknown>): LoFPEntry | null {
  const tid = raw.technique_id as string;
  const desc = raw.description as string;
  // Only the description is required. technique_id is legitimately '' for the
  // unattributed pages, so testing it for truthiness here would silently undo
  // the decision parseLoFP just made.
  if (typeof tid !== 'string' || !desc) return null;
  return { id: raw.id as string, technique_id: tid, description: desc };
}

// --- WADComs ----------------------------------------------------------------
//
// A Jekyll site, not an API. Each technique is a Markdown file under
// _wadcoms/ whose YAML front matter carries description, command, items,
// services, OS, attack_types and references. So the sync is a directory listing
// (one GitHub API call) followed by one raw fetch per file.
//
// The interesting problem is ATT&CK mapping: WADComs records none. Writing
// technique IDs from recall would be fabrication — a mapping that looks
// authoritative and is unfalsifiable — so instead the tool name is resolved
// against ATT&CK's own software entries and the technique IDs come from the
// `uses` relationships MITRE already publishes. Mimikatz resolves to S0002 and
// its 17 techniques; Evil-WinRM resolves to nothing and is stored unmapped,
// reachable through lookup_wadcom and search_lolfarm but not through
// get_lolfarm_context, which selects on mitre_techniques. That asymmetry is
// reported rather than papered over.

/** Concurrency cap for the per-file fetches. Polite, and fast enough weekly. */
const WADCOM_CONCURRENCY = 8;

async function fetchText(url: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': USER_AGENT, Accept: 'text/plain' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

/** YAML front matter between the leading `---` fences. */
function frontMatter(md: string): Record<string, unknown> | null {
  const m = md.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return null;
  try {
    const parsed = parseYaml(m[1]);
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/**
 * ATT&CK technique IDs for a WADComs entry, derived from MITRE's own data.
 *
 * File names carry a qualifier — `Evil-WinRM-PTH`, `Enum4Linux-Creds` — so the
 * trailing segments are stripped one at a time looking for a software entry.
 * Candidates shorter than five characters are refused: stripping
 * `Evil-WinRM-PTH` down to `Evil` would eventually match something unrelated,
 * and a wrong mapping here is worse than none, because it would place a
 * technique's abuse guidance under a technique that does not use it.
 */
function techniquesForToolName(rawName: string): { ids: string[]; source?: string } {
  const parts = rawName.split('-');
  for (let take = parts.length; take >= 1; take--) {
    const candidate = parts.slice(0, take).join('-');
    if (candidate.length < 5) break;
    const sw = runQuery<{ id: string; stix_id: string; name: string }>(
      `SELECT id, stix_id, name FROM mitre_tools WHERE LOWER(name) = LOWER(?)
       UNION
       SELECT id, stix_id, name FROM mitre_malware WHERE LOWER(name) = LOWER(?)
       LIMIT 1`,
      [candidate, candidate]
    );
    if (sw.length === 0) continue;
    const ids = runQuery<{ id: string }>(
      `SELECT DISTINCT t.id FROM mitre_relationships r
       JOIN mitre_techniques_full t ON r.target_ref = t.stix_id
       WHERE r.source_ref = ? AND r.relationship_type = 'uses'
       ORDER BY t.id`,
      [sw[0].stix_id]
    ).map(r => r.id);
    if (ids.length === 0) continue;
    // The provenance is the honest part. Without it, "Impacket-GetADUsers has
    // T1003.006" reads as a claim about that command; with it, the claim is the
    // true one — ATT&CK attributes that technique to Impacket the tool.
    return {
      ids,
      source: `${sw[0].id} ${sw[0].name} — tool-level ATT&CK profile, not specific to this command`,
    };
  }
  return { ids: [] };
}

/** One pass over the collection, bounded concurrency, failures skipped not fatal. */
async function fetchWADComs(listingUrl: string): Promise<Array<Record<string, unknown>>> {
  const listing = await fetchJson<Array<{ name: string; download_url: string | null; type: string }>>(
    listingUrl
  );
  if (!Array.isArray(listing)) return [];

  const files = listing.filter(
    f => f.type === 'file' && f.name.endsWith('.md') && typeof f.download_url === 'string'
  );

  const out: Array<Record<string, unknown>> = [];
  let cursor = 0;

  async function worker(): Promise<void> {
    for (;;) {
      const i = cursor++;
      if (i >= files.length) return;
      const f = files[i];
      try {
        const fm = frontMatter(await fetchText(f.download_url as string));
        if (!fm) continue;
        out.push({ ...fm, __name: f.name.replace(/\.md$/, '') });
      } catch {
        // One unreachable file must not lose the other 143.
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(WADCOM_CONCURRENCY, files.length) }, worker)
  );
  return out;
}

function mapWADCom(raw: Record<string, unknown>): WADComEntry | null {
  const name = (raw.__name as string) || (raw.name as string) || (raw.title as string);
  if (!name) return null;

  const { ids, source } = techniquesForToolName(name);

  return {
    name,
    // Front matter descriptions carry a "Command Reference" block with example
    // IPs and passwords. Kept — it is how the command is meant to be read — but
    // capped, because 144 of them at full length is a lot of corpus for little
    // added meaning.
    description: typeof raw.description === 'string' ? raw.description.trim().slice(0, 900) : undefined,
    command: typeof raw.command === 'string' ? raw.command.trim() : undefined,
    category: toStringArray(raw.attack_types ?? raw.category).join(', ') || undefined,
    os: toStringArray(raw.OS ?? raw.os).join(', ') || undefined,
    tools_required: toStringArray(raw.items),
    services: toStringArray(raw.services),
    mitre_techniques: ids,
    mitre_source: source,
    resources: toStringArray(raw.references).slice(0, 5),
  };
}

function mapLOTS(raw: Record<string, unknown>): LOTSEntry | null {
  const domain = (raw.domain as string) || (raw.host as string);
  if (!domain) return null;
  return {
    domain,
    service_name: raw.service as string,
    category: raw.category as string,
    description: raw.description as string,
    mitre_techniques: (raw.mitre as string[]) || [],
    resources: (raw.references as string[]) || [],
  };
}

function mapMalAPI(raw: Record<string, unknown>): MalAPIEntry | null {
  const api = (raw.api as string) || (raw.name as string);
  if (!api) return null;
  const mitre = raw.MITRE ?? raw.mitre;
  const malware = raw.Malware ?? raw.malware;
  return {
    api_name: api,
    description: raw.description as string,
    category: (raw.category as string) || (raw.group as string),
    mitre_techniques: toStringArray(mitre),
    malware_families: toStringArray(malware),
    detection_notes: raw.detection as string,
  };
}

function mapLOLBAS(raw: Record<string, unknown>): LOLBASEntry | null {
  const name = (raw.name as string) || (raw.Name as string);
  if (!name) return null;
  const cmds = (raw.Commands as Array<Record<string, unknown>>) || [];
  const mitre_techniques = [...new Set(cmds.map(c => c.MitreID as string).filter(Boolean))];
  const fullPaths = (raw.Full_Path as Array<Record<string, unknown>> | undefined)
    ?.map(p => p.Path as string).filter(Boolean) || [];
  const resources = (raw.Resources as Array<Record<string, unknown>> | undefined)
    ?.map(r => r.Link as string).filter(Boolean) || [];
  return {
    name: name.toLowerCase(),
    description: (raw.Description as string) || (raw.description as string) || '',
    author: raw.Author as string,
    created: raw.Created as string,
    commands: cmds.map(c => (c.Command as string) || '').filter(Boolean),
    full_path: fullPaths,
    detection: (raw.Detection as Array<Record<string, unknown>> | undefined)
      ?.map(d => (d.Sigma as string) || (d.BlockRule as string) || '').filter(Boolean).join('; ') || '',
    resources,
    mitre_techniques,
  };
}

// ---------------------------------------------------------------------------
// Source registry — drives the sync loop
// ---------------------------------------------------------------------------

interface Fetcher {
  /**
   * Upstream endpoint, or `null` when no machine-readable upstream exists —
   * in which case NO_UPSTREAM[source] holds the reason.
   *
   * The mapper and parser for a `null` source are kept rather than deleted.
   * They encode how the entry shape maps onto the DB, which stays true whether
   * or not a feed exists today, and leaving them in place makes adopting an
   * upstream a one-line change instead of a rediscovery.
   */
  url: string | null;
  /**
   * Custom retrieval, for a source whose records are not one JSON document.
   * When present it replaces the single `fetchJson(url)` call and returns the
   * records directly; `url` is still carried so the result can report where the
   * sync started.
   */
  fetchAll?: (url: string) => Promise<Array<Record<string, unknown>>>;
  parse: (data: unknown) => Array<Record<string, unknown>>;
  map: (raw: Record<string, unknown>) => unknown;
  cache: (entry: unknown) => void;
}

const FETCHERS: Record<SourceName, Fetcher> = {
  drivers: {
    url: SOURCES.drivers,
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : [],
    map: (r) => mapDriver(r),
    cache: (e) => e && cacheLOLDriver(e as LOLDriverEntry),
  },
  hijacklibs: {
    url: SOURCES.hijacklibs,
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : (data as { hijacklibs?: Array<Record<string, unknown>> })?.hijacklibs ?? [],
    map: (r) => mapHijackLib(r),
    cache: (e) => e && cacheHijackLib(e as HijackLibEntry),
  },
  rmm: {
    url: SOURCES.rmm,
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : (data as { tools?: Array<Record<string, unknown>> })?.tools ?? [],
    map: (r) => mapRMM(r),
    cache: (e) => e && cacheLOLRMM(e as LOLRMMEntry),
  },
  lofp: {
    url: SOURCES.lofp,
    parse: parseLoFP,
    map: (r) => mapLoFP(r),
    cache: (e) => e && cacheLoFP(e as LoFPEntry),
  },
  wadcoms: {
    url: SOURCES.wadcoms,
    // The only source whose records are not one JSON document. fetchAll does
    // the directory listing and the per-file fetches; parse then just passes
    // the collected front matter through.
    fetchAll: fetchWADComs,
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : [],
    map: (r) => mapWADCom(r),
    cache: (e) => e && cacheWADCom(e as WADComEntry),
  },
  lots: {
    url: null,
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : [],
    map: (r) => mapLOTS(r),
    cache: (e) => e && cacheLOTS(e as LOTSEntry),
  },
  malapi: {
    url: null,
    parse: (data) => {
      if (Array.isArray(data)) return data as Array<Record<string, unknown>>;
      if (data && typeof data === 'object') {
        // malapi.io returns { "ApiName": { description, category, MITRE, Malware }, ... }
        return Object.entries(data as Record<string, unknown>).map(([api, v]) => ({
          api: api,
          ...((v && typeof v === 'object') ? v as Record<string, unknown> : { description: String(v) }),
        }));
      }
      return [];
    },
    map: (r) => mapMalAPI(r),
    cache: (e) => e && cacheMalAPI(e as MalAPIEntry),
  },
  lolbas: {
    url: SOURCES.lolbas,
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : [],
    map: (r) => mapLOLBAS(r),
    cache: (e) => e && cacheLOLBAS(e as LOLBASEntry),
  },
};

// ---------------------------------------------------------------------------
// Sync runner — one source or all
// ---------------------------------------------------------------------------

export interface SyncSourceResult {
  source: SourceName;
  url: string | null;
  /**
   * `no_upstream` is distinct from `failed` on purpose. A failure is worth
   * retrying; the absence of any published feed is not, and collapsing the two
   * meant three permanent gaps were reported every week as though the network
   * had hiccupped. Callers should surface `reason` and move on.
   */
  status: 'success' | 'failed' | 'empty' | 'no_upstream';
  fetched: number;
  cached: number;
  duration_ms: number;
  error?: string;
  reason?: string;
}

async function syncOne(source: SourceName): Promise<SyncSourceResult> {
  const fetcher = FETCHERS[source];
  const t0 = Date.now();

  if (fetcher.url === null) {
    return {
      source, url: null, status: 'no_upstream', fetched: 0, cached: 0,
      duration_ms: Date.now() - t0,
      reason: NO_UPSTREAM[source] ?? 'No upstream endpoint is configured for this source.',
    };
  }

  try {
    const records = fetcher.fetchAll
      ? await fetcher.fetchAll(fetcher.url)
      : fetcher.parse(await fetchJson(fetcher.url));
    if (records.length === 0) {
      return { source, url: fetcher.url, status: 'empty', fetched: 0, cached: 0, duration_ms: Date.now() - t0 };
    }
    let cached = 0;
    for (const rec of records) {
      const mapped = fetcher.map(rec);
      if (mapped) {
        try { fetcher.cache(mapped); cached++; } catch { /* skip bad row, keep going */ }
      }
    }
    updateSyncStatus(source, cached);
    return { source, url: fetcher.url, status: 'success', fetched: records.length, cached, duration_ms: Date.now() - t0 };
  } catch (e) {
    return {
      source, url: fetcher.url, status: 'failed', fetched: 0, cached: 0,
      duration_ms: Date.now() - t0,
      error: (e as Error).message,
    };
  }
}

export async function syncLOLFarm(only?: SourceName): Promise<{
  results: SyncSourceResult[];
  totals: { fetched: number; cached: number; failed: number; no_upstream: number };
  duration_ms: number;
}> {
  const t0 = Date.now();
  const targets = only ? [only] : (Object.keys(FETCHERS) as SourceName[]);
  // Fetch all sources in parallel — independent failures don't block each other
  const results = await Promise.all(targets.map(syncOne));
  // Persist to disk once after all sources complete
  saveDb();
  const totals = results.reduce(
    (acc, r) => ({
      fetched: acc.fetched + r.fetched,
      cached: acc.cached + r.cached,
      failed: acc.failed + (r.status === 'failed' ? 1 : 0),
      no_upstream: acc.no_upstream + (r.status === 'no_upstream' ? 1 : 0),
    }),
    { fetched: 0, cached: 0, failed: 0, no_upstream: 0 },
  );
  return { results, totals, duration_ms: Date.now() - t0 };
}

export const SYNC_SOURCES = Object.keys(FETCHERS) as SourceName[];

/** Sources that can actually be refreshed. The rest are seed-only — see NO_UPSTREAM. */
export const LIVE_SYNC_SOURCES = (Object.keys(FETCHERS) as SourceName[])
  .filter(s => FETCHERS[s].url !== null);
