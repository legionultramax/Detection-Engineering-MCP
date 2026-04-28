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
import { saveDb } from '../../db/connection.js';

// ---------------------------------------------------------------------------
// Upstream endpoints
// ---------------------------------------------------------------------------

const SOURCES = {
  drivers:    'https://www.loldrivers.io/api/drivers.json',
  hijacklibs: 'https://hijacklibs.net/api/hijacklibs.json',
  rmm:        'https://lolrmm.io/api/rmm_tools.json',
  lofp:       'https://raw.githubusercontent.com/SigmaHQ/lofp/main/lofp.json',
  wadcoms:    'https://raw.githubusercontent.com/swisskyrepo/WADComs/master/WADComs/data.json',
  lots:       'https://raw.githubusercontent.com/eversinc33/Lots-of-Trusted-Sites/main/data.json',
  malapi:     'https://raw.githubusercontent.com/nicowillis/malapi.io/main/malapi.json',
  lolbas:     'https://lolbas-project.github.io/api/lolbas.json',
} as const;

type SourceName = keyof typeof SOURCES;

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
    return await res.json() as T;
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

function mapLoFP(raw: Record<string, unknown>): LoFPEntry | null {
  const tid = (raw.technique_id as string) || (raw.technique as string);
  const desc = (raw.description as string) || (raw.fp_description as string);
  if (!tid || !desc) return null;
  return {
    id: (raw.id as string) || `${tid}-${(raw.process as string) || 'unknown'}`,
    technique_id: tid,
    process_name: (raw.process as string) || (raw.process_name as string),
    command_pattern: raw.command_pattern as string,
    description: desc,
    suppression_logic: raw.suppression as string,
    confidence: (raw.confidence as LoFPEntry['confidence']) || 'possible',
  };
}

function mapWADCom(raw: Record<string, unknown>): WADComEntry | null {
  const name = (raw.name as string) || (raw.title as string);
  if (!name) return null;
  return {
    name,
    description: raw.description as string,
    command: (raw.command as string) || (raw.cmd as string),
    category: raw.category as string,
    os: (raw.os as string) || 'windows',
    tools_required: (raw.tools as string[]) || [],
    mitre_techniques: (raw.mitre as string[]) || [],
    resources: (raw.references as string[]) || [],
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
  url: string;
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
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : [],
    map: (r) => mapLoFP(r),
    cache: (e) => e && cacheLoFP(e as LoFPEntry),
  },
  wadcoms: {
    url: SOURCES.wadcoms,
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : [],
    map: (r) => mapWADCom(r),
    cache: (e) => e && cacheWADCom(e as WADComEntry),
  },
  lots: {
    url: SOURCES.lots,
    parse: (data) => Array.isArray(data) ? data as Array<Record<string, unknown>> : [],
    map: (r) => mapLOTS(r),
    cache: (e) => e && cacheLOTS(e as LOTSEntry),
  },
  malapi: {
    url: SOURCES.malapi,
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
  url: string;
  status: 'success' | 'failed' | 'empty';
  fetched: number;
  cached: number;
  duration_ms: number;
  error?: string;
}

async function syncOne(source: SourceName): Promise<SyncSourceResult> {
  const fetcher = FETCHERS[source];
  const t0 = Date.now();
  try {
    const raw = await fetchJson(fetcher.url);
    const records = fetcher.parse(raw);
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
  totals: { fetched: number; cached: number; failed: number };
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
    }),
    { fetched: 0, cached: 0, failed: 0 },
  );
  return { results, totals, duration_ms: Date.now() - t0 };
}

export const SYNC_SOURCES = Object.keys(FETCHERS) as SourceName[];
