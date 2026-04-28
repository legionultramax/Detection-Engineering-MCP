// LOLFarm Database Schema
// Aggregated Living-Off-The-Land data from lolol.farm sub-projects:
// LOLDrivers, HijackLibs, LOLRMM, LoFP, WADComs, LOTS, MalAPI
import { getDb, runQuery, runStatement, runBulkStatement, saveDb } from './connection.js';

// ---------------------------------------------------------------------------
// Schema initialization
// ---------------------------------------------------------------------------

export function initLOLFarmSchema(): void {
  const db = getDb();

  db.exec(`
    -- LOLDrivers: Vulnerable/malicious Windows drivers (BYOVD)
    CREATE TABLE IF NOT EXISTS lolfarm_drivers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT,
      commands TEXT,
      hashes TEXT,
      detection TEXT,
      mitre_techniques TEXT,
      cve TEXT,
      verified INTEGER DEFAULT 0,
      resources TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_lolfarm_drivers_name ON lolfarm_drivers(name);
    CREATE INDEX IF NOT EXISTS idx_lolfarm_drivers_category ON lolfarm_drivers(category);

    -- HijackLibs: DLL hijacking candidates per executable
    CREATE TABLE IF NOT EXISTS lolfarm_hijacklibs (
      name TEXT PRIMARY KEY,
      vendor TEXT,
      expected_locations TEXT,
      vulnerable_executables TEXT,
      hijack_type TEXT,
      resources TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_lolfarm_hijacklibs_type ON lolfarm_hijacklibs(hijack_type);
    CREATE INDEX IF NOT EXISTS idx_lolfarm_hijacklibs_vendor ON lolfarm_hijacklibs(vendor);

    -- LOLRMM: Legitimate Remote Monitoring & Management tools abused for C2
    CREATE TABLE IF NOT EXISTS lolfarm_rmm (
      name TEXT PRIMARY KEY,
      vendor TEXT,
      description TEXT,
      executable_names TEXT,
      network_artifacts TEXT,
      registry_artifacts TEXT,
      detection_guidance TEXT,
      mitre_techniques TEXT,
      abuse_references TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- LoFP: Known false positives mapped to ATT&CK techniques
    CREATE TABLE IF NOT EXISTS lolfarm_lofp (
      id TEXT PRIMARY KEY,
      technique_id TEXT,
      process_name TEXT,
      command_pattern TEXT,
      description TEXT,
      suppression_logic TEXT,
      confidence TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_lolfarm_lofp_technique ON lolfarm_lofp(technique_id);
    CREATE INDEX IF NOT EXISTS idx_lolfarm_lofp_process ON lolfarm_lofp(process_name);

    -- WADComs: Windows/AD offensive commands
    CREATE TABLE IF NOT EXISTS lolfarm_wadcoms (
      name TEXT PRIMARY KEY,
      description TEXT,
      command TEXT,
      category TEXT,
      os TEXT,
      tools_required TEXT,
      mitre_techniques TEXT,
      resources TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_lolfarm_wadcoms_category ON lolfarm_wadcoms(category);
    CREATE INDEX IF NOT EXISTS idx_lolfarm_wadcoms_os ON lolfarm_wadcoms(os);

    -- LOTS: Legitimate domains abused for C2/exfiltration/phishing
    CREATE TABLE IF NOT EXISTS lolfarm_lots (
      domain TEXT PRIMARY KEY,
      service_name TEXT,
      category TEXT,
      description TEXT,
      mitre_techniques TEXT,
      resources TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_lolfarm_lots_category ON lolfarm_lots(category);

    -- MalAPI: Windows APIs mapped to malware behavior
    CREATE TABLE IF NOT EXISTS lolfarm_malapi (
      api_name TEXT PRIMARY KEY,
      description TEXT,
      category TEXT,
      mitre_techniques TEXT,
      malware_families TEXT,
      detection_notes TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_lolfarm_malapi_category ON lolfarm_malapi(category);

    -- Sync metadata: tracks when each source was last synced
    CREATE TABLE IF NOT EXISTS lolfarm_sync (
      source TEXT PRIMARY KEY,
      last_synced TEXT,
      entry_count INTEGER DEFAULT 0,
      sync_version TEXT
    );
  `);

  console.error('[db] LOLFarm schema initialized');
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface LOLDriverEntry {
  id: string;
  name: string;
  description?: string;
  category?: string;
  commands?: Array<{ command: string; description: string; usecase: string; privileges: string; os: string }>;
  hashes?: { md5?: string; sha1?: string; sha256?: string; authentihash_sha256?: string };
  detection?: Array<{ type: string; value: string }>;
  mitre_techniques?: string[];
  cve?: string[];
  verified?: boolean;
  resources?: string[];
}

export interface HijackLibEntry {
  name: string;
  vendor?: string;
  expected_locations?: string[];
  vulnerable_executables?: Array<{
    path: string;
    type: 'Phantom' | 'Sideloading' | 'Search Order' | 'Environment Variable';
    auto_elevate?: boolean;
    privilege_escalation?: boolean;
    condition?: string;
  }>;
  hijack_type?: string;
  resources?: string[];
}

export interface LOLRMMEntry {
  name: string;
  vendor?: string;
  description?: string;
  executable_names?: string[];
  network_artifacts?: { domains?: string[]; ports?: number[]; user_agents?: string[] };
  registry_artifacts?: string[];
  detection_guidance?: string;
  mitre_techniques?: string[];
  abuse_references?: string[];
}

export interface LoFPEntry {
  id: string;
  technique_id: string;
  process_name?: string;
  command_pattern?: string;
  description: string;
  suppression_logic?: string;
  confidence?: 'confirmed' | 'likely' | 'possible';
}

export interface WADComEntry {
  name: string;
  description?: string;
  command?: string;
  category?: string;
  os?: string;
  tools_required?: string[];
  mitre_techniques?: string[];
  resources?: string[];
}

export interface LOTSEntry {
  domain: string;
  service_name?: string;
  category?: string;
  description?: string;
  mitre_techniques?: string[];
  resources?: string[];
}

export interface MalAPIEntry {
  api_name: string;
  description?: string;
  category?: string;
  mitre_techniques?: string[];
  malware_families?: string[];
  detection_notes?: string;
}

// Aggregated context returned by get_lolfarm_context
export interface LOLFarmContext {
  technique_id: string;
  drivers: LOLDriverEntry[];
  hijacklibs: HijackLibEntry[];
  rmm_tools: LOLRMMEntry[];
  false_positives: LoFPEntry[];
  wadcoms: WADComEntry[];
  lots_domains: LOTSEntry[];
  malapis: MalAPIEntry[];
  summary: {
    total_results: number;
    sources_with_data: string[];
  };
}

// ---------------------------------------------------------------------------
// Cache functions — LOLDrivers
// ---------------------------------------------------------------------------

export function cacheLOLDriver(entry: LOLDriverEntry): void {
  runBulkStatement(
    `INSERT OR REPLACE INTO lolfarm_drivers
     (id, name, description, category, commands, hashes, detection,
      mitre_techniques, cve, verified, resources, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [entry.id, entry.name, entry.description || null, entry.category || null,
     entry.commands ? JSON.stringify(entry.commands) : null,
     entry.hashes ? JSON.stringify(entry.hashes) : null,
     entry.detection ? JSON.stringify(entry.detection) : null,
     entry.mitre_techniques ? JSON.stringify(entry.mitre_techniques) : null,
     entry.cve ? JSON.stringify(entry.cve) : null,
     entry.verified ? 1 : 0,
     entry.resources ? JSON.stringify(entry.resources) : null]
  );
}

export function getLOLDriver(nameOrHash: string): LOLDriverEntry | null {
  const q = nameOrHash.toLowerCase();
  // Try name first, then hash search
  let results = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_drivers WHERE LOWER(name) = ?', [q]
  );
  if (results.length === 0) {
    results = runQuery<Record<string, unknown>>(
      'SELECT * FROM lolfarm_drivers WHERE LOWER(hashes) LIKE ?', [`%${q}%`]
    );
  }
  if (results.length === 0) return null;
  return parseDriverRow(results[0]);
}

export function searchLOLDrivers(query: string, category?: string): LOLDriverEntry[] {
  const q = `%${query.toLowerCase()}%`;
  let sql = 'SELECT * FROM lolfarm_drivers WHERE (LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(hashes) LIKE ?)';
  const params: unknown[] = [q, q, q];
  if (category) {
    sql += ' AND category = ?';
    params.push(category);
  }
  sql += ' LIMIT 25';
  return runQuery<Record<string, unknown>>(sql, params).map(parseDriverRow);
}

export function listLOLDrivers(category?: string): { count: number; drivers: Array<{ name: string; category: string; cve: string[] }> } {
  let sql = 'SELECT name, category, cve FROM lolfarm_drivers';
  const params: unknown[] = [];
  if (category) {
    sql += ' WHERE category = ?';
    params.push(category);
  }
  sql += ' ORDER BY name LIMIT 100';
  const rows = runQuery<Record<string, unknown>>(sql, params);
  return {
    count: rows.length,
    drivers: rows.map(r => ({
      name: r.name as string,
      category: (r.category as string) || 'unknown',
      cve: r.cve ? JSON.parse(r.cve as string) : [],
    })),
  };
}

function parseDriverRow(row: Record<string, unknown>): LOLDriverEntry {
  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    category: row.category as string | undefined,
    commands: row.commands ? JSON.parse(row.commands as string) : undefined,
    hashes: row.hashes ? JSON.parse(row.hashes as string) : undefined,
    detection: row.detection ? JSON.parse(row.detection as string) : undefined,
    mitre_techniques: row.mitre_techniques ? JSON.parse(row.mitre_techniques as string) : undefined,
    cve: row.cve ? JSON.parse(row.cve as string) : undefined,
    verified: row.verified === 1,
    resources: row.resources ? JSON.parse(row.resources as string) : undefined,
  };
}

// ---------------------------------------------------------------------------
// Cache functions — HijackLibs
// ---------------------------------------------------------------------------

export function cacheHijackLib(entry: HijackLibEntry): void {
  runBulkStatement(
    `INSERT OR REPLACE INTO lolfarm_hijacklibs
     (name, vendor, expected_locations, vulnerable_executables, hijack_type, resources, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [entry.name, entry.vendor || null,
     entry.expected_locations ? JSON.stringify(entry.expected_locations) : null,
     entry.vulnerable_executables ? JSON.stringify(entry.vulnerable_executables) : null,
     entry.hijack_type || null,
     entry.resources ? JSON.stringify(entry.resources) : null]
  );
}

export function getHijackLib(nameOrExe: string): HijackLibEntry[] {
  const q = nameOrExe.toLowerCase();
  // Search by DLL name or by vulnerable executable path
  const results = runQuery<Record<string, unknown>>(
    `SELECT * FROM lolfarm_hijacklibs
     WHERE LOWER(name) LIKE ? OR LOWER(vulnerable_executables) LIKE ?`,
    [`%${q}%`, `%${q}%`]
  );
  return results.map(parseHijackLibRow);
}

function parseHijackLibRow(row: Record<string, unknown>): HijackLibEntry {
  return {
    name: row.name as string,
    vendor: row.vendor as string | undefined,
    expected_locations: row.expected_locations ? JSON.parse(row.expected_locations as string) : undefined,
    vulnerable_executables: row.vulnerable_executables ? JSON.parse(row.vulnerable_executables as string) : undefined,
    hijack_type: row.hijack_type as string | undefined,
    resources: row.resources ? JSON.parse(row.resources as string) : undefined,
  };
}

// ---------------------------------------------------------------------------
// Cache functions — LOLRMM
// ---------------------------------------------------------------------------

export function cacheLOLRMM(entry: LOLRMMEntry): void {
  const mitreJson = entry.mitre_techniques?.length ? JSON.stringify(entry.mitre_techniques) : null;
  runBulkStatement(
    `INSERT INTO lolfarm_rmm
     (name, vendor, description, executable_names, network_artifacts, registry_artifacts,
      detection_guidance, mitre_techniques, abuse_references, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(name) DO UPDATE SET
       vendor            = COALESCE(excluded.vendor, vendor),
       description       = COALESCE(excluded.description, description),
       executable_names  = COALESCE(excluded.executable_names, executable_names),
       network_artifacts = COALESCE(excluded.network_artifacts, network_artifacts),
       registry_artifacts= COALESCE(excluded.registry_artifacts, registry_artifacts),
       detection_guidance= COALESCE(excluded.detection_guidance, detection_guidance),
       mitre_techniques  = COALESCE(excluded.mitre_techniques, mitre_techniques),
       abuse_references  = COALESCE(excluded.abuse_references, abuse_references),
       last_updated      = CURRENT_TIMESTAMP`,
    [entry.name, entry.vendor || null, entry.description || null,
     entry.executable_names?.length ? JSON.stringify(entry.executable_names) : null,
     entry.network_artifacts ? JSON.stringify(entry.network_artifacts) : null,
     entry.registry_artifacts?.length ? JSON.stringify(entry.registry_artifacts) : null,
     entry.detection_guidance || null,
     mitreJson,
     entry.abuse_references?.length ? JSON.stringify(entry.abuse_references) : null]
  );
}

export function getLOLRMM(name: string): LOLRMMEntry | null {
  const results = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_rmm WHERE LOWER(name) LIKE ?', [`%${name.toLowerCase()}%`]
  );
  if (results.length === 0) return null;
  return parseRMMRow(results[0]);
}

export function listLOLRMM(): { count: number; tools: Array<{ name: string; vendor: string; executables: string[] }> } {
  const rows = runQuery<Record<string, unknown>>('SELECT name, vendor, executable_names FROM lolfarm_rmm ORDER BY name');
  return {
    count: rows.length,
    tools: rows.map(r => ({
      name: r.name as string,
      vendor: (r.vendor as string) || 'unknown',
      executables: r.executable_names ? JSON.parse(r.executable_names as string) : [],
    })),
  };
}

function parseRMMRow(row: Record<string, unknown>): LOLRMMEntry {
  return {
    name: row.name as string,
    vendor: row.vendor as string | undefined,
    description: row.description as string | undefined,
    executable_names: row.executable_names ? JSON.parse(row.executable_names as string) : undefined,
    network_artifacts: row.network_artifacts ? JSON.parse(row.network_artifacts as string) : undefined,
    registry_artifacts: row.registry_artifacts ? JSON.parse(row.registry_artifacts as string) : undefined,
    detection_guidance: row.detection_guidance as string | undefined,
    mitre_techniques: row.mitre_techniques ? JSON.parse(row.mitre_techniques as string) : undefined,
    abuse_references: row.abuse_references ? JSON.parse(row.abuse_references as string) : undefined,
  };
}

// ---------------------------------------------------------------------------
// Cache functions — LoFP
// ---------------------------------------------------------------------------

export function cacheLoFP(entry: LoFPEntry): void {
  runBulkStatement(
    `INSERT OR REPLACE INTO lolfarm_lofp
     (id, technique_id, process_name, command_pattern, description,
      suppression_logic, confidence, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [entry.id, entry.technique_id, entry.process_name || null,
     entry.command_pattern || null, entry.description,
     entry.suppression_logic || null, entry.confidence || null]
  );
}

export function getLoFP(techniqueId: string): LoFPEntry[] {
  const results = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_lofp WHERE technique_id = ? ORDER BY confidence DESC',
    [techniqueId.toUpperCase()]
  );
  return results.map(r => ({
    id: r.id as string,
    technique_id: r.technique_id as string,
    process_name: r.process_name as string | undefined,
    command_pattern: r.command_pattern as string | undefined,
    description: r.description as string,
    suppression_logic: r.suppression_logic as string | undefined,
    confidence: r.confidence as 'confirmed' | 'likely' | 'possible' | undefined,
  }));
}

export function searchLoFP(query: string): LoFPEntry[] {
  const q = `%${query.toLowerCase()}%`;
  const results = runQuery<Record<string, unknown>>(
    `SELECT * FROM lolfarm_lofp
     WHERE LOWER(technique_id) LIKE ? OR LOWER(process_name) LIKE ?
        OR LOWER(description) LIKE ? OR LOWER(command_pattern) LIKE ?
     LIMIT 25`,
    [q, q, q, q]
  );
  return results.map(r => ({
    id: r.id as string,
    technique_id: r.technique_id as string,
    process_name: r.process_name as string | undefined,
    command_pattern: r.command_pattern as string | undefined,
    description: r.description as string,
    suppression_logic: r.suppression_logic as string | undefined,
    confidence: r.confidence as 'confirmed' | 'likely' | 'possible' | undefined,
  }));
}

// ---------------------------------------------------------------------------
// Cache functions — WADComs
// ---------------------------------------------------------------------------

export function cacheWADCom(entry: WADComEntry): void {
  runBulkStatement(
    `INSERT OR REPLACE INTO lolfarm_wadcoms
     (name, description, command, category, os, tools_required,
      mitre_techniques, resources, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [entry.name, entry.description || null, entry.command || null,
     entry.category || null, entry.os || null,
     entry.tools_required ? JSON.stringify(entry.tools_required) : null,
     entry.mitre_techniques ? JSON.stringify(entry.mitre_techniques) : null,
     entry.resources ? JSON.stringify(entry.resources) : null]
  );
}

export function searchWADComs(query: string): WADComEntry[] {
  const q = `%${query.toLowerCase()}%`;
  const results = runQuery<Record<string, unknown>>(
    `SELECT * FROM lolfarm_wadcoms
     WHERE LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(command) LIKE ?
        OR LOWER(mitre_techniques) LIKE ?
     LIMIT 25`,
    [q, q, q, q]
  );
  return results.map(parseWADComRow);
}

function parseWADComRow(row: Record<string, unknown>): WADComEntry {
  return {
    name: row.name as string,
    description: row.description as string | undefined,
    command: row.command as string | undefined,
    category: row.category as string | undefined,
    os: row.os as string | undefined,
    tools_required: row.tools_required ? JSON.parse(row.tools_required as string) : undefined,
    mitre_techniques: row.mitre_techniques ? JSON.parse(row.mitre_techniques as string) : undefined,
    resources: row.resources ? JSON.parse(row.resources as string) : undefined,
  };
}

// ---------------------------------------------------------------------------
// Cache functions — LOTS
// ---------------------------------------------------------------------------

export function cacheLOTS(entry: LOTSEntry): void {
  runBulkStatement(
    `INSERT OR REPLACE INTO lolfarm_lots
     (domain, service_name, category, description, mitre_techniques, resources, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [entry.domain, entry.service_name || null, entry.category || null,
     entry.description || null,
     entry.mitre_techniques ? JSON.stringify(entry.mitre_techniques) : null,
     entry.resources ? JSON.stringify(entry.resources) : null]
  );
}

export function getLOTS(domain: string): LOTSEntry | null {
  const results = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_lots WHERE LOWER(domain) LIKE ?', [`%${domain.toLowerCase()}%`]
  );
  if (results.length === 0) return null;
  return parseLOTSRow(results[0]);
}

export function searchLOTS(query: string): LOTSEntry[] {
  const q = `%${query.toLowerCase()}%`;
  const results = runQuery<Record<string, unknown>>(
    `SELECT * FROM lolfarm_lots
     WHERE LOWER(domain) LIKE ? OR LOWER(service_name) LIKE ? OR LOWER(category) LIKE ?
     LIMIT 25`,
    [q, q, q]
  );
  return results.map(parseLOTSRow);
}

function parseLOTSRow(row: Record<string, unknown>): LOTSEntry {
  return {
    domain: row.domain as string,
    service_name: row.service_name as string | undefined,
    category: row.category as string | undefined,
    description: row.description as string | undefined,
    mitre_techniques: row.mitre_techniques ? JSON.parse(row.mitre_techniques as string) : undefined,
    resources: row.resources ? JSON.parse(row.resources as string) : undefined,
  };
}

// ---------------------------------------------------------------------------
// Cache functions — MalAPI
// ---------------------------------------------------------------------------

export function cacheMalAPI(entry: MalAPIEntry): void {
  runBulkStatement(
    `INSERT OR REPLACE INTO lolfarm_malapi
     (api_name, description, category, mitre_techniques, malware_families,
      detection_notes, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [entry.api_name, entry.description || null, entry.category || null,
     entry.mitre_techniques ? JSON.stringify(entry.mitre_techniques) : null,
     entry.malware_families ? JSON.stringify(entry.malware_families) : null,
     entry.detection_notes || null]
  );
}

export function getMalAPI(apiName: string): MalAPIEntry | null {
  const results = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_malapi WHERE LOWER(api_name) = ?', [apiName.toLowerCase()]
  );
  if (results.length === 0) return null;
  return parseMalAPIRow(results[0]);
}

export function searchMalAPI(query: string): MalAPIEntry[] {
  const q = `%${query.toLowerCase()}%`;
  const results = runQuery<Record<string, unknown>>(
    `SELECT * FROM lolfarm_malapi
     WHERE LOWER(api_name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(category) LIKE ?
        OR LOWER(mitre_techniques) LIKE ?
     LIMIT 25`,
    [q, q, q, q]
  );
  return results.map(parseMalAPIRow);
}

function parseMalAPIRow(row: Record<string, unknown>): MalAPIEntry {
  return {
    api_name: row.api_name as string,
    description: row.description as string | undefined,
    category: row.category as string | undefined,
    mitre_techniques: row.mitre_techniques ? JSON.parse(row.mitre_techniques as string) : undefined,
    malware_families: row.malware_families ? JSON.parse(row.malware_families as string) : undefined,
    detection_notes: row.detection_notes as string | undefined,
  };
}

// ---------------------------------------------------------------------------
// Cross-source aggregation — get_lolfarm_context
// ---------------------------------------------------------------------------

export function getLOLFarmContext(techniqueId: string): LOLFarmContext {
  const tid = techniqueId.toUpperCase();
  const tidLike = `%${tid}%`;

  // Query all sources for this technique in parallel (sync SQLite, but fast)
  const drivers = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_drivers WHERE mitre_techniques LIKE ? LIMIT 10', [tidLike]
  ).map(parseDriverRow);

  const hijacklibs = runQuery<Record<string, unknown>>(
    // T1574.001 and T1574.002 — search by known DLL hijack techniques
    tid.startsWith('T1574') ?
      'SELECT * FROM lolfarm_hijacklibs LIMIT 20' :
      `SELECT * FROM lolfarm_hijacklibs WHERE 0`, // empty for non-DLL techniques
    []
  ).map(parseHijackLibRow);

  const rmm = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_rmm WHERE mitre_techniques LIKE ? LIMIT 10', [tidLike]
  ).map(parseRMMRow);

  const fps = getLoFP(tid);

  const wadcoms = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_wadcoms WHERE mitre_techniques LIKE ? LIMIT 10', [tidLike]
  ).map(parseWADComRow);

  const lots = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_lots WHERE mitre_techniques LIKE ? LIMIT 10', [tidLike]
  ).map(parseLOTSRow);

  const malapis = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolfarm_malapi WHERE mitre_techniques LIKE ? LIMIT 10', [tidLike]
  ).map(parseMalAPIRow);

  const sourcesWithData: string[] = [];
  if (drivers.length > 0) sourcesWithData.push('LOLDrivers');
  if (hijacklibs.length > 0) sourcesWithData.push('HijackLibs');
  if (rmm.length > 0) sourcesWithData.push('LOLRMM');
  if (fps.length > 0) sourcesWithData.push('LoFP');
  if (wadcoms.length > 0) sourcesWithData.push('WADComs');
  if (lots.length > 0) sourcesWithData.push('LOTS');
  if (malapis.length > 0) sourcesWithData.push('MalAPI');

  return {
    technique_id: tid,
    drivers,
    hijacklibs,
    rmm_tools: rmm,
    false_positives: fps,
    wadcoms,
    lots_domains: lots,
    malapis,
    summary: {
      total_results: drivers.length + hijacklibs.length + rmm.length +
                     fps.length + wadcoms.length + lots.length + malapis.length,
      sources_with_data: sourcesWithData,
    },
  };
}

// ---------------------------------------------------------------------------
// Unified cross-source search
// ---------------------------------------------------------------------------

export function searchLOLFarm(query: string, source?: string): {
  query: string;
  total: number;
  results: Array<{ source: string; name: string; description?: string; mitre_techniques?: string[] }>;
} {
  const q = `%${query.toLowerCase()}%`;
  const results: Array<{ source: string; name: string; description?: string; mitre_techniques?: string[] }> = [];

  if (!source || source === 'drivers') {
    const drivers = runQuery<Record<string, unknown>>(
      'SELECT name, description, mitre_techniques FROM lolfarm_drivers WHERE LOWER(name) LIKE ? OR LOWER(description) LIKE ? LIMIT 10',
      [q, q]
    );
    for (const d of drivers) {
      results.push({
        source: 'LOLDrivers',
        name: d.name as string,
        description: (d.description as string)?.substring(0, 120),
        mitre_techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques as string) : undefined,
      });
    }
  }

  if (!source || source === 'hijacklibs') {
    const libs = runQuery<Record<string, unknown>>(
      'SELECT name, vendor, hijack_type FROM lolfarm_hijacklibs WHERE LOWER(name) LIKE ? OR LOWER(vulnerable_executables) LIKE ? LIMIT 10',
      [q, q]
    );
    for (const l of libs) {
      results.push({
        source: 'HijackLibs',
        name: l.name as string,
        description: `${l.vendor || 'Unknown'} — ${l.hijack_type || 'Unknown type'}`,
      });
    }
  }

  if (!source || source === 'rmm') {
    const rmm = runQuery<Record<string, unknown>>(
      'SELECT name, vendor, description, mitre_techniques FROM lolfarm_rmm WHERE LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(executable_names) LIKE ? LIMIT 10',
      [q, q, q]
    );
    for (const r of rmm) {
      results.push({
        source: 'LOLRMM',
        name: r.name as string,
        description: (r.description as string)?.substring(0, 120),
        mitre_techniques: r.mitre_techniques ? JSON.parse(r.mitre_techniques as string) : undefined,
      });
    }
  }

  if (!source || source === 'wadcoms') {
    const wad = runQuery<Record<string, unknown>>(
      'SELECT name, description, command, mitre_techniques FROM lolfarm_wadcoms WHERE LOWER(name) LIKE ? OR LOWER(command) LIKE ? OR LOWER(description) LIKE ? LIMIT 10',
      [q, q, q]
    );
    for (const w of wad) {
      results.push({
        source: 'WADComs',
        name: w.name as string,
        description: (w.description as string)?.substring(0, 120),
        mitre_techniques: w.mitre_techniques ? JSON.parse(w.mitre_techniques as string) : undefined,
      });
    }
  }

  if (!source || source === 'lots') {
    const lots = runQuery<Record<string, unknown>>(
      'SELECT domain, service_name, category, mitre_techniques FROM lolfarm_lots WHERE LOWER(domain) LIKE ? OR LOWER(service_name) LIKE ? LIMIT 10',
      [q, q]
    );
    for (const l of lots) {
      results.push({
        source: 'LOTS',
        name: l.domain as string,
        description: `${l.service_name || ''} (${l.category || 'unknown'})`,
        mitre_techniques: l.mitre_techniques ? JSON.parse(l.mitre_techniques as string) : undefined,
      });
    }
  }

  if (!source || source === 'malapi') {
    const apis = runQuery<Record<string, unknown>>(
      'SELECT api_name, description, category, mitre_techniques FROM lolfarm_malapi WHERE LOWER(api_name) LIKE ? OR LOWER(description) LIKE ? LIMIT 10',
      [q, q]
    );
    for (const a of apis) {
      results.push({
        source: 'MalAPI',
        name: a.api_name as string,
        description: (a.description as string)?.substring(0, 120),
        mitre_techniques: a.mitre_techniques ? JSON.parse(a.mitre_techniques as string) : undefined,
      });
    }
  }

  return { query, total: results.length, results };
}

// ---------------------------------------------------------------------------
// Sync metadata helpers
// ---------------------------------------------------------------------------

export function getSyncStatus(source: string): { last_synced: string | null; entry_count: number } {
  const results = runQuery<Record<string, unknown>>(
    'SELECT last_synced, entry_count FROM lolfarm_sync WHERE source = ?', [source]
  );
  if (results.length === 0) return { last_synced: null, entry_count: 0 };
  return {
    last_synced: results[0].last_synced as string | null,
    entry_count: results[0].entry_count as number,
  };
}

export function updateSyncStatus(source: string, entryCount: number, version?: string): void {
  runStatement(
    `INSERT OR REPLACE INTO lolfarm_sync (source, last_synced, entry_count, sync_version)
     VALUES (?, CURRENT_TIMESTAMP, ?, ?)`,
    [source, entryCount, version || null]
  );
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export function getLOLFarmStats(): Record<string, number> {
  const tables = [
    ['lolfarm_drivers', 'drivers'],
    ['lolfarm_hijacklibs', 'hijacklibs'],
    ['lolfarm_rmm', 'rmm_tools'],
    ['lolfarm_lofp', 'false_positives'],
    ['lolfarm_wadcoms', 'wadcoms'],
    ['lolfarm_lots', 'lots_domains'],
    ['lolfarm_malapi', 'malapis'],
  ] as const;

  const stats: Record<string, number> = {};
  for (const [table, key] of tables) {
    try {
      const result = runQuery<{ count: number }>(`SELECT COUNT(*) as count FROM ${table}`);
      stats[key] = result[0]?.count || 0;
    } catch {
      stats[key] = 0;
    }
  }
  stats['total'] = Object.values(stats).reduce((a, b) => a + b, 0);
  return stats;
}
