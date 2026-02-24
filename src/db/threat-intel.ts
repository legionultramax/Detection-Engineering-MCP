// Threat Intelligence Database Schema
// Caches data from MITRE ATT&CK, CVE/NVD, CISA KEV, LOLBAS, etc.
import { getDb, runQuery, runStatement } from './connection.js';

export function initThreatIntelSchema(): void {
  const db = getDb();
  
  db.exec(`
    -- MITRE ATT&CK Techniques cache
    CREATE TABLE IF NOT EXISTS mitre_techniques (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      tactic_ids TEXT,
      tactic_names TEXT,
      platforms TEXT,
      permissions_required TEXT,
      data_sources TEXT,
      detection TEXT,
      mitigations TEXT,
      refs TEXT,
      is_subtechnique INTEGER DEFAULT 0,
      parent_id TEXT,
      url TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_mitre_name ON mitre_techniques(name);
    
    -- MITRE ATT&CK Tactics cache
    CREATE TABLE IF NOT EXISTS mitre_tactics (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      short_name TEXT,
      url TEXT,
      technique_count INTEGER DEFAULT 0,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- CVE/NVD cache
    CREATE TABLE IF NOT EXISTS cve_cache (
      id TEXT PRIMARY KEY,
      description TEXT,
      severity TEXT,
      cvss_score REAL,
      cvss_vector TEXT,
      cwe_ids TEXT,
      affected_products TEXT,
      refs TEXT,
      published_date TEXT,
      last_modified TEXT,
      exploit_available INTEGER DEFAULT 0,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_cache(severity);
    CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_cache(cvss_score);
    
    -- CISA KEV (Known Exploited Vulnerabilities)
    CREATE TABLE IF NOT EXISTS cisa_kev (
      cve_id TEXT PRIMARY KEY,
      vendor_project TEXT,
      product TEXT,
      vulnerability_name TEXT,
      date_added TEXT,
      short_description TEXT,
      required_action TEXT,
      due_date TEXT,
      known_ransomware_campaign TEXT,
      notes TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- LOLBAS (Living Off The Land Binaries and Scripts)
    CREATE TABLE IF NOT EXISTS lolbas (
      name TEXT PRIMARY KEY,
      description TEXT,
      author TEXT,
      created TEXT,
      commands TEXT,
      full_path TEXT,
      code_sample TEXT,
      detection TEXT,
      resources TEXT,
      acknowledgement TEXT,
      mitre_techniques TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- GTFOBins
    CREATE TABLE IF NOT EXISTS gtfobins (
      name TEXT PRIMARY KEY,
      description TEXT,
      functions TEXT,
      examples TEXT,
      refs TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- IOC cache
    CREATE TABLE IF NOT EXISTS ioc_cache (
      value TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      source TEXT,
      threat_type TEXT,
      confidence REAL,
      first_seen TEXT,
      last_seen TEXT,
      tags TEXT,
      related_malware TEXT,
      last_updated TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_cache(type);
    CREATE INDEX IF NOT EXISTS idx_ioc_threat ON ioc_cache(threat_type);
  `);
  
  console.error('[db] Threat intelligence schema initialized');
}

// MITRE ATT&CK operations
export interface MitreTechnique {
  id: string;
  name: string;
  description?: string;
  tactic_ids?: string[];
  tactic_names?: string[];
  platforms?: string[];
  permissions_required?: string[];
  data_sources?: string[];
  detection?: string;
  mitigations?: string[];
  references?: string[];
  is_subtechnique?: boolean;
  parent_id?: string;
  url?: string;
}

export function cacheMitreTechnique(technique: MitreTechnique): void {
  runStatement(
    `INSERT OR REPLACE INTO mitre_techniques 
     (id, name, description, tactic_ids, tactic_names, platforms, permissions_required, 
      data_sources, detection, mitigations, refs, is_subtechnique, parent_id, url, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [technique.id, technique.name, technique.description || null,
     technique.tactic_ids ? JSON.stringify(technique.tactic_ids) : null,
     technique.tactic_names ? JSON.stringify(technique.tactic_names) : null,
     technique.platforms ? JSON.stringify(technique.platforms) : null,
     technique.permissions_required ? JSON.stringify(technique.permissions_required) : null,
     technique.data_sources ? JSON.stringify(technique.data_sources) : null,
     technique.detection || null,
     technique.mitigations ? JSON.stringify(technique.mitigations) : null,
     technique.references ? JSON.stringify(technique.references) : null,
     technique.is_subtechnique ? 1 : 0, technique.parent_id || null, technique.url || null]
  );
}

export function getMitreTechnique(id: string): MitreTechnique | null {
  const results = runQuery<Record<string, unknown>>('SELECT * FROM mitre_techniques WHERE id = ?', [id]);
  if (results.length === 0) return null;
  
  const row = results[0];
  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    tactic_ids: row.tactic_ids ? JSON.parse(row.tactic_ids as string) : undefined,
    tactic_names: row.tactic_names ? JSON.parse(row.tactic_names as string) : undefined,
    platforms: row.platforms ? JSON.parse(row.platforms as string) : undefined,
    is_subtechnique: row.is_subtechnique === 1,
    parent_id: row.parent_id as string | undefined,
    url: row.url as string | undefined,
  };
}

export function searchMitreTechniques(query: string): MitreTechnique[] {
  const results = runQuery<Record<string, unknown>>(
    'SELECT * FROM mitre_techniques WHERE id LIKE ? OR name LIKE ? OR description LIKE ?',
    [`%${query}%`, `%${query}%`, `%${query}%`]
  );
  
  return results.map(row => ({
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    is_subtechnique: row.is_subtechnique === 1,
  }));
}

// CVE operations
export interface CVEEntry {
  id: string;
  description?: string;
  severity?: string;
  cvss_score?: number;
  cvss_vector?: string;
  cwe_ids?: string[];
  affected_products?: string[];
  references?: string[];
  published_date?: string;
  last_modified?: string;
  exploit_available?: boolean;
}

export function cacheCVE(cve: CVEEntry): void {
  runStatement(
    `INSERT OR REPLACE INTO cve_cache 
     (id, description, severity, cvss_score, cvss_vector, cwe_ids, affected_products,
      refs, published_date, last_modified, exploit_available, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [cve.id, cve.description || null, cve.severity || null, cve.cvss_score || null,
     cve.cvss_vector || null,
     cve.cwe_ids ? JSON.stringify(cve.cwe_ids) : null,
     cve.affected_products ? JSON.stringify(cve.affected_products) : null,
     cve.references ? JSON.stringify(cve.references) : null,
     cve.published_date || null, cve.last_modified || null, cve.exploit_available ? 1 : 0]
  );
}

export function getCVE(id: string): CVEEntry | null {
  const results = runQuery<Record<string, unknown>>('SELECT * FROM cve_cache WHERE id = ?', [id]);
  if (results.length === 0) return null;
  
  const row = results[0];
  return {
    id: row.id as string,
    description: row.description as string | undefined,
    severity: row.severity as string | undefined,
    cvss_score: row.cvss_score as number | undefined,
    exploit_available: row.exploit_available === 1,
  };
}

// CISA KEV operations
export interface KEVEntry {
  cve_id: string;
  vendor_project?: string;
  product?: string;
  vulnerability_name?: string;
  date_added?: string;
  short_description?: string;
  required_action?: string;
  due_date?: string;
  known_ransomware_campaign?: string;
  notes?: string;
}

export function cacheKEV(kev: KEVEntry): void {
  runStatement(
    `INSERT OR REPLACE INTO cisa_kev 
     (cve_id, vendor_project, product, vulnerability_name, date_added, short_description,
      required_action, due_date, known_ransomware_campaign, notes, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [kev.cve_id, kev.vendor_project || null, kev.product || null, kev.vulnerability_name || null,
     kev.date_added || null, kev.short_description || null, kev.required_action || null,
     kev.due_date || null, kev.known_ransomware_campaign || null, kev.notes || null]
  );
}

export function getKEV(cveId: string): KEVEntry | null {
  const results = runQuery<KEVEntry>('SELECT * FROM cisa_kev WHERE cve_id = ?', [cveId]);
  return results[0] || null;
}

export function getAllKEV(): KEVEntry[] {
  return runQuery<KEVEntry>('SELECT * FROM cisa_kev ORDER BY date_added DESC');
}

export function isInKEV(cveId: string): boolean {
  const results = runQuery<{ count: number }>('SELECT COUNT(*) as count FROM cisa_kev WHERE cve_id = ?', [cveId]);
  return results[0]?.count > 0;
}

// LOLBAS operations
export interface LOLBASEntry {
  name: string;
  description?: string;
  author?: string;
  created?: string;
  commands?: string[];
  full_path?: string[];
  detection?: string;
  resources?: string[];
  mitre_techniques?: string[];
}

export function cacheLOLBAS(entry: LOLBASEntry): void {
  runStatement(
    `INSERT OR REPLACE INTO lolbas 
     (name, description, author, created, commands, full_path, detection, resources, mitre_techniques, last_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [entry.name, entry.description || null, entry.author || null, entry.created || null,
     entry.commands ? JSON.stringify(entry.commands) : null,
     entry.full_path ? JSON.stringify(entry.full_path) : null,
     entry.detection || null,
     entry.resources ? JSON.stringify(entry.resources) : null,
     entry.mitre_techniques ? JSON.stringify(entry.mitre_techniques) : null]
  );
}

export function getLOLBAS(name: string): LOLBASEntry | null {
  const results = runQuery<Record<string, unknown>>('SELECT * FROM lolbas WHERE name = ?', [name]);
  if (results.length === 0) return null;
  
  const row = results[0];
  return {
    name: row.name as string,
    description: row.description as string | undefined,
    commands: row.commands ? JSON.parse(row.commands as string) : undefined,
    detection: row.detection as string | undefined,
    mitre_techniques: row.mitre_techniques ? JSON.parse(row.mitre_techniques as string) : undefined,
  };
}

export function searchLOLBAS(query: string): LOLBASEntry[] {
  const results = runQuery<Record<string, unknown>>(
    'SELECT * FROM lolbas WHERE name LIKE ? OR description LIKE ?',
    [`%${query}%`, `%${query}%`]
  );
  
  return results.map(row => ({
    name: row.name as string,
    description: row.description as string | undefined,
  }));
}
