// MITRE ATT&CK STIX Database Schema and Parser
import { createGunzip } from 'zlib';
import { createReadStream, existsSync } from 'fs';
import { runSchemaStatement, runBulkStatement, runQuery, getDb, saveDb } from './connection.js';

// STIX Object Interfaces
interface STIXObject {
  type: string;
  id: string;
  name?: string;
  description?: string;
  created?: string;
  modified?: string;
  external_references?: Array<{
    source_name: string;
    external_id?: string;
    url?: string;
  }>;
  x_mitre_platforms?: string[];
  x_mitre_domains?: string[];
  x_mitre_version?: string;
  x_mitre_deprecated?: boolean;
  x_mitre_detection?: string;
  aliases?: string[];
  kill_chain_phases?: Array<{
    kill_chain_name: string;
    phase_name: string;
  }>;
  // Relationship specific
  source_ref?: string;
  target_ref?: string;
  relationship_type?: string;
  // Data source specific
  x_mitre_collection_layers?: string[];
  // Campaign specific
  first_seen?: string;
  last_seen?: string;
  // Intrusion set specific
  x_mitre_contributors?: string[];
}

interface STIXBundle {
  type: string;
  id: string;
  objects: STIXObject[];
}

// Initialize MITRE ATT&CK tables
export function initMitreAttackTables(): void {
  // Threat Groups (intrusion-set)
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_groups (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      aliases TEXT,
      created TEXT,
      modified TEXT,
      external_id TEXT,
      url TEXT,
      is_deprecated INTEGER DEFAULT 0
    )
  `);

  // Software - Malware
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_malware (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      aliases TEXT,
      platforms TEXT,
      created TEXT,
      modified TEXT,
      external_id TEXT,
      url TEXT,
      is_deprecated INTEGER DEFAULT 0
    )
  `);

  // Software - Tools
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_tools (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      aliases TEXT,
      platforms TEXT,
      created TEXT,
      modified TEXT,
      external_id TEXT,
      url TEXT,
      is_deprecated INTEGER DEFAULT 0
    )
  `);

  // Campaigns
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_campaigns (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      aliases TEXT,
      first_seen TEXT,
      last_seen TEXT,
      created TEXT,
      modified TEXT,
      external_id TEXT,
      url TEXT,
      is_deprecated INTEGER DEFAULT 0
    )
  `);

  // Mitigations (course-of-action)
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_mitigations (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      created TEXT,
      modified TEXT,
      external_id TEXT,
      url TEXT,
      is_deprecated INTEGER DEFAULT 0
    )
  `);

  // Data Sources
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_data_sources (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      collection_layers TEXT,
      platforms TEXT,
      created TEXT,
      modified TEXT,
      external_id TEXT,
      url TEXT,
      is_deprecated INTEGER DEFAULT 0
    )
  `);

  // Data Components
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_data_components (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      data_source_id TEXT,
      created TEXT,
      modified TEXT,
      external_id TEXT,
      is_deprecated INTEGER DEFAULT 0,
      FOREIGN KEY (data_source_id) REFERENCES mitre_data_sources(stix_id)
    )
  `);

  // Techniques (attack-pattern) - enhanced version
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_techniques_full (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      detection TEXT,
      platforms TEXT,
      tactics TEXT,
      is_subtechnique INTEGER DEFAULT 0,
      parent_technique_id TEXT,
      created TEXT,
      modified TEXT,
      external_id TEXT,
      url TEXT,
      is_deprecated INTEGER DEFAULT 0
    )
  `);

  // Relationships (the glue)
  runSchemaStatement(`
    CREATE TABLE IF NOT EXISTS mitre_relationships (
      id TEXT PRIMARY KEY,
      stix_id TEXT UNIQUE,
      source_ref TEXT NOT NULL,
      target_ref TEXT NOT NULL,
      relationship_type TEXT NOT NULL,
      description TEXT,
      created TEXT,
      modified TEXT
    )
  `);

  // Create indexes for fast lookups
  runSchemaStatement(`CREATE INDEX IF NOT EXISTS idx_mitre_rel_source ON mitre_relationships(source_ref)`);
  runSchemaStatement(`CREATE INDEX IF NOT EXISTS idx_mitre_rel_target ON mitre_relationships(target_ref)`);
  runSchemaStatement(`CREATE INDEX IF NOT EXISTS idx_mitre_rel_type ON mitre_relationships(relationship_type)`);
  runSchemaStatement(`CREATE INDEX IF NOT EXISTS idx_mitre_groups_name ON mitre_groups(name)`);
  runSchemaStatement(`CREATE INDEX IF NOT EXISTS idx_mitre_malware_name ON mitre_malware(name)`);
  runSchemaStatement(`CREATE INDEX IF NOT EXISTS idx_mitre_tools_name ON mitre_tools(name)`);
  runSchemaStatement(`CREATE INDEX IF NOT EXISTS idx_mitre_techniques_extid ON mitre_techniques_full(external_id)`);
}

// Helper to extract external ID (e.g., G0001, S0001, T1059)
function getExternalId(obj: STIXObject): string | null {
  const ref = obj.external_references?.find(r => r.source_name === 'mitre-attack');
  return ref?.external_id || null;
}

function getExternalUrl(obj: STIXObject): string | null {
  const ref = obj.external_references?.find(r => r.source_name === 'mitre-attack');
  return ref?.url || null;
}

// Parse and index the STIX bundle
export async function indexMitreAttack(stixPath: string): Promise<{
  groups: number;
  malware: number;
  tools: number;
  campaigns: number;
  mitigations: number;
  data_sources: number;
  data_components: number;
  techniques: number;
  relationships: number;
}> {
  if (!existsSync(stixPath)) {
    throw new Error(`STIX file not found: ${stixPath}`);
  }

  // Read and decompress the gzipped JSON
  const chunks: Buffer[] = [];
  const gunzip = createGunzip();
  const stream = createReadStream(stixPath);

  stream.pipe(gunzip);
  for await (const chunk of gunzip) {
    chunks.push(chunk as Buffer);
  }

  const bundle: STIXBundle = JSON.parse(Buffer.concat(chunks).toString());

  const counts = {
    groups: 0,
    malware: 0,
    tools: 0,
    campaigns: 0,
    mitigations: 0,
    data_sources: 0,
    data_components: 0,
    techniques: 0,
    relationships: 0,
  };

  // Use transaction for bulk insert performance (avoids per-row saveDb)
  const database = getDb();
  database.run('BEGIN TRANSACTION');

  try {
    // First pass: index all non-relationship objects
    for (const obj of bundle.objects) {
      try {
        switch (obj.type) {
          case 'intrusion-set':
            indexGroup(obj);
            counts.groups++;
            break;
          case 'malware':
            indexMalware(obj);
            counts.malware++;
            break;
          case 'tool':
            indexTool(obj);
            counts.tools++;
            break;
          case 'campaign':
            indexCampaign(obj);
            counts.campaigns++;
            break;
          case 'course-of-action':
            indexMitigation(obj);
            counts.mitigations++;
            break;
          case 'x-mitre-data-source':
            indexDataSource(obj);
            counts.data_sources++;
            break;
          case 'x-mitre-data-component':
            indexDataComponent(obj);
            counts.data_components++;
            break;
          case 'attack-pattern':
            indexTechnique(obj);
            counts.techniques++;
            break;
        }
      } catch (e) {
        // Skip invalid objects
      }
    }

    // Second pass: index relationships
    for (const obj of bundle.objects) {
      if (obj.type === 'relationship') {
        try {
          indexRelationship(obj);
          counts.relationships++;
        } catch (e) {
          // Skip invalid relationships
        }
      }
    }

    database.run('COMMIT');
  } catch (e) {
    database.run('ROLLBACK');
    throw e;
  }

  // Save to disk once after all inserts
  saveDb();

  return counts;
}

function indexGroup(obj: STIXObject): void {
  const extId = getExternalId(obj);
  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_groups
     (id, stix_id, name, description, aliases, created, modified, external_id, url, is_deprecated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      extId || obj.id,
      obj.id,
      obj.name || '',
      obj.description || null,
      obj.aliases ? JSON.stringify(obj.aliases) : null,
      obj.created || null,
      obj.modified || null,
      extId,
      getExternalUrl(obj),
      obj.x_mitre_deprecated ? 1 : 0,
    ]
  );
}

function indexMalware(obj: STIXObject): void {
  const extId = getExternalId(obj);
  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_malware
     (id, stix_id, name, description, aliases, platforms, created, modified, external_id, url, is_deprecated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      extId || obj.id,
      obj.id,
      obj.name || '',
      obj.description || null,
      obj.aliases ? JSON.stringify(obj.aliases) : null,
      obj.x_mitre_platforms ? JSON.stringify(obj.x_mitre_platforms) : null,
      obj.created || null,
      obj.modified || null,
      extId,
      getExternalUrl(obj),
      obj.x_mitre_deprecated ? 1 : 0,
    ]
  );
}

function indexTool(obj: STIXObject): void {
  const extId = getExternalId(obj);
  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_tools
     (id, stix_id, name, description, aliases, platforms, created, modified, external_id, url, is_deprecated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      extId || obj.id,
      obj.id,
      obj.name || '',
      obj.description || null,
      obj.aliases ? JSON.stringify(obj.aliases) : null,
      obj.x_mitre_platforms ? JSON.stringify(obj.x_mitre_platforms) : null,
      obj.created || null,
      obj.modified || null,
      extId,
      getExternalUrl(obj),
      obj.x_mitre_deprecated ? 1 : 0,
    ]
  );
}

function indexCampaign(obj: STIXObject): void {
  const extId = getExternalId(obj);
  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_campaigns
     (id, stix_id, name, description, aliases, first_seen, last_seen, created, modified, external_id, url, is_deprecated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      extId || obj.id,
      obj.id,
      obj.name || '',
      obj.description || null,
      obj.aliases ? JSON.stringify(obj.aliases) : null,
      obj.first_seen || null,
      obj.last_seen || null,
      obj.created || null,
      obj.modified || null,
      extId,
      getExternalUrl(obj),
      obj.x_mitre_deprecated ? 1 : 0,
    ]
  );
}

function indexMitigation(obj: STIXObject): void {
  const extId = getExternalId(obj);
  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_mitigations
     (id, stix_id, name, description, created, modified, external_id, url, is_deprecated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      extId || obj.id,
      obj.id,
      obj.name || '',
      obj.description || null,
      obj.created || null,
      obj.modified || null,
      extId,
      getExternalUrl(obj),
      obj.x_mitre_deprecated ? 1 : 0,
    ]
  );
}

function indexDataSource(obj: STIXObject): void {
  const extId = getExternalId(obj);
  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_data_sources
     (id, stix_id, name, description, collection_layers, platforms, created, modified, external_id, url, is_deprecated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      extId || obj.id,
      obj.id,
      obj.name || '',
      obj.description || null,
      obj.x_mitre_collection_layers ? JSON.stringify(obj.x_mitre_collection_layers) : null,
      obj.x_mitre_platforms ? JSON.stringify(obj.x_mitre_platforms) : null,
      obj.created || null,
      obj.modified || null,
      extId,
      getExternalUrl(obj),
      obj.x_mitre_deprecated ? 1 : 0,
    ]
  );
}

function indexDataComponent(obj: STIXObject): void {
  // Data components reference their parent data source
  const parentRef = (obj as unknown as { x_mitre_data_source_ref?: string }).x_mitre_data_source_ref;
  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_data_components
     (id, stix_id, name, description, data_source_id, created, modified, external_id, is_deprecated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      obj.id,
      obj.id,
      obj.name || '',
      obj.description || null,
      parentRef || null,
      obj.created || null,
      obj.modified || null,
      getExternalId(obj),
      obj.x_mitre_deprecated ? 1 : 0,
    ]
  );
}

function indexTechnique(obj: STIXObject): void {
  const extId = getExternalId(obj);
  const tactics = obj.kill_chain_phases
    ?.filter(p => p.kill_chain_name === 'mitre-attack')
    .map(p => p.phase_name) || [];
  
  // Check if subtechnique (has parent in external_id like T1059.001)
  const isSubtechnique = extId?.includes('.') ? 1 : 0;
  const parentId = isSubtechnique && extId ? extId.split('.')[0] : null;

  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_techniques_full
     (id, stix_id, name, description, detection, platforms, tactics, is_subtechnique, parent_technique_id, created, modified, external_id, url, is_deprecated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      extId || obj.id,
      obj.id,
      obj.name || '',
      obj.description || null,
      obj.x_mitre_detection || null,
      obj.x_mitre_platforms ? JSON.stringify(obj.x_mitre_platforms) : null,
      JSON.stringify(tactics),
      isSubtechnique,
      parentId,
      obj.created || null,
      obj.modified || null,
      extId,
      getExternalUrl(obj),
      obj.x_mitre_deprecated ? 1 : 0,
    ]
  );
}

function indexRelationship(obj: STIXObject): void {
  if (!obj.source_ref || !obj.target_ref || !obj.relationship_type) return;

  runBulkStatement(
    `INSERT OR REPLACE INTO mitre_relationships
     (id, stix_id, source_ref, target_ref, relationship_type, description, created, modified)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      obj.id,
      obj.id,
      obj.source_ref,
      obj.target_ref,
      obj.relationship_type,
      obj.description || null,
      obj.created || null,
      obj.modified || null,
    ]
  );
}

// Check if MITRE data needs indexing
export function needsMitreIndexing(): boolean {
  try {
    const result = runQuery<{ count: number }>('SELECT COUNT(*) as count FROM mitre_groups');
    return result[0]?.count === 0;
  } catch {
    return true;
  }
}

// Query functions
export function getGroupByName(name: string): unknown {
  const results = runQuery<Record<string, unknown>>(
    `SELECT * FROM mitre_groups WHERE name LIKE ? OR aliases LIKE ? LIMIT 1`,
    [`%${name}%`, `%${name}%`]
  );
  return results[0] || null;
}

export function getGroupTechniques(groupId: string): unknown[] {
  // Get techniques used by this group via relationships
  return runQuery<Record<string, unknown>>(
    `SELECT t.* FROM mitre_techniques_full t
     JOIN mitre_relationships r ON r.target_ref = t.stix_id
     JOIN mitre_groups g ON r.source_ref = g.stix_id
     WHERE (g.external_id = ? OR g.name LIKE ?) AND r.relationship_type = 'uses'`,
    [groupId, `%${groupId}%`]
  );
}

export function getSoftwareByName(name: string): unknown {
  // Search both malware and tools
  let result = runQuery<Record<string, unknown>>(
    `SELECT *, 'malware' as software_type FROM mitre_malware WHERE name LIKE ? OR aliases LIKE ? LIMIT 1`,
    [`%${name}%`, `%${name}%`]
  );
  if (result.length === 0) {
    result = runQuery<Record<string, unknown>>(
      `SELECT *, 'tool' as software_type FROM mitre_tools WHERE name LIKE ? OR aliases LIKE ? LIMIT 1`,
      [`%${name}%`, `%${name}%`]
    );
  }
  return result[0] || null;
}

export function getMitigationsForTechnique(techniqueId: string): unknown[] {
  return runQuery<Record<string, unknown>>(
    `SELECT m.* FROM mitre_mitigations m
     JOIN mitre_relationships r ON r.source_ref = m.stix_id
     JOIN mitre_techniques_full t ON r.target_ref = t.stix_id
     WHERE t.external_id = ? AND r.relationship_type = 'mitigates'`,
    [techniqueId.toUpperCase()]
  );
}

export function getDataSourcesForTechnique(techniqueId: string): unknown[] {
  return runQuery<Record<string, unknown>>(
    `SELECT DISTINCT ds.*, dc.name as component_name, dc.description as component_description
     FROM mitre_data_sources ds
     JOIN mitre_data_components dc ON dc.data_source_id = ds.stix_id
     JOIN mitre_relationships r ON r.source_ref = dc.stix_id
     JOIN mitre_techniques_full t ON r.target_ref = t.stix_id
     WHERE t.external_id = ? AND r.relationship_type = 'detects'`,
    [techniqueId.toUpperCase()]
  );
}

export function searchGroups(query: string): unknown[] {
  return runQuery<Record<string, unknown>>(
    `SELECT * FROM mitre_groups 
     WHERE name LIKE ? OR description LIKE ? OR aliases LIKE ?
     ORDER BY name LIMIT 50`,
    [`%${query}%`, `%${query}%`, `%${query}%`]
  );
}

export function searchSoftware(query: string): unknown[] {
  const malware = runQuery<Record<string, unknown>>(
    `SELECT *, 'malware' as software_type FROM mitre_malware 
     WHERE name LIKE ? OR description LIKE ? OR aliases LIKE ?`,
    [`%${query}%`, `%${query}%`, `%${query}%`]
  );
  const tools = runQuery<Record<string, unknown>>(
    `SELECT *, 'tool' as software_type FROM mitre_tools 
     WHERE name LIKE ? OR description LIKE ? OR aliases LIKE ?`,
    [`%${query}%`, `%${query}%`, `%${query}%`]
  );
  return [...malware, ...tools].slice(0, 50);
}

export function getCampaigns(query?: string): unknown[] {
  if (query) {
    return runQuery<Record<string, unknown>>(
      `SELECT * FROM mitre_campaigns 
       WHERE name LIKE ? OR description LIKE ?
       ORDER BY last_seen DESC LIMIT 50`,
      [`%${query}%`, `%${query}%`]
    );
  }
  return runQuery<Record<string, unknown>>(
    `SELECT * FROM mitre_campaigns ORDER BY last_seen DESC LIMIT 50`
  );
}

export function getMitreStats(): Record<string, number> {
  const stats: Record<string, number> = {};
  
  const tables = [
    { name: 'groups', table: 'mitre_groups' },
    { name: 'malware', table: 'mitre_malware' },
    { name: 'tools', table: 'mitre_tools' },
    { name: 'campaigns', table: 'mitre_campaigns' },
    { name: 'mitigations', table: 'mitre_mitigations' },
    { name: 'data_sources', table: 'mitre_data_sources' },
    { name: 'data_components', table: 'mitre_data_components' },
    { name: 'techniques', table: 'mitre_techniques_full' },
    { name: 'relationships', table: 'mitre_relationships' },
  ];
  
  for (const { name, table } of tables) {
    try {
      const result = runQuery<{ count: number }>(`SELECT COUNT(*) as count FROM ${table}`);
      stats[name] = result[0]?.count || 0;
    } catch {
      stats[name] = 0;
    }
  }
  
  return stats;
}
