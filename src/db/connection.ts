// Database connection and initialization using sql.js (pure JavaScript SQLite)
import initSqlJs, { Database as SqlJsDatabase } from 'sql.js';
import path from 'path';
import os from 'os';
import fs from 'fs';

let db: SqlJsDatabase | null = null;
let SQL: Awaited<ReturnType<typeof initSqlJs>> | null = null;
let dbPath: string = '';

function getDbPath(): string {
  if (process.env.DETECTIONS_DB_PATH) {
    return process.env.DETECTIONS_DB_PATH;
  }

  const dbDir = path.join(os.homedir(), '.cache', 'security-detections-mcp');
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  return path.join(dbDir, 'detections.db');
}

// Migrate existing databases by adding any new columns that may be missing
function migrateDetectionsTable(db: SqlJsDatabase): void {
  const newColumns: Record<string, string> = {
    logsource_category: 'TEXT',
    logsource_product: 'TEXT',
    logsource_service: 'TEXT',
    cves: 'TEXT',
    analytic_stories: 'TEXT',
    data_sources: 'TEXT',
    detection_type: 'TEXT',
    asset_type: 'TEXT',
    security_domain: 'TEXT',
    process_names: 'TEXT',
    file_paths_found: 'TEXT',
    registry_paths: 'TEXT',
    platforms: 'TEXT',
    kql_category: 'TEXT',
    kql_tags: 'TEXT',
    kql_keywords: 'TEXT',
  };

  // Get existing columns via PRAGMA
  const existingCols = new Set<string>();
  try {
    const stmt = db.prepare('PRAGMA table_info(detections)');
    while (stmt.step()) {
      const row = stmt.getAsObject() as { name: string };
      existingCols.add(row.name);
    }
    stmt.free();
  } catch {
    return;
  }

  for (const [col, type] of Object.entries(newColumns)) {
    if (!existingCols.has(col)) {
      try {
        db.run(`ALTER TABLE detections ADD COLUMN ${col} ${type}`);
      } catch {
        // Column already exists or other error — safe to ignore
      }
    }
  }

  normalizeTacticsInPlace(db);
}

// One-shot normalization of mitre_tactics rows that were written before the
// indexer started using serializeTactics(). Idempotent: rows already in
// canonical JSON-array-of-slugs form are skipped. Runs every startup but only
// rewrites rows that are demonstrably malformed (scalar JSON string, or any
// non-canonical tactic name), so it's cheap after the first pass.
const _TACTIC_CANONICAL_DB: ReadonlySet<string> = new Set([
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]);
function _canonTactic(raw: string): string | null {
  const slug = raw.trim()
    .replace(/([a-z])([A-Z])/g, '$1-$2')
    .replace(/\s+/g, '-').replace(/-+/g, '-').toLowerCase();
  return _TACTIC_CANONICAL_DB.has(slug) ? slug : null;
}
function normalizeTacticsInPlace(db: SqlJsDatabase): void {
  try {
    const stmt = db.prepare(
      'SELECT id, mitre_tactics FROM detections WHERE mitre_tactics IS NOT NULL'
    );
    const fixes: Array<{ id: string; value: string }> = [];
    while (stmt.step()) {
      const row = stmt.getAsObject() as { id: string; mitre_tactics: string };
      const raw = row.mitre_tactics;
      let isCanonical = false;
      let normalized: string[] = [];
      try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.every(v => typeof v === 'string' && _TACTIC_CANONICAL_DB.has(v))) {
          isCanonical = true;
        } else {
          const items: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
          const seen = new Set<string>();
          for (const v of items) {
            if (typeof v !== 'string') continue;
            const slug = _canonTactic(v);
            if (slug) seen.add(slug);
          }
          normalized = [...seen];
        }
      } catch {
        const slug = _canonTactic(raw);
        if (slug) normalized = [slug];
      }
      if (!isCanonical) fixes.push({ id: row.id, value: JSON.stringify(normalized) });
    }
    stmt.free();

    if (fixes.length === 0) return;
    console.error(`[db] Normalizing mitre_tactics for ${fixes.length} legacy rows...`);
    const upd = db.prepare('UPDATE detections SET mitre_tactics = ? WHERE id = ?');
    for (const f of fixes) { upd.run([f.value, f.id]); }
    upd.free();
    console.error(`[db] Tactic normalization complete.`);
  } catch (err) {
    console.error('[db] Tactic normalization failed (non-fatal):', (err as Error).message);
  }
}

export async function initDbAsync(): Promise<SqlJsDatabase> {
  if (db) return db;
  
  if (!SQL) {
    SQL = await initSqlJs();
  }
  
  dbPath = getDbPath();
  console.error(`[db] Initializing database at ${dbPath}`);
  
  // Load existing database if it exists
  if (fs.existsSync(dbPath)) {
    const buffer = fs.readFileSync(dbPath);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }
  
  // Create core tables
  db.run(`
    CREATE TABLE IF NOT EXISTS detections (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      source_type TEXT NOT NULL,
      severity TEXT,
      status TEXT,
      author TEXT,
      date_created TEXT,
      date_modified TEXT,
      query TEXT,
      raw_content TEXT,
      file_path TEXT,
      mitre_tactics TEXT,
      mitre_techniques TEXT,
      tags TEXT,
      refs TEXT,
      false_positives TEXT,
      search_text TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      logsource_category TEXT,
      logsource_product TEXT,
      logsource_service TEXT,
      cves TEXT,
      analytic_stories TEXT,
      data_sources TEXT,
      detection_type TEXT,
      asset_type TEXT,
      security_domain TEXT,
      process_names TEXT,
      file_paths_found TEXT,
      registry_paths TEXT,
      platforms TEXT,
      kql_category TEXT,
      kql_tags TEXT,
      kql_keywords TEXT
    )
  `);

  // Migrate existing databases: add any new columns that may be missing
  migrateDetectionsTable(db);

  // Base indexes
  db.run(`CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source_type)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_detections_name ON detections(name)`);

  // Enrichment field indexes
  db.run(`CREATE INDEX IF NOT EXISTS idx_logsource_product ON detections(logsource_product)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logsource_category ON detections(logsource_category)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_detection_type ON detections(detection_type)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_asset_type ON detections(asset_type)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_security_domain ON detections(security_domain)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_kql_category ON detections(kql_category)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_platforms ON detections(platforms)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_cves ON detections(cves)`);

  // Note: sql.js WASM build does not include FTS5.
  // Search uses multi-column LIKE across all enriched fields (see search_detections tool).
  
  db.run(`
    CREATE TABLE IF NOT EXISTS stories (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      narrative TEXT,
      source_type TEXT,
      detection_ids TEXT,
      mitre_tactics TEXT,
      mitre_techniques TEXT,
      tags TEXT,
      refs TEXT,
      file_path TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS cache (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      expires_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS dynamic_tables (
      name TEXT PRIMARY KEY,
      schema TEXT NOT NULL,
      description TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  saveDb();
  console.error('[db] Database initialized successfully');
  return db;
}

// Synchronous init for compatibility (requires async init to be called first)
export function initDb(): SqlJsDatabase {
  if (!db) {
    throw new Error('Database not initialized. Call initDbAsync() first.');
  }
  return db;
}

export function getDb(): SqlJsDatabase {
  if (!db) {
    throw new Error('Database not initialized. Call initDbAsync() first.');
  }
  return db;
}

export function saveDb(): void {
  if (!db || !dbPath) return;
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(dbPath, buffer);
  } catch (error) {
    console.error('[db] Save error:', error);
  }
}

export function closeDb(): void {
  if (db) {
    saveDb();
    db.close();
    db = null;
  }
}

// Helper for running queries with error handling
export function runQuery<T>(query: string, params: unknown[] = []): T[] {
  const database = getDb();
  try {
    const stmt = database.prepare(query);
    if (params.length > 0) {
      stmt.bind(params as (string | number | Uint8Array | null)[]);
    }
    
    const results: T[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push(row as T);
    }
    stmt.free();
    return results;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[db] Query error: ${message}`);
    throw error;
  }
}

// Convert value to SQLite-compatible primitive
function toSqlValue(val: unknown): string | number | Uint8Array | null {
  if (val === null || val === undefined) return null;
  if (typeof val === 'string') return val;
  if (typeof val === 'number') return val;
  if (typeof val === 'boolean') return val ? 1 : 0;
  if (val instanceof Uint8Array) return val;
  // Convert objects/arrays to JSON string
  return JSON.stringify(val);
}

export function runStatement(query: string, params: unknown[] = []): void {
  const database = getDb();
  try {
    if (params.length > 0) {
      const safeParams = params.map(toSqlValue);
      database.run(query, safeParams);
    } else {
      database.run(query);
    }
    saveDb();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[db] Statement error: ${message}`);
    throw error;
  }
}

// Bulk insert helper — skips per-row saveDb() for performance during batch operations
export function runBulkStatement(query: string, params: unknown[] = []): void {
  const database = getDb();
  try {
    if (params.length > 0) {
      const safeParams = params.map(toSqlValue);
      database.run(query, safeParams);
    } else {
      database.run(query);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[db] Bulk statement error: ${message}`);
    throw error;
  }
}
