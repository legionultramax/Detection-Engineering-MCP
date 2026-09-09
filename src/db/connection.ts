// Database connection, on better-sqlite3.
//
// This replaced sql.js, which was the root cause of three separate problems.
// sql.js is a WASM build that holds the entire database in memory and has no
// incremental write path: every write meant db.export() of the whole image
// followed by a full file rewrite, so a 120MB corpus cost 120MB of I/O per
// statement — initMitreAttackTables() alone spent roughly 930MB of writes per
// startup on idempotent DDL. Its WASM build also omits FTS5, which is why the
// flagship search tool was a substring LIKE scan while its description claimed
// full-text search. And read-only mode could only be approximated by neutering
// the save function, because the in-memory image was always writable.
//
// All three go away. Writes are incremental, FTS5 is available, and read-only is
// enforced by SQLite itself: opening with readonly:true makes the engine reject
// a write with SQLITE_READONLY rather than relying on this module to remember
// not to persist one.
//
// Every exported signature is unchanged, so the 256 call sites going through
// these wrappers did not move.
//
// One behaviour did change, and it is a consequence of the file now being
// genuinely read-only rather than a copy in memory. Runtime seeding of
// reference data — the 138 coverage telemetry mappings, the 85 LOLFarm
// constants — used to succeed against the in-memory image and vanish on exit.
// It cannot happen at all against a read-only file. That is the right outcome:
// reference data belongs baked into the database by the indexer, not
// synthesised on every boot. In read-only mode those writes are now skipped
// with a notice, and the affected tools report empty rather than throwing.
import Database from 'better-sqlite3';
import path from 'path';
import os from 'os';
import fs from 'fs';

type Db = Database.Database;

let db: Db | null = null;
let dbPath: string = '';

let readOnlyCache: boolean | null = null;
let readOnlyNoticeShown = false;
let seedSkipNoticeShown = false;

export function isReadOnly(): boolean {
  if (readOnlyCache === null) {
    const raw = (process.env.HAWKEYE_READONLY ?? '').trim().toLowerCase();
    readOnlyCache = raw === '1' || raw === 'true' || raw === 'yes';
  }
  return readOnlyCache;
}

function refuseWrite(): never {
  throw new Error(
    'EREADONLY: this server runs with HAWKEYE_READONLY set, so database writes are refused. ' +
    'Knowledge-graph, cache, and indexing tools are unavailable in this mode; reads are unaffected.'
  );
}

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

/** Columns added after the original schema shipped. Idempotent. */
function migrateDetectionsTable(database: Db): void {
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

  const existingCols = new Set<string>();
  try {
    const info = database.pragma('table_info(detections)') as Array<{ name: string }>;
    for (const row of info) existingCols.add(row.name);
  } catch {
    return;
  }

  for (const [col, type] of Object.entries(newColumns)) {
    if (!existingCols.has(col)) {
      try {
        database.exec(`ALTER TABLE detections ADD COLUMN ${col} ${type}`);
      } catch {
        // Column already exists or the table is missing — safe to ignore.
      }
    }
  }

  normalizeTacticsInPlace(database);
}

// One-shot normalization of mitre_tactics rows written before the indexer began
// using serializeTactics(). Idempotent: rows already in canonical
// JSON-array-of-slugs form are skipped, so after the first pass it only reads.
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
function normalizeTacticsInPlace(database: Db): void {
  try {
    const rows = database.prepare(
      'SELECT id, mitre_tactics FROM detections WHERE mitre_tactics IS NOT NULL'
    ).all() as Array<{ id: string; mitre_tactics: string }>;

    const fixes: Array<{ id: string; value: string }> = [];
    for (const row of rows) {
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

    if (fixes.length === 0) return;
    console.error(`[db] Normalizing mitre_tactics for ${fixes.length} legacy rows...`);
    const upd = database.prepare('UPDATE detections SET mitre_tactics = ? WHERE id = ?');
    const applyAll = database.transaction((batch: typeof fixes) => {
      for (const f of batch) upd.run(f.value, f.id);
    });
    applyAll(fixes);
    console.error(`[db] Tactic normalization complete.`);
  } catch (err) {
    console.error('[db] Tactic normalization failed (non-fatal):', (err as Error).message);
  }
}

/** Core schema. Only created when the connection is writable. */
function createCoreSchema(database: Db): void {
  database.exec(`
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
    );

    CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source_type);
    CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);
    CREATE INDEX IF NOT EXISTS idx_detections_name ON detections(name);
    CREATE INDEX IF NOT EXISTS idx_logsource_product ON detections(logsource_product);
    CREATE INDEX IF NOT EXISTS idx_logsource_category ON detections(logsource_category);
    CREATE INDEX IF NOT EXISTS idx_detection_type ON detections(detection_type);
    CREATE INDEX IF NOT EXISTS idx_asset_type ON detections(asset_type);
    CREATE INDEX IF NOT EXISTS idx_security_domain ON detections(security_domain);
    CREATE INDEX IF NOT EXISTS idx_kql_category ON detections(kql_category);
    CREATE INDEX IF NOT EXISTS idx_platforms ON detections(platforms);
    CREATE INDEX IF NOT EXISTS idx_cves ON detections(cves);

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
    );

    CREATE TABLE IF NOT EXISTS cache (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      expires_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS dynamic_tables (
      name TEXT PRIMARY KEY,
      schema TEXT NOT NULL,
      description TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

/**
 * Open the database.
 *
 * Async only for compatibility — sql.js needed to await its WASM runtime and
 * every caller awaits this. better-sqlite3 opens synchronously.
 */
export async function initDbAsync(): Promise<Db> {
  if (db) return db;

  dbPath = getDbPath();
  const readonly = isReadOnly();
  console.error(`[db] Initializing database at ${dbPath}${readonly ? ' (read-only)' : ''}`);

  if (readonly && !fs.existsSync(dbPath)) {
    throw new Error(
      `EREADONLY: read-only mode requested but no database exists at ${dbPath}. ` +
      'A read-only server cannot create or index one. Point DETECTIONS_DB_PATH at a ' +
      'populated database, or start once without HAWKEYE_READONLY to build it.'
    );
  }

  db = new Database(dbPath, readonly ? { readonly: true, fileMustExist: true } : {});

  if (!readonly) {
    // WAL lets readers proceed during a write and removes the rollback-journal
    // rewrite. NORMAL synchronous is the usual WAL pairing: durable against
    // process crashes, which is the failure this actually needs to survive.
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');
    createCoreSchema(db);
    migrateDetectionsTable(db);
  }

  console.error('[db] Database initialized successfully');
  return db;
}

/** Synchronous accessor. Requires initDbAsync() to have run. */
export function initDb(): Db {
  if (!db) {
    throw new Error('Database not initialized. Call initDbAsync() first.');
  }
  return db;
}

export function getDb(): Db {
  if (!db) {
    throw new Error('Database not initialized. Call initDbAsync() first.');
  }
  return db;
}

/**
 * Retained as a no-op for its fourteen callers.
 *
 * Under sql.js this exported the whole in-memory image and rewrote the file,
 * which is why it needed atomic-rename handling and Windows retry logic. Writes
 * now land when the statement runs, so there is nothing to flush. The function
 * stays so callers do not all have to change at once, and so that "where does
 * this persist?" has an answer that is easy to find.
 */
export function saveDb(): void {
  if (isReadOnly() && !readOnlyNoticeShown) {
    console.error(`[db] read-only mode — ${dbPath} will not be modified`);
    readOnlyNoticeShown = true;
  }
}

export function closeDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/** Convert a value to something SQLite can bind. */
function toSqlValue(val: unknown): string | number | Uint8Array | null {
  if (val === null || val === undefined) return null;
  if (typeof val === 'string') return val;
  if (typeof val === 'number') return val;
  if (typeof val === 'boolean') return val ? 1 : 0;
  if (typeof val === 'bigint') return Number(val);
  if (val instanceof Uint8Array) return val;
  return JSON.stringify(val);
}

export function runQuery<T>(query: string, params: unknown[] = []): T[] {
  const database = getDb();
  try {
    const stmt = database.prepare(query);
    return (params.length > 0
      ? stmt.all(...params.map(toSqlValue))
      : stmt.all()) as T[];
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[db] Query error: ${message}`);
    throw error;
  }
}

/**
 * Execute schema DDL — CREATE TABLE / CREATE INDEX / ALTER.
 *
 * Permitted in read-only mode only in the sense that it does not pre-emptively
 * refuse: SQLite will reject it with SQLITE_READONLY if it actually writes.
 * `CREATE TABLE IF NOT EXISTS` against an already-populated database is a
 * no-op, so schema initialisation on a read-only connection succeeds without
 * touching the file.
 *
 * Kept separate from runStatement() because under sql.js each of these
 * triggered a full image rewrite — initMitreAttackTables() issued sixteen,
 * costing roughly 930MB of I/O per startup for statements that changed nothing.
 */
export function runSchemaStatement(query: string, params: unknown[] = []): void {
  const database = getDb();
  try {
    if (params.length > 0) {
      database.prepare(query).run(...params.map(toSqlValue));
    } else {
      database.exec(query);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // On a read-only connection an IF NOT EXISTS that has nothing to do still
    // reports SQLITE_READONLY on some builds. That is not a failure worth
    // propagating, because the schema it wanted already exists.
    if (isReadOnly() && /READONLY/i.test(message)) return;
    console.error(`[db] Schema statement error: ${message}`);
    throw error;
  }
}

/**
 * Execute a write whose only purpose is caching.
 *
 * In read-only mode this is a silent no-op rather than an error, because the
 * caller already holds the value it was trying to cache — failing the write
 * would fail a read that had already succeeded.
 *
 * That is not hypothetical. lookup_lolbas, nvd_cve_lookup and check_cisa_kev
 * all fetch or query, then cache. Routing them through runStatement() made
 * three read-only tools throw EREADONLY on a successful lookup, and all three
 * sit in the phase1-authoring profile.
 *
 * Use this only where losing the write is genuinely harmless. Anything a user
 * or model would consider durable belongs in runStatement(), which refuses
 * loudly instead.
 */
export function runCacheStatement(query: string, params: unknown[] = []): void {
  if (isReadOnly()) return;
  runStatement(query, params);
}

export function runStatement(query: string, params: unknown[] = []): void {
  if (isReadOnly()) refuseWrite();
  const database = getDb();
  try {
    if (params.length > 0) {
      database.prepare(query).run(...params.map(toSqlValue));
    } else {
      database.prepare(query).run();
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[db] Statement error: ${message}`);
    throw error;
  }
}

/**
 * Bulk write, used by the indexer and by the reference-data seeders.
 *
 * Under sql.js this was distinguished by skipping the per-statement image
 * export, which is why it also had to stay unguarded in read-only mode — the
 * seed paths depended on writing to the in-memory copy. Neither applies now:
 * writes are incremental, and a read-only file cannot be written at all.
 *
 * So in read-only mode this skips rather than throws. The callers are the
 * indexer, which is already skipped at startup, and the seeders for the
 * coverage telemetry mappings and the LOLFarm constants. Those will find their
 * tables empty, which is honest — reference data belongs baked into the
 * database by the indexer rather than synthesised on every boot, and a
 * read-only server has no business inventing it.
 */
export function runBulkStatement(query: string, params: unknown[] = []): void {
  if (isReadOnly()) {
    if (!seedSkipNoticeShown) {
      console.error(
        '[db] read-only mode — skipping bulk writes. Reference data that is normally seeded ' +
        'at runtime (coverage telemetry mappings, LOLFarm constants) will be absent unless it ' +
        'was baked into the database.'
      );
      seedSkipNoticeShown = true;
    }
    return;
  }
  const database = getDb();
  try {
    if (params.length > 0) {
      database.prepare(query).run(...params.map(toSqlValue));
    } else {
      database.prepare(query).run();
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[db] Bulk statement error: ${message}`);
    throw error;
  }
}
