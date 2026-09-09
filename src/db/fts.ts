// FTS5 full-text index over the detection corpus.
//
// Why this is an explicitly-built artifact rather than a set of triggers: the
// read-only deployment cannot create or update it, so the index has to be
// inside the database file that ships. Building it is a step the indexer
// performs, and search must cope with a database that predates it — because
// every existing corpus does.
//
// It is a standalone FTS5 table rather than an external-content one. External
// content avoids duplicating the text, which is tempting on a 117MB database,
// but it ties the index to detections' implicit rowid, and the indexer uses
// INSERT OR REPLACE, which changes rowids. A standalone table costs disk and
// cannot desynchronise in a way that silently returns the wrong rows.
//
// Staleness is detected rather than assumed. If the row counts disagree, search
// says so and falls back instead of quietly searching a partial index.

import { getDb, isReadOnly, runQuery } from './connection.js';

/**
 * Indexed columns, in the order bm25() weights are applied.
 *
 * The weights carry the same claim as the substring scorer they replace: a hit
 * in a structured field is better evidence than a hit in free text. A rule
 * named "Mimikatz Execution" should outrank one that mentions mimikatz in a
 * paragraph, and a technique or CVE match is exact rather than incidental.
 *
 * search_text is the catch-all concatenation and is weighted lowest — nearly
 * everything matches it, so a hit there carries almost no information.
 */
export const FTS_COLUMNS = [
  { column: 'name', weight: 10.0 },
  { column: 'mitre_techniques', weight: 8.0 },
  { column: 'cves', weight: 8.0 },
  { column: 'process_names', weight: 4.0 },
  { column: 'tags', weight: 3.0 },
  { column: 'description', weight: 2.0 },
  { column: 'search_text', weight: 1.0 },
] as const;

export const FTS_TABLE = 'detections_fts';

/** bm25 weight list, positionally matched to the column order above. */
export function bm25Weights(): string {
  return FTS_COLUMNS.map(c => c.weight.toFixed(1)).join(', ');
}

export interface FtsStatus {
  available: boolean;
  rows: number;
  detections: number;
  stale: boolean;
  reason?: string;
}

let cachedStatus: FtsStatus | null = null;

/**
 * Whether the index exists and matches the corpus.
 *
 * Cached, because search calls this on every request and the answer only
 * changes when the index is rebuilt — which a read-only server cannot do and a
 * writable one does explicitly.
 */
export function ftsStatus(force = false): FtsStatus {
  if (cachedStatus && !force) return cachedStatus;

  const detections = (() => {
    try {
      return runQuery<{ n: number }>('SELECT COUNT(*) AS n FROM detections')[0]?.n ?? 0;
    } catch { return 0; }
  })();

  const exists = (() => {
    try {
      const r = runQuery<{ n: number }>(
        `SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table' AND name=?`, [FTS_TABLE]);
      return (r[0]?.n ?? 0) > 0;
    } catch { return false; }
  })();

  if (!exists) {
    cachedStatus = {
      available: false, rows: 0, detections, stale: true,
      reason: `${FTS_TABLE} does not exist. Run "npm run fts:build" against a writable database.`,
    };
    return cachedStatus;
  }

  let rows = 0;
  try {
    rows = runQuery<{ n: number }>(`SELECT COUNT(*) AS n FROM ${FTS_TABLE}`)[0]?.n ?? 0;
  } catch (err) {
    cachedStatus = {
      available: false, rows: 0, detections, stale: true,
      reason: `${FTS_TABLE} is unreadable: ${err instanceof Error ? err.message : String(err)}`,
    };
    return cachedStatus;
  }

  // An empty index is a different problem from a partial one, and both are
  // worse than saying so and using the fallback.
  if (rows === 0) {
    cachedStatus = {
      available: false, rows, detections, stale: true,
      reason: `${FTS_TABLE} exists but is empty. Run "npm run fts:build".`,
    };
  } else if (rows !== detections) {
    cachedStatus = {
      available: false, rows, detections, stale: true,
      reason: `${FTS_TABLE} holds ${rows} rows against ${detections} detections, so it is stale ` +
        'and would return an incomplete answer. Run "npm run fts:build".',
    };
  } else {
    cachedStatus = { available: true, rows, detections, stale: false };
  }
  return cachedStatus;
}

/** Create the virtual table. Writable connections only. */
export function createFtsTable(): void {
  if (isReadOnly()) return;
  const db = getDb();
  const cols = FTS_COLUMNS.map(c => c.column).join(', ');
  // tokenchars keeps dots, hyphens and underscores inside tokens. Without it
  // "T1003.001" tokenises as "t1003" and "001", so a search for the full
  // subtechnique ID matches every subtechnique of T1003 — and "powershell.exe"
  // would split into two tokens that match far more than intended.
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS ${FTS_TABLE} USING fts5(
      detection_id UNINDEXED,
      ${cols},
      tokenize = "unicode61 remove_diacritics 2 tokenchars '.-_'"
    )
  `);
}

export interface RebuildResult {
  rebuilt: boolean;
  rows: number;
  ms: number;
  reason?: string;
}

/**
 * Populate the index from scratch.
 *
 * Full rebuild rather than incremental: it runs after a bulk index, it takes
 * seconds, and a rebuild cannot leave the two tables disagreeing the way a
 * missed incremental update can.
 */
export function rebuildFtsIndex(): RebuildResult {
  if (isReadOnly()) {
    return {
      rebuilt: false, rows: 0, ms: 0,
      reason: 'Read-only connection. The index must be built where the database is writable, ' +
        'then shipped inside the database file.',
    };
  }

  const db = getDb();
  const t0 = Date.now();
  createFtsTable();

  const cols = FTS_COLUMNS.map(c => c.column);
  const build = db.transaction(() => {
    db.exec(`DELETE FROM ${FTS_TABLE}`);
    db.exec(`
      INSERT INTO ${FTS_TABLE} (detection_id, ${cols.join(', ')})
      SELECT id, ${cols.map(c => `COALESCE(${c}, '')`).join(', ')}
      FROM detections
    `);
  });
  build();

  // 'optimize' merges the segments FTS5 accumulates during a bulk load.
  // Without it the first queries pay for reading many small ones.
  try {
    db.exec(`INSERT INTO ${FTS_TABLE}(${FTS_TABLE}) VALUES('optimize')`);
  } catch {
    // Optimisation is a performance step, not a correctness one.
  }

  const rows = runQuery<{ n: number }>(`SELECT COUNT(*) AS n FROM ${FTS_TABLE}`)[0]?.n ?? 0;
  cachedStatus = null;
  return { rebuilt: true, rows, ms: Date.now() - t0 };
}

/**
 * Build an FTS5 MATCH expression from user terms.
 *
 * Every term is quoted and given a prefix wildcard, so "powershell" matches
 * "powershell.exe" and "certut" matches "certutil". The quoting is what makes
 * this safe: an unquoted term containing FTS5 syntax — a hyphen reads as NOT, a
 * colon as a column filter, AND/OR/NEAR as operators — would either error or
 * silently mean something else. `"term"*` is the documented prefix form for a
 * quoted string.
 *
 * Terms are AND-ed, matching the substring scorer: a multi-word query returns
 * rules containing every term.
 */
export function buildMatchExpression(terms: string[]): string {
  return terms
    .map(t => `"${t.replace(/"/g, '""')}"*`)
    .join(' AND ');
}
