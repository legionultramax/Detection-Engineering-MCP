#!/usr/bin/env node
/**
 * Build the FTS5 full-text index over the detection corpus.
 *
 * The indexer already does this after a run, so this exists for the case that
 * matters in deployment: a database that was indexed before the index existed,
 * or one whose index has gone stale. The read-only server cannot build it, so
 * it has to be built here and shipped inside the database file.
 *
 * Local only, no network.
 *
 * Usage:
 *   npm run fts:build                     # build against data/detections.db
 *   DETECTIONS_DB_PATH=/x npm run fts:build
 *   npm run fts:build -- --status         # report without changing anything
 */
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const statusOnly = process.argv.slice(2).includes('--status');

if (!process.env.DETECTIONS_DB_PATH) {
  const local = path.join(ROOT, 'data', 'detections.db');
  if (!existsSync(local)) {
    console.error(`error: no database at ${local}. Set DETECTIONS_DB_PATH.`);
    process.exit(2);
  }
  process.env.DETECTIONS_DB_PATH = local;
}
// Building requires a writable connection by definition.
if (statusOnly) process.env.HAWKEYE_READONLY = '1';
else delete process.env.HAWKEYE_READONLY;

const dist = path.join(ROOT, 'dist', 'db', 'connection.js');
if (!existsSync(dist)) {
  console.error('error: dist not found — run "npm run build" first.');
  process.exit(2);
}

const conn = await import(pathToFileURL(dist).href);
const fts = await import(pathToFileURL(path.join(ROOT, 'dist', 'db', 'fts.js')).href);
await conn.initDbAsync();

const before = fts.ftsStatus(true);
console.log(`database:   ${process.env.DETECTIONS_DB_PATH}`);
console.log(`detections: ${before.detections}`);
console.log(`index:      ${before.available ? `${before.rows} rows, current` : before.reason}`);

if (statusOnly) {
  conn.closeDb();
  process.exit(before.available ? 0 : 1);
}

if (before.available) {
  console.log('\nAlready current. Rebuilding anyway so the result is deterministic.');
}
const r = fts.rebuildFtsIndex();
if (!r.rebuilt) {
  console.error(`\nnot rebuilt: ${r.reason}`);
  conn.closeDb();
  process.exit(1);
}
console.log(`\nrebuilt: ${r.rows} rows in ${r.ms}ms`);

const after = fts.ftsStatus(true);
console.log(`status:  ${after.available ? 'current' : after.reason}`);
conn.closeDb();
process.exit(after.available ? 0 : 1);
