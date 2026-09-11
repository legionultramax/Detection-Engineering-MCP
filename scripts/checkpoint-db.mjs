#!/usr/bin/env node
/**
 * Fold the write-ahead log into the database file, so a plain copy is complete.
 *
 * This exists because of a real near-miss. The server runs SQLite in WAL mode,
 * which means recent writes live in `detections.db-wal` until a checkpoint
 * moves them into `detections.db`. A reader that opens the database sees both
 * and reports the full count, so nothing looks wrong — but `cp detections.db`
 * copies only the main file, and the copy silently lacks whatever the WAL was
 * still holding.
 *
 * Measured: a copy taken with 4 MB outstanding in the WAL was missing 68 LoFP
 * rows. The counts matched everywhere except in the copy, which is the worst
 * shape for this kind of bug — it surfaces on the target machine, after the
 * source is gone.
 *
 * MIGRATION-SOP.md previously said "copy detections.db. Nothing else in data/
 * is needed." That is true only after this has run.
 *
 * Usage:
 *   npm run db:checkpoint
 *   DETECTIONS_DB_PATH=/abs/path/detections.db npm run db:checkpoint
 */
import Database from 'better-sqlite3';
import { existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DB = process.env.DETECTIONS_DB_PATH ?? path.join(ROOT, 'data', 'detections.db');

if (!existsSync(DB)) {
  console.error(`error: no database at ${DB}.`);
  console.error('Set DETECTIONS_DB_PATH, or build the index first.');
  process.exit(2);
}

const sizeOf = (p) => (existsSync(p) ? statSync(p).size : 0);
const walPath = `${DB}-wal`;
const shmPath = `${DB}-shm`;

const walBefore = sizeOf(walPath);
console.log(`database : ${DB}`);
console.log(`main     : ${(sizeOf(DB) / 1024 / 1024).toFixed(1)} MB`);
console.log(`wal      : ${(walBefore / 1024 / 1024).toFixed(2)} MB${walBefore === 0 ? ' (nothing outstanding)' : ''}`);

// Must be writable: a checkpoint is a write, which is also why this is a
// separate script rather than something the read-only server does at exit.
let db;
try {
  db = new Database(DB);
} catch (err) {
  console.error(`error: could not open the database for writing — ${err.message}`);
  console.error('Stop any running server first; a checkpoint needs write access.');
  process.exit(1);
}

// TRUNCATE blocks until every reader has finished and then zeroes the WAL,
// which is what makes the subsequent file copy self-contained. PASSIVE would
// return immediately and might copy nothing at all.
const [busy, logFrames, checkpointed] = (() => {
  const r = db.pragma('wal_checkpoint(TRUNCATE)');
  const row = Array.isArray(r) ? r[0] : r;
  return [row?.busy, row?.log, row?.checkpointed];
})();

db.close();

if (busy !== 0) {
  console.error(
    `\nerror: checkpoint blocked (busy=${busy}). Another process holds the database open — ` +
    'stop the server and run this again. The WAL was not folded in, so a copy taken now would ' +
    'be incomplete.'
  );
  process.exit(1);
}

const walAfter = sizeOf(walPath);
console.log(`\ncheckpointed ${checkpointed} of ${logFrames} frames.`);
console.log(`wal now  : ${(walAfter / 1024 / 1024).toFixed(2)} MB`);
console.log(`shm      : ${sizeOf(shmPath) === 0 ? 'removed' : `${sizeOf(shmPath)} bytes`}`);

if (walAfter > 0) {
  console.error(
    '\nwarning: the WAL is not empty. Copy detections.db-wal and -shm alongside the database, ' +
    'or run this again with nothing else connected.'
  );
  process.exit(1);
}

console.log('\nok — detections.db is self-contained. Copying it alone is now safe.');
