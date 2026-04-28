// Atomic Red Team (ART) Database Schema, Git Sync, YAML Parser, and Query Functions
// Provides adversary simulation test data for detection validation
//
// Pattern follows src/db/mitre-attack.ts:
//   initArtTables() → syncArtRepo() → indexArtTests() → query functions

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { parse as parseYaml } from 'yaml';
import { runQuery, runBulkStatement, getDb, saveDb } from './connection.js';

// ── Interfaces matching ART YAML schema ──────────────────────────────────

interface ARTInputArgument {
  description: string;
  type: string;
  default: string | number | boolean;
}

interface ARTDependency {
  description: string;
  prereq_command: string;
  get_prereq_command: string;
}

interface ARTExecutor {
  name: string;
  command?: string;
  cleanup_command?: string;
  elevation_required?: boolean;
  steps?: string; // For 'manual' executor type
}

interface ARTTest {
  name: string;
  auto_generated_guid: string;
  description: string;
  supported_platforms: string[];
  executor: ARTExecutor;
  input_arguments?: Record<string, ARTInputArgument>;
  dependencies?: ARTDependency[];
  dependency_executor_name?: string;
}

interface ARTTechnique {
  attack_technique: string;
  display_name: string;
  atomic_tests: ARTTest[];
}

// ── Row type returned by queries ─────────────────────────────────────────

export interface ARTTestRow {
  guid: string;
  technique_id: string;
  technique_name: string;
  test_name: string;
  test_number: number;
  description: string | null;
  supported_platforms: string; // JSON array
  executor_name: string;
  command: string | null;
  cleanup_command: string | null;
  elevation_required: number;
  input_arguments: string | null; // JSON
  dependencies: string | null; // JSON
  dependency_executor_name: string | null;
  search_text: string;
  indexed_at: string;
}

// ── Schema Initialization ────────────────────────────────────────────────

export function initArtTables(): void {
  const db = getDb();

  db.run(`
    CREATE TABLE IF NOT EXISTS art_tests (
      guid TEXT PRIMARY KEY,
      technique_id TEXT NOT NULL,
      technique_name TEXT NOT NULL,
      test_name TEXT NOT NULL,
      test_number INTEGER NOT NULL,
      description TEXT,
      supported_platforms TEXT NOT NULL,
      executor_name TEXT NOT NULL,
      command TEXT,
      cleanup_command TEXT,
      elevation_required INTEGER DEFAULT 0,
      input_arguments TEXT,
      dependencies TEXT,
      dependency_executor_name TEXT,
      search_text TEXT,
      indexed_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`CREATE INDEX IF NOT EXISTS idx_art_technique ON art_tests(technique_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_art_executor ON art_tests(executor_name)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_art_name ON art_tests(test_name)`);

  db.run(`
    CREATE TABLE IF NOT EXISTS art_sync_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

// ── Repository Path Resolution ───────────────────────────────────────────

export function getArtRepoPath(): string {
  if (process.env.ART_REPO_PATH) {
    return process.env.ART_REPO_PATH;
  }
  // Default: data/atomic-red-team relative to project root
  return path.join(process.cwd(), 'data', 'atomic-red-team');
}

// ── Sync State Checks ────────────────────────────────────────────────────

export function needsArtSync(): boolean {
  try {
    const result = runQuery<{ count: number }>(
      'SELECT COUNT(*) as count FROM art_tests'
    );
    return (result[0]?.count || 0) === 0;
  } catch {
    return true;
  }
}

export function isArtStale(): boolean {
  try {
    const result = runQuery<{ value: string }>(
      "SELECT value FROM art_sync_meta WHERE key = 'last_sync_timestamp'"
    );
    if (!result[0]?.value) return true;

    const lastSync = new Date(result[0].value);
    const now = new Date();
    const daysSinceSync = (now.getTime() - lastSync.getTime()) / (1000 * 60 * 60 * 24);
    return daysSinceSync > 7;
  } catch {
    return true;
  }
}

// ── Git Repository Sync ──────────────────────────────────────────────────

export async function syncArtRepo(): Promise<{ action: 'cloned' | 'pulled' | 'skipped'; path: string }> {
  const repoPath = getArtRepoPath();
  const atomicsPath = path.join(repoPath, 'atomics');

  // Check if repo exists and has atomics directory
  if (!fs.existsSync(repoPath) || !fs.existsSync(atomicsPath)) {
    console.error('[art] Cloning Atomic Red Team repository (sparse — atomics/ only)...');

    // Ensure parent directory exists
    const parentDir = path.dirname(repoPath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }

    try {
      // Sparse clone: only checkout the atomics/ directory to save disk space
      execSync(
        `git clone --depth 1 --filter=blob:none --sparse "https://github.com/redcanaryco/atomic-red-team.git" "${repoPath}"`,
        { timeout: 180000, stdio: 'pipe' }
      );
      execSync('git sparse-checkout set atomics', {
        cwd: repoPath,
        timeout: 120000,
        stdio: 'pipe',
      });
      console.error(`[art] Repository cloned to ${repoPath}`);
      return { action: 'cloned', path: repoPath };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // If sparse clone fails, try regular shallow clone as fallback
      console.error(`[art] Sparse clone failed (${message}), trying shallow clone...`);
      try {
        // Clean up failed sparse clone
        if (fs.existsSync(repoPath)) {
          fs.rmSync(repoPath, { recursive: true, force: true });
        }
        execSync(
          `git clone --depth 1 "https://github.com/redcanaryco/atomic-red-team.git" "${repoPath}"`,
          { timeout: 300000, stdio: 'pipe' }
        );
        console.error(`[art] Repository cloned (full shallow) to ${repoPath}`);
        return { action: 'cloned', path: repoPath };
      } catch (fallbackError) {
        const fbMsg = fallbackError instanceof Error ? fallbackError.message : String(fallbackError);
        throw new Error(`Failed to clone ART repository: ${fbMsg}`);
      }
    }
  }

  // Repo exists — pull if stale
  if (isArtStale()) {
    console.error('[art] Pulling latest Atomic Red Team updates...');
    try {
      execSync('git pull --ff-only', {
        cwd: repoPath,
        timeout: 60000,
        stdio: 'pipe',
      });
      console.error('[art] Repository updated');
      return { action: 'pulled', path: repoPath };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[art] Pull failed (non-fatal, using cached data): ${message}`);
      return { action: 'skipped', path: repoPath };
    }
  }

  return { action: 'skipped', path: repoPath };
}

// ── YAML Parsing & Indexing ──────────────────────────────────────────────

export async function indexArtTests(): Promise<{
  techniques_parsed: number;
  tests_indexed: number;
  errors: string[];
}> {
  const repoPath = getArtRepoPath();
  const atomicsDir = path.join(repoPath, 'atomics');

  if (!fs.existsSync(atomicsDir)) {
    throw new Error(`ART atomics directory not found: ${atomicsDir}`);
  }

  // Find all technique directories (T1234, T1234.001, etc.)
  const techniqueDirs = fs.readdirSync(atomicsDir)
    .filter(d => /^T\d{4}/.test(d))
    .map(d => path.join(atomicsDir, d))
    .filter(d => fs.statSync(d).isDirectory());

  const database = getDb();
  database.run('BEGIN TRANSACTION');

  // Clear existing data for clean re-index
  runBulkStatement('DELETE FROM art_tests');

  let testsIndexed = 0;
  let techniquesParsed = 0;
  const errors: string[] = [];

  for (const techniqueDir of techniqueDirs) {
    const dirName = path.basename(techniqueDir);
    const yamlFile = `${dirName}.yaml`;
    const yamlPath = path.join(techniqueDir, yamlFile);

    if (!fs.existsSync(yamlPath)) continue;

    try {
      const content = fs.readFileSync(yamlPath, 'utf-8');
      const technique = parseYaml(content) as ARTTechnique;

      if (!technique?.atomic_tests || !Array.isArray(technique.atomic_tests)) continue;
      techniquesParsed++;

      for (let i = 0; i < technique.atomic_tests.length; i++) {
        const test = technique.atomic_tests[i];
        if (!test.auto_generated_guid || !test.name) continue;

        // Build search_text for full-text LIKE search
        const searchParts: string[] = [
          technique.attack_technique || '',
          technique.display_name || '',
          test.name || '',
          test.description || '',
          test.executor?.command || '',
          test.executor?.cleanup_command || '',
          test.executor?.name || '',
          ...(test.supported_platforms || []),
        ];

        // Include input argument names, defaults, and descriptions
        if (test.input_arguments) {
          for (const [argName, arg] of Object.entries(test.input_arguments)) {
            searchParts.push(argName);
            if (arg.default !== undefined && arg.default !== null) {
              searchParts.push(String(arg.default));
            }
            if (arg.description) {
              searchParts.push(arg.description);
            }
          }
        }

        // Include dependency descriptions
        if (test.dependencies) {
          for (const dep of test.dependencies) {
            if (dep.description) searchParts.push(dep.description);
            if (dep.prereq_command) searchParts.push(dep.prereq_command);
          }
        }

        const searchText = searchParts.join(' ').toLowerCase();

        runBulkStatement(
          `INSERT OR REPLACE INTO art_tests
           (guid, technique_id, technique_name, test_name, test_number,
            description, supported_platforms, executor_name, command,
            cleanup_command, elevation_required, input_arguments,
            dependencies, dependency_executor_name, search_text)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            test.auto_generated_guid,
            technique.attack_technique,
            technique.display_name || '',
            test.name,
            i + 1,
            test.description || null,
            JSON.stringify(test.supported_platforms || []),
            test.executor?.name || 'manual',
            test.executor?.command || test.executor?.steps || null,
            test.executor?.cleanup_command || null,
            test.executor?.elevation_required ? 1 : 0,
            test.input_arguments ? JSON.stringify(test.input_arguments) : null,
            test.dependencies ? JSON.stringify(test.dependencies) : null,
            test.dependency_executor_name || null,
            searchText,
          ]
        );
        testsIndexed++;
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      errors.push(`${yamlFile}: ${msg}`);
    }
  }

  // Update sync metadata
  runBulkStatement(
    `INSERT OR REPLACE INTO art_sync_meta (key, value, updated_at)
     VALUES ('last_sync_timestamp', ?, datetime('now'))`,
    [new Date().toISOString()]
  );
  runBulkStatement(
    `INSERT OR REPLACE INTO art_sync_meta (key, value, updated_at)
     VALUES ('tests_count', ?, datetime('now'))`,
    [String(testsIndexed)]
  );
  runBulkStatement(
    `INSERT OR REPLACE INTO art_sync_meta (key, value, updated_at)
     VALUES ('techniques_count', ?, datetime('now'))`,
    [String(techniquesParsed)]
  );

  database.run('COMMIT');
  saveDb();

  return { techniques_parsed: techniquesParsed, tests_indexed: testsIndexed, errors };
}

// ── Query Functions ──────────────────────────────────────────────────────

export function getTestsByTechnique(techniqueId: string): ARTTestRow[] {
  const normalized = techniqueId.toUpperCase().trim();
  return runQuery<ARTTestRow>(
    'SELECT * FROM art_tests WHERE technique_id = ? ORDER BY test_number',
    [normalized]
  );
}

export function searchArtTests(query: string, limit: number = 30): ARTTestRow[] {
  const term = query.toLowerCase().trim();
  return runQuery<ARTTestRow>(
    'SELECT * FROM art_tests WHERE search_text LIKE ? ORDER BY technique_id, test_number LIMIT ?',
    [`%${term}%`, limit]
  );
}

export function getTestByGuid(guid: string): ARTTestRow | null {
  const results = runQuery<ARTTestRow>(
    'SELECT * FROM art_tests WHERE guid = ?',
    [guid]
  );
  return results[0] || null;
}

export function getArtStats(): {
  total_tests: number;
  total_techniques: number;
  by_platform: Record<string, number>;
  by_executor: Record<string, number>;
  top_techniques: Array<{ technique_id: string; technique_name: string; test_count: number }>;
  last_synced: string | null;
} {
  const total = runQuery<{ count: number }>(
    'SELECT COUNT(*) as count FROM art_tests'
  )[0]?.count || 0;

  const techniques = runQuery<{ count: number }>(
    'SELECT COUNT(DISTINCT technique_id) as count FROM art_tests'
  )[0]?.count || 0;

  // Platform counts — need to parse JSON arrays
  const platformCounts: Record<string, number> = {};
  if (total > 0) {
    const allPlatforms = runQuery<{ supported_platforms: string }>(
      'SELECT supported_platforms FROM art_tests'
    );
    for (const row of allPlatforms) {
      try {
        const platforms = JSON.parse(row.supported_platforms) as string[];
        for (const p of platforms) {
          platformCounts[p] = (platformCounts[p] || 0) + 1;
        }
      } catch {
        // Skip malformed rows
      }
    }
  }

  // Executor counts
  const executorRows = runQuery<{ executor_name: string; count: number }>(
    'SELECT executor_name, COUNT(*) as count FROM art_tests GROUP BY executor_name ORDER BY count DESC'
  );
  const byExecutor: Record<string, number> = {};
  for (const row of executorRows) {
    byExecutor[row.executor_name] = row.count;
  }

  // Top techniques by test count
  const topTechniques = runQuery<{ technique_id: string; technique_name: string; test_count: number }>(
    `SELECT technique_id, technique_name, COUNT(*) as test_count
     FROM art_tests GROUP BY technique_id ORDER BY test_count DESC LIMIT 15`
  );

  // Last sync timestamp
  const lastSynced = runQuery<{ value: string }>(
    "SELECT value FROM art_sync_meta WHERE key = 'last_sync_timestamp'"
  );

  return {
    total_tests: total,
    total_techniques: techniques,
    by_platform: platformCounts,
    by_executor: byExecutor,
    top_techniques: topTechniques,
    last_synced: lastSynced[0]?.value || null,
  };
}
