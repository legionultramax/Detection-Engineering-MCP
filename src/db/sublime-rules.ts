// Sublime Security Detection Rules — Git Sync, YAML Parser, and Indexer
//
// Ingests email detection rules from https://github.com/sublime-security/sublime-rules
// into the existing `detections` table with source_type = 'sublime'.
//
// Pattern follows src/db/atomic-red-team.ts:
//   initSublimeTables() → syncSublimeRepo() → indexSublimeRules() → query functions

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { parse as parseYaml } from 'yaml';
import { runQuery, runBulkStatement, getDb, saveDb } from './connection.js';

// ── Interfaces matching Sublime Security YAML schema ─────────────────────

interface SublimeRule {
  id?: string;
  name?: string;
  description?: string;
  type?: string;
  severity?: string;
  source?: string;
  tags?: string[];
  attack_types?: string[];
  tactics_and_techniques?: string[];
  detection_methods?: string[];
  references?: string[];
  authors?: Array<{ name?: string; twitter?: string } | string>;
}

// ── MITRE ATT&CK heuristic mapping ───────────────────────────────────────
// Sublime uses descriptive attack_types / tactics_and_techniques, not T-IDs.
// This table provides a best-effort mapping for search compatibility.

const ATTACK_TYPE_TO_TECHNIQUES: Record<string, string[]> = {
  'credential phishing':    ['T1566', 'T1566.002', 'T1598', 'T1598.003'],
  'bec/fraud':              ['T1534', 'T1566', 'T1585'],
  'malware/ransomware':     ['T1566', 'T1566.001', 'T1204', 'T1204.002'],
  'callback phishing':      ['T1566', 'T1566.002', 'T1598'],
  'spam':                   ['T1566'],
  'extortion':              ['T1566', 'T1585'],
  'social engineering':     ['T1566', 'T1534'],
  'supply chain':           ['T1195', 'T1566'],
  'data exfiltration':      ['T1048', 'T1567'],
  'account takeover':       ['T1078', 'T1586'],
};

const TACTIC_TO_TECHNIQUES: Record<string, string[]> = {
  'impersonation: brand':    ['T1566', 'T1585.002'],
  'impersonation: employee': ['T1534', 'T1566'],
  'impersonation: vip':      ['T1534', 'T1566'],
  'evasion':                 ['T1027', 'T1036'],
  'exploit':                 ['T1203'],
  'social engineering':      ['T1566', 'T1534'],
  'reconnaissance':          ['T1598'],
  'free subdomain':          ['T1583.001'],
  'open redirect':           ['T1027'],
  'url shortener':           ['T1027'],
};

function mapToMitreTechniques(
  attackTypes: string[] = [],
  tacticsAndTechniques: string[] = []
): string[] {
  const seen = new Set<string>();
  const result: string[] = [];

  const add = (techniques: string[] | undefined) => {
    if (!techniques) return;
    for (const t of techniques) {
      if (!seen.has(t)) {
        seen.add(t);
        result.push(t);
      }
    }
  };

  for (const at of attackTypes) {
    add(ATTACK_TYPE_TO_TECHNIQUES[at.toLowerCase()]);
  }
  for (const tt of tacticsAndTechniques) {
    add(TACTIC_TO_TECHNIQUES[tt.toLowerCase()]);
  }

  return result;
}

// ── Detection method → data source label ─────────────────────────────────

const DETECTION_METHOD_TO_DATA_SOURCE: Record<string, string> = {
  'header analysis':              'Email Headers',
  'sender analysis':              'Email Addresses',
  'content analysis':             'Email Body',
  'natural language understanding': 'Email Body',
  'archive analysis':             'Email Attachments',
  'file analysis':                'Email Attachments',
  'yara':                         'Email Attachments',
  'url analysis':                 'Email Links',
  'link analysis':                'Email Links',
  'whois':                        'Domain Registration',
  'computer vision':              'Email Images',
  'recipient analysis':           'Email Recipients',
};

function mapToDataSources(detectionMethods: string[] = []): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const method of detectionMethods) {
    const ds = DETECTION_METHOD_TO_DATA_SOURCE[method.toLowerCase()];
    if (ds && !seen.has(ds)) {
      seen.add(ds);
      result.push(ds);
    }
  }
  // Always include base email data source
  if (!seen.has('Email Messages')) result.push('Email Messages');
  return result;
}

// ── Schema Initialization ────────────────────────────────────────────────

export function initSublimeTables(): void {
  const db = getDb();

  db.run(`
    CREATE TABLE IF NOT EXISTS sublime_sync_meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

// ── Repository Path Resolution ───────────────────────────────────────────

export function getSublimeRepoPath(): string {
  if (process.env.SUBLIME_REPO_PATH) {
    return process.env.SUBLIME_REPO_PATH;
  }
  return path.join(process.cwd(), 'data', 'sublime-rules');
}

// ── Sync State Checks ────────────────────────────────────────────────────

export function needsSublimeSync(): boolean {
  try {
    const result = runQuery<{ count: number }>(
      "SELECT COUNT(*) as count FROM detections WHERE source_type = 'sublime'"
    );
    return (result[0]?.count || 0) === 0;
  } catch {
    return true;
  }
}

export function isSublimeStale(): boolean {
  try {
    const result = runQuery<{ value: string }>(
      "SELECT value FROM sublime_sync_meta WHERE key = 'last_sync_timestamp'"
    );
    if (!result[0]?.value) return true;

    const lastSync = new Date(result[0].value);
    const daysSinceSync =
      (Date.now() - lastSync.getTime()) / (1000 * 60 * 60 * 24);
    return daysSinceSync > 7;
  } catch {
    return true;
  }
}

// ── Git Repository Sync ──────────────────────────────────────────────────

export async function syncSublimeRepo(): Promise<{
  action: 'cloned' | 'pulled' | 'skipped';
  path: string;
}> {
  const repoPath = getSublimeRepoPath();
  const rulesPath = path.join(repoPath, 'detection-rules');

  if (!fs.existsSync(repoPath) || !fs.existsSync(rulesPath)) {
    console.error('[sublime] Cloning sublime-rules repository...');

    const parentDir = path.dirname(repoPath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }

    try {
      execSync(
        `git clone --depth 1 "https://github.com/sublime-security/sublime-rules.git" "${repoPath}"`,
        { timeout: 300000, stdio: 'pipe' }
      );
      console.error(`[sublime] Repository cloned to ${repoPath}`);
      return { action: 'cloned', path: repoPath };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to clone sublime-rules repository: ${message}`);
    }
  }

  if (isSublimeStale()) {
    console.error('[sublime] Pulling latest sublime-rules updates...');
    try {
      execSync('git pull --ff-only', {
        cwd: repoPath,
        timeout: 60000,
        stdio: 'pipe',
      });
      console.error('[sublime] Repository updated');
      return { action: 'pulled', path: repoPath };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[sublime] Pull failed (non-fatal, using cached data): ${message}`);
      return { action: 'skipped', path: repoPath };
    }
  }

  return { action: 'skipped', path: repoPath };
}

// ── YAML Parsing & Indexing ──────────────────────────────────────────────

function findYamlFiles(dir: string): string[] {
  const files: string[] = [];
  if (!fs.existsSync(dir)) return files;

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...findYamlFiles(full));
    } else if (
      entry.isFile() &&
      (entry.name.endsWith('.yml') || entry.name.endsWith('.yaml'))
    ) {
      files.push(full);
    }
  }
  return files;
}

function extractAuthor(rule: SublimeRule): string {
  if (!rule.authors || rule.authors.length === 0) return 'Sublime Security';
  return rule.authors
    .map((a) => (typeof a === 'string' ? a : a.name || ''))
    .filter(Boolean)
    .join(', ') || 'Sublime Security';
}

function normalizeSeverity(sev: string | undefined): string {
  const s = (sev || 'medium').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'low') return 'low';
  return 'medium';
}

export async function indexSublimeRules(): Promise<{
  rules_indexed: number;
  errors: string[];
}> {
  const repoPath = getSublimeRepoPath();
  const rulesDir = path.join(repoPath, 'detection-rules');

  if (!fs.existsSync(rulesDir)) {
    throw new Error(`Sublime rules directory not found: ${rulesDir}`);
  }

  const files = findYamlFiles(rulesDir);
  const database = getDb();
  database.run('BEGIN TRANSACTION');

  // Clear existing sublime detections for a clean re-index
  runBulkStatement("DELETE FROM detections WHERE source_type = 'sublime'");

  let rulesIndexed = 0;
  const errors: string[] = [];

  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content) as SublimeRule;

      if (!rule || !rule.name || !rule.source) continue;
      if (rule.type && rule.type !== 'rule') continue; // skip non-detection types

      const ruleUuid = rule.id || '';
      const id = `sublime_${ruleUuid || path.basename(filePath, path.extname(filePath))}`;

      const mitreTechniques = mapToMitreTechniques(
        rule.attack_types,
        rule.tactics_and_techniques
      );

      // Tactics: derive from techniques (T1566 → initial-access, etc.)
      const mitreTactics = deriveTactics(mitreTechniques);

      const dataSources = mapToDataSources(rule.detection_methods);

      const allTags = [
        ...(rule.tags || []),
        ...(rule.attack_types || []),
        ...(rule.tactics_and_techniques || []),
        ...(rule.detection_methods || []),
      ];

      const author = extractAuthor(rule);
      const severity = normalizeSeverity(rule.severity);

      // Build search_text for LIKE-based full-text search
      const searchText = [
        rule.name,
        rule.description || '',
        rule.source,
        (rule.attack_types || []).join(' '),
        (rule.tactics_and_techniques || []).join(' '),
        (rule.detection_methods || []).join(' '),
        (rule.tags || []).join(' '),
        (rule.references || []).join(' '),
        mitreTechniques.join(' '),
      ]
        .join(' ')
        .toLowerCase();

      runBulkStatement(
        `INSERT OR REPLACE INTO detections
         (id, name, description, source_type, severity, status, author,
          date_created, date_modified, query, raw_content, file_path,
          mitre_tactics, mitre_techniques, tags, refs, false_positives,
          search_text, logsource_category, logsource_product, logsource_service,
          data_sources, detection_type, asset_type, security_domain,
          platforms, cves, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          id,
          rule.name,
          rule.description || null,
          'sublime',
          severity,
          'production',
          author,
          null, // date_created — not in YAML
          null, // date_modified — not in YAML
          rule.source,
          content,
          filePath,
          JSON.stringify(mitreTactics),
          JSON.stringify(mitreTechniques),
          JSON.stringify(allTags),
          JSON.stringify(rule.references || []),
          null, // false_positives — not in YAML
          searchText,
          (rule.attack_types || ['email'])[0] || 'email', // logsource_category
          'sublime',                                        // logsource_product
          'email',                                          // logsource_service
          JSON.stringify(dataSources),
          'TTP',
          'email',  // asset_type
          'email',  // security_domain
          JSON.stringify(['email']),
          JSON.stringify([]), // cves — none in Sublime rules
        ]
      );

      rulesIndexed++;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      errors.push(`${path.basename(filePath)}: ${msg}`);
    }
  }

  // Update sync metadata
  runBulkStatement(
    `INSERT OR REPLACE INTO sublime_sync_meta (key, value, updated_at)
     VALUES ('last_sync_timestamp', ?, datetime('now'))`,
    [new Date().toISOString()]
  );
  runBulkStatement(
    `INSERT OR REPLACE INTO sublime_sync_meta (key, value, updated_at)
     VALUES ('rules_count', ?, datetime('now'))`,
    [String(rulesIndexed)]
  );

  database.run('COMMIT');
  saveDb();

  return { rules_indexed: rulesIndexed, errors };
}

// ── Tactic derivation from technique IDs ────────────────────────────────
// Minimal map covering the techniques we produce from Sublime attack_types.

const TECHNIQUE_TO_TACTIC: Record<string, string> = {
  T1566:     'initial-access',
  'T1566.001': 'initial-access',
  'T1566.002': 'initial-access',
  T1534:     'lateral-movement',
  T1598:     'reconnaissance',
  'T1598.003': 'reconnaissance',
  T1203:     'execution',
  T1204:     'execution',
  'T1204.002': 'execution',
  T1195:     'initial-access',
  T1027:     'defense-evasion',
  T1036:     'defense-evasion',
  T1078:     'defense-evasion',
  T1583:     'resource-development',
  'T1583.001': 'resource-development',
  T1585:     'resource-development',
  'T1585.002': 'resource-development',
  T1586:     'resource-development',
  T1048:     'exfiltration',
  T1567:     'exfiltration',
};

function deriveTactics(techniques: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const t of techniques) {
    const tactic = TECHNIQUE_TO_TACTIC[t];
    if (tactic && !seen.has(tactic)) {
      seen.add(tactic);
      result.push(tactic);
    }
  }
  return result;
}

// ── Query Functions ──────────────────────────────────────────────────────

export interface SublimeRuleRow {
  id: string;
  name: string;
  description: string | null;
  severity: string;
  author: string;
  query: string;
  file_path: string;
  mitre_techniques: string; // JSON array
  tags: string;             // JSON array
  data_sources: string;     // JSON array
  refs: string;             // JSON array
  logsource_category: string | null;
  search_text: string;
  updated_at: string;
}

export function searchSublimeRules(query: string, limit = 30): SublimeRuleRow[] {
  const term = `%${query.toLowerCase()}%`;
  return runQuery<SublimeRuleRow>(
    `SELECT id, name, description, severity, author, query, file_path,
            mitre_techniques, tags, data_sources, refs, logsource_category,
            search_text, updated_at
     FROM detections
     WHERE source_type = 'sublime' AND search_text LIKE ?
     ORDER BY
       CASE severity
         WHEN 'critical' THEN 1 WHEN 'high' THEN 2
         WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4
         ELSE 5
       END
     LIMIT ?`,
    [term, limit]
  );
}

export function getSublimeRule(id: string): SublimeRuleRow | null {
  const rows = runQuery<SublimeRuleRow>(
    `SELECT * FROM detections WHERE id = ? AND source_type = 'sublime'`,
    [id]
  );
  return rows[0] || null;
}

export function getSublimeStats(): {
  total_rules: number;
  by_severity: Record<string, number>;
  by_attack_type: Record<string, number>;
  top_techniques: Array<{ technique: string; count: number }>;
  last_synced: string | null;
} {
  const total =
    runQuery<{ count: number }>(
      "SELECT COUNT(*) as count FROM detections WHERE source_type = 'sublime'"
    )[0]?.count || 0;

  // Severity breakdown
  const sevRows = runQuery<{ severity: string; count: number }>(
    `SELECT severity, COUNT(*) as count
     FROM detections WHERE source_type = 'sublime'
     GROUP BY severity ORDER BY count DESC`
  );
  const bySeverity: Record<string, number> = {};
  for (const r of sevRows) bySeverity[r.severity] = r.count;

  // Attack type breakdown (from logsource_category which stores first attack_type)
  const catRows = runQuery<{ logsource_category: string; count: number }>(
    `SELECT logsource_category, COUNT(*) as count
     FROM detections WHERE source_type = 'sublime' AND logsource_category IS NOT NULL
     GROUP BY logsource_category ORDER BY count DESC`
  );
  const byAttackType: Record<string, number> = {};
  for (const r of catRows) {
    if (r.logsource_category) byAttackType[r.logsource_category] = r.count;
  }

  // Top MITRE techniques (parse JSON arrays and count)
  const techCounts: Record<string, number> = {};
  if (total > 0) {
    const techRows = runQuery<{ mitre_techniques: string }>(
      "SELECT mitre_techniques FROM detections WHERE source_type = 'sublime' AND mitre_techniques IS NOT NULL"
    );
    for (const row of techRows) {
      try {
        const techs = JSON.parse(row.mitre_techniques) as string[];
        for (const t of techs) {
          techCounts[t] = (techCounts[t] || 0) + 1;
        }
      } catch {
        // skip malformed rows
      }
    }
  }
  const topTechniques = Object.entries(techCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([technique, count]) => ({ technique, count }));

  const lastSynced =
    runQuery<{ value: string }>(
      "SELECT value FROM sublime_sync_meta WHERE key = 'last_sync_timestamp'"
    )[0]?.value || null;

  return {
    total_rules: total,
    by_severity: bySeverity,
    by_attack_type: byAttackType,
    top_techniques: topTechniques,
    last_synced: lastSynced,
  };
}
