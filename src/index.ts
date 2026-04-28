#!/usr/bin/env node
/**
 * Security Detections MCP - Enhanced Edition
 * 
 * Advanced MCP server for security detections with:
 * - Multi-source detection support (Sigma, Splunk ESCU, Elastic, KQL)
 * - Threat intelligence integration (MITRE ATT&CK, CVE/NVD, CISA KEV, LOLBAS)
 * - Knowledge graph with tribal knowledge (decisions, learnings, reasoning)
 * - Detection engineering intelligence patterns
 * - Dynamic LLM-created tables for persistent storage
 * 
 * Enhanced with data from reputable cybersecurity researchers and sources.
 */

import { createServer, startServer } from './server.js';
import { registerAllTools, getToolsSummary } from './tools/index.js';
import { initDbAsync } from './db/connection.js';
import { indexDetections, needsIndexing, getMissingSources, countExpectedFiles } from './indexer.js';
import { initKnowledgeSchema } from './db/knowledge.js';
import { initThreatIntelSchema } from './db/threat-intel.js';
import { initMitreAttackTables, indexMitreAttack, needsMitreIndexing, getMitreStats } from './db/mitre-attack.js';
import { initArtTables, syncArtRepo, indexArtTests, needsArtSync, getArtStats } from './db/atomic-red-team.js';
import { initCoverageEngineSchema } from './db/coverage-engine.js';
import { initSublimeTables, syncSublimeRepo, indexSublimeRules, needsSublimeSync, getSublimeStats } from './db/sublime-rules.js';
import { initLOLFarmSchema } from './db/lolfarm.js';
import * as path from 'path';
import * as fs from 'fs';

// Parse comma-separated paths from env var
function parsePaths(envVar: string | undefined): string[] {
  if (!envVar) return [];
  return envVar.split(',').map(p => p.trim()).filter(p => p.length > 0);
}

// Get configured paths from environment
const SIGMA_PATHS = parsePaths(process.env.SIGMA_PATHS);
const SPLUNK_PATHS = parsePaths(process.env.SPLUNK_PATHS);
const ELASTIC_PATHS = parsePaths(process.env.ELASTIC_PATHS);
const STORY_PATHS = parsePaths(process.env.STORY_PATHS);

// Auto-discover Sentinel directories: if KQL_PATHS points to Hunting Queries,
// also include sibling Detections/ and Solutions/ dirs for full coverage
function expandKqlPaths(raw: string[]): string[] {
  const expanded = new Set<string>();
  for (const p of raw) {
    expanded.add(p);
    // If this looks like a Sentinel repo path, auto-add sibling detection dirs
    const parent = path.dirname(p);
    const siblings = ['Detections', 'Solutions', 'Hunting Queries'];
    for (const sib of siblings) {
      const sibPath = path.join(parent, sib);
      if (fs.existsSync(sibPath) && !expanded.has(sibPath)) {
        expanded.add(sibPath);
        console.error(`[harris-hawkeye-mcp] Auto-discovered KQL path: ${sib}`);
      }
    }
  }
  return [...expanded];
}
const KQL_PATHS = expandKqlPaths(parsePaths(process.env.KQL_PATHS));

// Auto-index on startup if paths are configured and DB is empty or missing sources
function autoIndex(): void {
  if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0 && ELASTIC_PATHS.length === 0 && KQL_PATHS.length === 0) {
    return;
  }

  if (needsIndexing()) {
    // DB is empty — full index
    console.error('[harris-hawkeye-mcp] Auto-indexing detections...');
    const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);
    let msg = `[harris-hawkeye-mcp] Indexed ${result.total} detections`;
    msg += ` (${result.sigma_indexed} Sigma, ${result.splunk_indexed} Splunk, ${result.elastic_indexed} Elastic, ${result.kql_indexed} KQL)`;
    if (result.stories_indexed > 0) {
      msg += `, ${result.stories_indexed} stories`;
    }
    console.error(msg);
    return;
  }

  // DB has data — check for missing OR partially-indexed sources
  const expected = countExpectedFiles(SIGMA_PATHS, SPLUNK_PATHS, ELASTIC_PATHS, KQL_PATHS);
  const missing = getMissingSources(expected);
  const sigmaMissing = missing.sigma && SIGMA_PATHS.length > 0;
  const splunkMissing = missing.splunk && SPLUNK_PATHS.length > 0;
  const elasticMissing = missing.elastic && ELASTIC_PATHS.length > 0;
  const kqlMissing = missing.kql && KQL_PATHS.length > 0;

  if (!sigmaMissing && !splunkMissing && !elasticMissing && !kqlMissing) {
    return;
  }

  const sources: string[] = [];
  if (sigmaMissing) sources.push('Sigma');
  if (splunkMissing) sources.push('Splunk');
  if (elasticMissing) sources.push('Elastic');
  if (kqlMissing) sources.push('KQL');
  console.error(`[harris-hawkeye-mcp] Indexing missing sources: ${sources.join(', ')}...`);

  const result = indexDetections(
    sigmaMissing ? SIGMA_PATHS : [],
    splunkMissing ? SPLUNK_PATHS : [],
    splunkMissing ? STORY_PATHS : [],
    elasticMissing ? ELASTIC_PATHS : [],
    kqlMissing ? KQL_PATHS : [],
  );

  let msg = `[harris-hawkeye-mcp] Indexed ${result.total} new detections`;
  msg += ` (${result.sigma_indexed} Sigma, ${result.splunk_indexed} Splunk, ${result.elastic_indexed} Elastic, ${result.kql_indexed} KQL)`;
  if (result.stories_indexed > 0) {
    msg += `, ${result.stories_indexed} stories`;
  }
  console.error(msg);
}

// Auto-index MITRE ATT&CK data from STIX bundle
async function autoIndexMitre(): Promise<void> {
  // Look for MITRE ATT&CK STIX bundle in known locations
  const possiblePaths = [
    // From ELASTIC_PATHS (detection_rules package)
    ...ELASTIC_PATHS.map(p => path.join(path.dirname(p), 'detection_rules', 'etc', 'attack-v18.1.0.json.gz')),
    // Default location if ELASTIC_PATHS configured
    'rules/elastic/detection_rules/etc/attack-v18.1.0.json.gz',
  ];

  // Find first existing path
  let stixPath: string | null = null;
  for (const p of possiblePaths) {
    try {
      if (fs.existsSync(p)) {
        stixPath = p;
        break;
      }
    } catch {
      // Ignore errors
    }
  }

  if (!stixPath) {
    console.error('[harris-hawkeye-mcp] MITRE ATT&CK STIX bundle not found, skipping MITRE indexing');
    return;
  }

  if (!needsMitreIndexing()) {
    const stats = getMitreStats();
    console.error(`[harris-hawkeye-mcp] MITRE ATT&CK already indexed: ${stats.groups} groups, ${stats.malware + stats.tools} software, ${stats.techniques} techniques`);
    return;
  }

  console.error(`[harris-hawkeye-mcp] Indexing MITRE ATT&CK from ${stixPath}...`);
  const result = await indexMitreAttack(stixPath);
  console.error(`[harris-hawkeye-mcp] MITRE ATT&CK indexed: ${result.groups} groups, ${result.malware + result.tools} software, ${result.techniques} techniques, ${result.relationships} relationships`);
}

// Auto-index Sublime Security rules (git clone + YAML parse)
async function autoIndexSublime(): Promise<void> {
  try {
    const syncResult = await syncSublimeRepo();

    if (syncResult.action === 'cloned' || syncResult.action === 'pulled' || needsSublimeSync()) {
      console.error(`[harris-hawkeye-mcp] Indexing Sublime Security rules (${syncResult.action})...`);
      const result = await indexSublimeRules();
      console.error(
        `[harris-hawkeye-mcp] Sublime indexed: ${result.rules_indexed} rules`
      );
      if (result.errors.length > 0) {
        console.error(
          `[harris-hawkeye-mcp] Sublime indexing warnings: ${result.errors.length} parse errors`
        );
      }
    } else {
      const stats = getSublimeStats();
      console.error(
        `[harris-hawkeye-mcp] Sublime already indexed: ${stats.total_rules} rules`
      );
    }
  } catch (error) {
    // Non-fatal: Sublime rules are supplementary data
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[harris-hawkeye-mcp] Sublime sync/index failed (non-fatal): ${message}`);
  }
}

// Auto-index Atomic Red Team tests (git clone + YAML parse)
async function autoIndexArt(): Promise<void> {
  try {
    // Sync repo (clone or pull as needed)
    const syncResult = await syncArtRepo();

    if (syncResult.action === 'cloned' || syncResult.action === 'pulled' || needsArtSync()) {
      console.error(`[harris-hawkeye-mcp] Indexing Atomic Red Team (${syncResult.action})...`);
      const result = await indexArtTests();
      console.error(
        `[harris-hawkeye-mcp] ART indexed: ${result.tests_indexed} tests across ${result.techniques_parsed} techniques`
      );
      if (result.errors.length > 0) {
        console.error(
          `[harris-hawkeye-mcp] ART indexing warnings: ${result.errors.length} parse errors`
        );
      }
    } else {
      const stats = getArtStats();
      console.error(
        `[harris-hawkeye-mcp] ART already indexed: ${stats.total_tests} tests, ${stats.total_techniques} techniques`
      );
    }
  } catch (error) {
    // Non-fatal: ART is supplementary data — server works fine without it
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[harris-hawkeye-mcp] ART sync/index failed (non-fatal): ${message}`);
  }
}

async function main() {
  console.error('[harris-hawkeye-mcp] Starting Harris HawkEye MCP...');

  // Initialize database (async for sql.js)
  await initDbAsync();

  // Initialize schemas for enhanced features
  initKnowledgeSchema();
  initThreatIntelSchema();
  initMitreAttackTables();
  initArtTables();
  initCoverageEngineSchema();
  initSublimeTables();
  initLOLFarmSchema();

  // Register all tools from modules BEFORE starting server
  registerAllTools();

  // Log tool summary
  const summary = getToolsSummary();
  console.error(`[harris-hawkeye-mcp] ${summary.total} tools registered`);
  console.error(`[harris-hawkeye-mcp] Modules: ${Object.entries(summary.byModule).map(([k, v]) => `${k}(${v})`).join(', ')}`);

  // Create and start server FIRST so MCP handshake completes immediately
  const server = createServer();
  await startServer(server);

  // THEN index detections in the background (after server is connected)
  // This prevents the 60-second MCP handshake timeout
  autoIndex();
  await autoIndexMitre();
  await autoIndexArt();
  await autoIndexSublime();

  console.error('[harris-hawkeye-mcp] Indexing complete — fully ready');
}

main().catch((error) => {
  console.error('[harris-hawkeye-mcp] Fatal error:', error);
  process.exit(1);
});
