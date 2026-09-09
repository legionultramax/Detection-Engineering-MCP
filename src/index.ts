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
import { registerAllTools, getToolsSummary, toolRegistry } from './tools/index.js';
import { resolveProfile, unresolvedNames, PROFILES, WRITE_TOOLS } from './tools/profiles.js';
import { initDbAsync, isReadOnly, runQuery } from './db/connection.js';
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

  // Async only for call-site compatibility — the engine opens synchronously.
  await initDbAsync();

  // Checked here, before any schema work, for two reasons.
  //
  // A read-only server with an empty database answers every question with
  // silence, which for a detection tool is the worst available failure mode: it
  // reads as "no coverage" rather than "misconfigured".
  //
  // And several schema initializers seed reference data rather than only
  // declaring tables — initCoverageEngineSchema() calls seedTelemetryMappings()
  // — which read-only refuses. On a populated database that seeding is skipped
  // and never arises; on an empty one it would crash with EREADONLY and bury
  // the actual problem in a stack trace.
  if (isReadOnly()) {
    let indexed = 0;
    try {
      const rows = runQuery<{ n: number }>('SELECT COUNT(*) AS n FROM detections');
      indexed = rows[0]?.n ?? 0;
    } catch {
      indexed = 0;
    }
    if (indexed === 0) {
      console.error(
        '[harris-hawkeye-mcp] FATAL: read-only mode requested but the database holds no ' +
        'detections. Read-only servers cannot index, so this instance would answer every ' +
        'query with an empty result. Point DETECTIONS_DB_PATH at a populated database, or ' +
        'start once without HAWKEYE_READONLY to build one.'
      );
      process.exit(1);
    }
    console.error(`[harris-hawkeye-mcp] read-only mode — ${indexed} detections available, indexing disabled`);
  }

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

  // Apply the tool profile before the server is built, so the generated server
  // instructions describe the scoped surface rather than the full registry.
  // An unrecognised name is fatal: silently falling back to all 129 tools is
  // the exact outcome profiles exist to prevent.
  const profileName = process.env.HAWKEYE_TOOL_PROFILE;
  try {
    let active = resolveProfile(profileName, toolRegistry.getNames());

    if (active !== null) {
      const missing = unresolvedNames(profileName, toolRegistry.getNames());
      if (missing.length > 0) {
        console.error(
          `[harris-hawkeye-mcp] WARNING: profile "${profileName}" names ${missing.length} ` +
          `tool(s) not in the registry, so the surface is smaller than intended: ${missing.join(', ')}`
        );
      }
      const desc = PROFILES[profileName!.trim()]?.description ?? '';
      console.error(`[harris-hawkeye-mcp] Tool profile "${profileName}" active. ${desc}`);
    }

    // Read-only withholds the write tools regardless of profile. They cannot
    // work, and failing to list them is better than letting the model spend a
    // turn on one: several of them bulk-write and then call saveDb(), which in
    // read-only applies to the in-memory image and silently never persists. A
    // write that reports success and then evaporates is the worst outcome here.
    if (isReadOnly()) {
      const base = active ?? toolRegistry.getNames();
      const denied = new Set<string>(WRITE_TOOLS);
      const kept = base.filter(n => !denied.has(n));
      const withheld = base.length - kept.length;
      active = kept;
      if (withheld > 0) {
        console.error(`[harris-hawkeye-mcp] read-only mode — ${withheld} write tool(s) withheld`);
      }
    }

    toolRegistry.setProfile(active);
    if (active !== null) {
      console.error(
        `[harris-hawkeye-mcp] ${toolRegistry.activeCount()} of ${summary.total} tools exposed`
      );
    }
  } catch (error) {
    console.error(`[harris-hawkeye-mcp] FATAL: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }

  // Create and start server FIRST so MCP handshake completes immediately
  const server = createServer();
  await startServer(server);

  // THEN index detections in the background (after server is connected)
  // This prevents the 60-second MCP handshake timeout
  //
  // Skipped entirely in read-only mode. These are the larger of the two write
  // paths: autoIndexArt() and autoIndexSublime() git clone from the network and
  // mkdir into data/, and nothing they index could be persisted anyway.
  // HAWKEYE_SKIP_SYNC keeps local indexing but skips the two upstream git
  // syncs. Worth having for two independent reasons.
  //
  // Atomic Red Team is a repository of working attack payloads — encoded
  // PowerShell, credential-dumping scripts, and named offensive tooling. On an
  // endpoint running EDR, pulling it generates alerts, and on an analyst's own
  // machine those alerts land in the SOC queue they are on call for. Anyone
  // running this where sync is not wanted needs a way to say so.
  //
  // It is also the startup latency. Both syncs use execSync, which blocks the
  // event loop despite this section being placed after startServer() to avoid
  // exactly that — so an unreachable remote stalls the MCP handshake for the
  // full git timeout, around a minute per remote, and the client sees a server
  // that accepted the connection and then went silent.
  const skipSync = ['1', 'true', 'yes'].includes(
    (process.env.HAWKEYE_SKIP_SYNC ?? '').trim().toLowerCase()
  );

  if (isReadOnly()) {
    console.error('[harris-hawkeye-mcp] read-only mode — skipping indexing and upstream sync');
  } else {
    autoIndex();
    await autoIndexMitre();
    if (skipSync) {
      console.error('[harris-hawkeye-mcp] HAWKEYE_SKIP_SYNC set — skipping Atomic Red Team and Sublime git sync');
    } else {
      await autoIndexArt();
      await autoIndexSublime();
    }
    console.error('[harris-hawkeye-mcp] Indexing complete — fully ready');
  }
}

main().catch((error) => {
  console.error('[harris-hawkeye-mcp] Fatal error:', error);
  process.exit(1);
});
