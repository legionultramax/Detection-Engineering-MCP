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
import { indexDetections, needsIndexing, getMissingSources } from './indexer.js';
import { initKnowledgeSchema } from './db/knowledge.js';
import { initThreatIntelSchema } from './db/threat-intel.js';
import { initMitreAttackTables, indexMitreAttack, needsMitreIndexing, getMitreStats } from './db/mitre-attack.js';
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
const KQL_PATHS = parsePaths(process.env.KQL_PATHS);

// Auto-index on startup if paths are configured and DB is empty or missing sources
function autoIndex(): void {
  if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0 && ELASTIC_PATHS.length === 0 && KQL_PATHS.length === 0) {
    return;
  }

  if (needsIndexing()) {
    // DB is empty — full index
    console.error('[security-detections-mcp] Auto-indexing detections...');
    const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);
    let msg = `[security-detections-mcp] Indexed ${result.total} detections`;
    msg += ` (${result.sigma_indexed} Sigma, ${result.splunk_indexed} Splunk, ${result.elastic_indexed} Elastic, ${result.kql_indexed} KQL)`;
    if (result.stories_indexed > 0) {
      msg += `, ${result.stories_indexed} stories`;
    }
    console.error(msg);
    return;
  }

  // DB has data — check for missing sources and index only those
  const missing = getMissingSources();
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
  console.error(`[security-detections-mcp] Indexing missing sources: ${sources.join(', ')}...`);

  const result = indexDetections(
    sigmaMissing ? SIGMA_PATHS : [],
    splunkMissing ? SPLUNK_PATHS : [],
    splunkMissing ? STORY_PATHS : [],
    elasticMissing ? ELASTIC_PATHS : [],
    kqlMissing ? KQL_PATHS : [],
  );

  let msg = `[security-detections-mcp] Indexed ${result.total} new detections`;
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
    console.error('[security-detections-mcp] MITRE ATT&CK STIX bundle not found, skipping MITRE indexing');
    return;
  }

  if (!needsMitreIndexing()) {
    const stats = getMitreStats();
    console.error(`[security-detections-mcp] MITRE ATT&CK already indexed: ${stats.groups} groups, ${stats.malware + stats.tools} software, ${stats.techniques} techniques`);
    return;
  }

  console.error(`[security-detections-mcp] Indexing MITRE ATT&CK from ${stixPath}...`);
  const result = await indexMitreAttack(stixPath);
  console.error(`[security-detections-mcp] MITRE ATT&CK indexed: ${result.groups} groups, ${result.malware + result.tools} software, ${result.techniques} techniques, ${result.relationships} relationships`);
}

async function main() {
  console.error('[security-detections-mcp] Starting Enhanced Security Detections MCP...');
  
  // Initialize database (async for sql.js)
  await initDbAsync();
  
  // Initialize schemas for enhanced features
  initKnowledgeSchema();
  initThreatIntelSchema();
  initMitreAttackTables();
  
  // Auto-index if configured
  autoIndex();
  
  // Index MITRE ATT&CK data
  await autoIndexMitre();
  
  // Register all tools from modules
  registerAllTools();
  
  // Log tool summary
  const summary = getToolsSummary();
  console.error(`[security-detections-mcp] ${summary.total} tools registered`);
  console.error(`[security-detections-mcp] Modules: ${Object.entries(summary.byModule).map(([k, v]) => `${k}(${v})`).join(', ')}`);
  
  // Create and start server
  const server = createServer();
  await startServer(server);
}

main().catch((error) => {
  console.error('[security-detections-mcp] Fatal error:', error);
  process.exit(1);
});
