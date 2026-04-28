// Detection Indexer - Parses and indexes detection rules from various sources
import fs from 'fs';
import path from 'path';
import { parse as parseYaml } from 'yaml';
import * as TOML from '@iarna/toml';
import { getDb, runQuery, runBulkStatement, saveDb } from './db/connection.js';

export interface IndexResult {
  total: number;
  sigma_indexed: number;
  splunk_indexed: number;
  elastic_indexed: number;
  kql_indexed: number;
  stories_indexed: number;
  errors: string[];
}

export function needsIndexing(): boolean {
  const result = runQuery<{ count: number }>('SELECT COUNT(*) as count FROM detections');
  return result[0]?.count === 0;
}

// Check which sources need (re-)indexing — detects both missing AND partial indexing
export function getMissingSources(
  expectedCounts?: { sigma?: number; splunk?: number; elastic?: number; kql?: number }
): { sigma: boolean; splunk: boolean; elastic: boolean; kql: boolean } {
  const counts = runQuery<{ source_type: string; count: number }>(
    'SELECT source_type, COUNT(*) as count FROM detections GROUP BY source_type'
  );
  const countMap = new Map(counts.map(r => [r.source_type, r.count]));

  // Partial-indexing threshold: if indexed count is less than 80% of expected files,
  // consider it a failed partial index that needs re-doing
  const PARTIAL_THRESHOLD = 0.80;

  const sigmaCount = countMap.get('sigma') || 0;
  const splunkCount = countMap.get('splunk_escu') || 0;
  const elasticCount = countMap.get('elastic') || 0;
  const kqlCount = countMap.get('kql') || 0;

  const sigmaExpected = expectedCounts?.sigma ?? 0;
  const splunkExpected = expectedCounts?.splunk ?? 0;
  const elasticExpected = expectedCounts?.elastic ?? 0;
  const kqlExpected = expectedCounts?.kql ?? 0;

  const sigmaMissing = sigmaCount === 0 || (sigmaExpected > 0 && sigmaCount < sigmaExpected * PARTIAL_THRESHOLD);
  const splunkMissing = splunkCount === 0 || (splunkExpected > 0 && splunkCount < splunkExpected * PARTIAL_THRESHOLD);
  const elasticMissing = elasticCount === 0 || (elasticExpected > 0 && elasticCount < elasticExpected * PARTIAL_THRESHOLD);
  const kqlMissing = kqlCount === 0 || (kqlExpected > 0 && kqlCount < kqlExpected * PARTIAL_THRESHOLD);

  if (sigmaMissing || splunkMissing || elasticMissing || kqlMissing) {
    console.error(`[indexer] Source counts — Sigma: ${sigmaCount}/${sigmaExpected}, Splunk: ${splunkCount}/${splunkExpected}, Elastic: ${elasticCount}/${elasticExpected}, KQL: ${kqlCount}/${kqlExpected}`);
  }

  return { sigma: sigmaMissing, splunk: splunkMissing, elastic: elasticMissing, kql: kqlMissing };
}

// Count expected files per source (fast — no parsing, just file discovery)
export function countExpectedFiles(
  sigmaPaths: string[], splunkPaths: string[], elasticPaths: string[], kqlPaths: string[]
): { sigma: number; splunk: number; elastic: number; kql: number } {
  let sigma = 0, splunk = 0, elastic = 0, kql = 0;
  for (const p of sigmaPaths) sigma += findYamlFiles(p).length;
  for (const p of splunkPaths) splunk += findYamlFiles(p).length;
  for (const p of elasticPaths) {
    elastic += findYamlFiles(p).length;
    elastic += findTomlFiles(p).length;
  }
  for (const p of kqlPaths) kql += findYamlFiles(p).length;
  return { sigma, splunk, elastic, kql };
}

export function indexDetections(
  sigmaPaths: string[],
  splunkPaths: string[],
  storyPaths: string[],
  elasticPaths: string[],
  kqlPaths: string[]
): IndexResult {
  const result: IndexResult = {
    total: 0,
    sigma_indexed: 0,
    splunk_indexed: 0,
    elastic_indexed: 0,
    kql_indexed: 0,
    stories_indexed: 0,
    errors: [],
  };

  // Index Sigma rules
  for (const sigmaPath of sigmaPaths) {
    try {
      const count = indexSigmaRules(sigmaPath);
      result.sigma_indexed += count;
      result.total += count;
    } catch (error) {
      result.errors.push(`Sigma indexing error: ${error}`);
    }
  }

  // Index Splunk ESCU rules
  for (const splunkPath of splunkPaths) {
    try {
      const count = indexSplunkRules(splunkPath);
      result.splunk_indexed += count;
      result.total += count;
    } catch (error) {
      result.errors.push(`Splunk indexing error: ${error}`);
    }
  }

  // Index Elastic rules
  for (const elasticPath of elasticPaths) {
    try {
      const count = indexElasticRules(elasticPath);
      result.elastic_indexed += count;
      result.total += count;
    } catch (error) {
      result.errors.push(`Elastic indexing error: ${error}`);
    }
  }

  // Index KQL rules
  for (const kqlPath of kqlPaths) {
    try {
      const count = indexKqlRules(kqlPath);
      result.kql_indexed += count;
      result.total += count;
    } catch (error) {
      result.errors.push(`KQL indexing error: ${error}`);
    }
  }

  // Index stories
  for (const storyPath of storyPaths) {
    try {
      const count = indexStories(storyPath);
      result.stories_indexed += count;
    } catch (error) {
      result.errors.push(`Story indexing error: ${error}`);
    }
  }

  return result;
}

function findYamlFiles(dir: string): string[] {
  const files: string[] = [];
  
  if (!fs.existsSync(dir)) {
    return files;
  }
  
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...findYamlFiles(fullPath));
    } else if (entry.isFile() && (entry.name.endsWith('.yml') || entry.name.endsWith('.yaml'))) {
      files.push(fullPath);
    }
  }
  
  return files;
}

function findTomlFiles(dir: string): string[] {
  const files: string[] = [];
  
  if (!fs.existsSync(dir)) {
    return files;
  }
  
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...findTomlFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.toml')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

function indexSigmaRules(basePath: string): number {
  const files = findYamlFiles(basePath);
  let indexed = 0;
  let skipped = 0;

  const database = getDb();
  database.run('BEGIN TRANSACTION');

  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content);

      if (!rule || !rule.title) continue;

      const id = rule.id || `sigma_${path.basename(filePath, path.extname(filePath))}`;
      const techniques = extractMitreTechniques(rule);
      const tactics = extractMitreTactics(rule);

      // Enrichment — fault-tolerant: if any extraction throws, fall back to nulls
      let logsource = { category: null as string | null, product: null as string | null, service: null as string | null };
      let cves: string[] = [];
      let processNames: string[] = [];
      let filePaths: string[] = [];
      let regPaths: string[] = [];
      let dataSources: string[] = [];
      let detectionType = 'TTP';
      let platforms: string[] = [];
      try {
        logsource = extractLogsource(rule);
        cves = extractCves((rule.tags as string[]) || []);
        processNames = extractProcessNames(rule.detection);
        filePaths = extractFilePaths(rule.detection);
        regPaths = extractRegistryPaths(rule.detection);
        dataSources = extractDataSourcesFromLogsource(logsource);
        detectionType = determineDetectionType(rule);
        platforms = logsource.product ? [logsource.product] : [];
      } catch { /* enrichment failed — index with basic fields */ }

      runBulkStatement(
        `INSERT OR REPLACE INTO detections
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text,
          logsource_category, logsource_product, logsource_service, cves, data_sources, detection_type,
          process_names, file_paths_found, registry_paths, platforms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          rule.title,
          rule.description || null,
          'sigma',
          rule.level || 'medium',
          rule.status || 'experimental',
          rule.author || null,
          rule.date || null,
          rule.modified || null,
          rule.detection ? JSON.stringify(rule.detection) : null,
          content,
          filePath,
          JSON.stringify(tactics),
          JSON.stringify(techniques),
          rule.tags ? JSON.stringify(rule.tags) : null,
          rule.references ? JSON.stringify(rule.references) : null,
          rule.falsepositives ? JSON.stringify(rule.falsepositives) : null,
          `${rule.title} ${rule.description || ''} ${(rule.tags || []).join(' ')}`.toLowerCase(),
          logsource.category,
          logsource.product,
          logsource.service,
          cves.length ? JSON.stringify(cves) : null,
          dataSources.length ? JSON.stringify(dataSources) : null,
          detectionType,
          processNames.length ? JSON.stringify(processNames) : null,
          filePaths.length ? JSON.stringify(filePaths) : null,
          regPaths.length ? JSON.stringify(regPaths) : null,
          platforms.length ? JSON.stringify(platforms) : null,
        ]
      );
      indexed++;
    } catch (error) {
      skipped++;
      if (skipped <= 5) console.error(`[indexer] Sigma skip: ${path.basename(filePath)}: ${error instanceof Error ? error.message.slice(0, 120) : error}`);
    }
  }

  database.run('COMMIT');
  saveDb();
  if (skipped > 0) console.error(`[indexer] Sigma: skipped ${skipped} of ${files.length} files (parse errors)`);
  return indexed;
}

function indexSplunkRules(basePath: string): number {
  const files = findYamlFiles(basePath);
  let indexed = 0;
  let skipped = 0;

  const database = getDb();
  database.run('BEGIN TRANSACTION');

  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content);

      const ruleName = rule?.title || rule?.name;
      if (!rule || !ruleName) continue;

      const id = rule.id || `splunk_${path.basename(filePath, path.extname(filePath))}`;

      const tagsObj = rule.tags || {};
      const mitreTags = tagsObj.mitre_attack_id || [];
      const techniques = Array.isArray(mitreTags) ? mitreTags.filter((t: string) => t.startsWith('T')) : [];
      const analyticStory: string[] = tagsObj.analytic_story || [];

      // Enrichment — fault-tolerant
      let cves: string[] = [];
      let dataSources: string[] = [];
      let detectionType: string | null = null;
      let assetType: string | null = null;
      let securityDomain: string | null = null;
      try {
        cves = tagsObj.cve ? (Array.isArray(tagsObj.cve) ? tagsObj.cve : [tagsObj.cve]) : [];
        dataSources = rule.data_source ? (Array.isArray(rule.data_source) ? rule.data_source : [rule.data_source]) : [];
        detectionType = rule.type || null;
        assetType = tagsObj.asset_type || null;
        securityDomain = tagsObj.security_domain || null;
      } catch { /* enrichment failed — index with basic fields */ }

      runBulkStatement(
        `INSERT OR REPLACE INTO detections
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text,
          analytic_stories, cves, data_sources, detection_type, asset_type, security_domain)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          ruleName,
          rule.description || null,
          'splunk_escu',
          tagsObj.risk_severity || 'medium',
          rule.status || 'production',
          rule.author || null,
          rule.date || null,
          null,
          rule.search || null,
          content,
          filePath,
          JSON.stringify(extractTacticsFromTechniqueIds(techniques)),
          JSON.stringify(techniques),
          JSON.stringify(analyticStory),
          rule.references ? JSON.stringify(rule.references) : null,
          rule.known_false_positives ? JSON.stringify([rule.known_false_positives]) : null,
          `${ruleName} ${rule.description || ''} ${analyticStory.join(' ')}`.toLowerCase(),
          analyticStory.length ? JSON.stringify(analyticStory) : null,
          cves.length ? JSON.stringify(cves) : null,
          dataSources.length ? JSON.stringify(dataSources) : null,
          detectionType,
          assetType,
          securityDomain,
        ]
      );
      indexed++;
    } catch (error) {
      skipped++;
      if (skipped <= 5) console.error(`[indexer] Splunk skip: ${path.basename(filePath)}: ${error instanceof Error ? error.message.slice(0, 120) : error}`);
    }
  }

  database.run('COMMIT');
  saveDb();
  if (skipped > 0) console.error(`[indexer] Splunk: skipped ${skipped} of ${files.length} files (parse errors)`);
  return indexed;
}

function indexElasticRules(basePath: string): number {
  // Handle both YAML and TOML files (Elastic uses TOML)
  const yamlFiles = findYamlFiles(basePath);
  const tomlFiles = findTomlFiles(basePath);
  let indexed = 0;
  let skipped = 0;

  const database = getDb();
  database.run('BEGIN TRANSACTION');

  // Index YAML files
  for (const filePath of yamlFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content);

      if (!rule || !rule.name) continue;

      const id = rule.id || rule.rule_id || `elastic_${path.basename(filePath, path.extname(filePath))}`;
      const techniques = rule.threat?.flatMap((t: { technique?: Array<{ id: string }> }) =>
        t.technique?.map((tech: { id: string }) => tech.id) || []
      ) || [];
      const tactics = rule.threat?.map((t: { tactic?: { name: string } }) => t.tactic?.name).filter(Boolean) || [];
      const platforms: string[] = rule.language ? [rule.language as string] : [];
      const detectionType: string = (rule.type as string) || 'TTP';

      // Enrichment from index patterns and query content
      let elasticDs = { dataSources: [] as string[], logsourceProduct: null as string | null, logsourceCategory: null as string | null };
      let processNames: string[] = [];
      let filePaths: string[] = [];
      let regPaths: string[] = [];
      try {
        elasticDs = extractElasticDataSources(rule.index);
        processNames = extractProcessNames(rule.query as string || '');
        filePaths = extractFilePaths(rule.query as string || '');
        regPaths = extractRegistryPaths(rule.query as string || '');
      } catch { /* enrichment failed */ }

      runBulkStatement(
        `INSERT OR REPLACE INTO detections
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text,
          platforms, detection_type, data_sources, logsource_product, logsource_category, process_names, file_paths_found, registry_paths)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          rule.name,
          rule.description || null,
          'elastic',
          rule.severity || 'medium',
          'production',
          rule.author ? JSON.stringify(rule.author) : null,
          null,
          null,
          rule.query || null,
          content,
          filePath,
          JSON.stringify(tactics),
          JSON.stringify(techniques),
          rule.tags ? JSON.stringify(rule.tags) : null,
          rule.references ? JSON.stringify(rule.references) : null,
          rule.false_positives ? JSON.stringify(rule.false_positives) : null,
          `${rule.name} ${rule.description || ''} ${(rule.tags || []).join(' ')}`.toLowerCase(),
          platforms.length ? JSON.stringify(platforms) : null,
          detectionType,
          elasticDs.dataSources.length ? JSON.stringify(elasticDs.dataSources) : null,
          elasticDs.logsourceProduct,
          elasticDs.logsourceCategory,
          processNames.length ? JSON.stringify(processNames) : null,
          filePaths.length ? JSON.stringify(filePaths) : null,
          regPaths.length ? JSON.stringify(regPaths) : null,
        ]
      );
      indexed++;
    } catch (error) {
      skipped++;
      if (skipped <= 5) console.error(`[indexer] Elastic YAML skip: ${path.basename(filePath)}: ${error instanceof Error ? error.message.slice(0, 120) : error}`);
    }
  }

  // Index TOML files (Elastic detection rules format)
  for (const filePath of tomlFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = TOML.parse(content) as Record<string, unknown>;
      const rule = parsed.rule as Record<string, unknown> | undefined;
      const metadata = parsed.metadata as Record<string, unknown> | undefined;

      if (!rule || !rule.name) continue;

      const id = (rule.rule_id as string) || `elastic_${path.basename(filePath, '.toml')}`;

      const threat = rule.threat as Array<{ tactic?: { name: string; id: string }; technique?: Array<{ id: string; name: string }> }> | undefined;
      const techniques = threat?.flatMap(t => t.technique?.map(tech => tech.id) || []) || [];
      const tactics = threat?.map(t => t.tactic?.name).filter(Boolean) || [];
      const platforms: string[] = rule.language ? [rule.language as string] : [];
      const detectionType: string = (rule.type as string) || 'TTP';

      // Enrichment from index patterns and query content
      let elasticDs = { dataSources: [] as string[], logsourceProduct: null as string | null, logsourceCategory: null as string | null };
      let processNames: string[] = [];
      let filePaths: string[] = [];
      let regPaths: string[] = [];
      try {
        elasticDs = extractElasticDataSources(rule.index);
        processNames = extractProcessNames(rule.query as string || '');
        filePaths = extractFilePaths(rule.query as string || '');
        regPaths = extractRegistryPaths(rule.query as string || '');
      } catch { /* enrichment failed */ }

      runBulkStatement(
        `INSERT OR REPLACE INTO detections
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text,
          platforms, detection_type, data_sources, logsource_product, logsource_category, process_names, file_paths_found, registry_paths)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          rule.name as string,
          (rule.description as string) || null,
          'elastic',
          (rule.severity as string) || 'medium',
          'production',
          rule.author ? JSON.stringify(rule.author) : null,
          (metadata?.creation_date as string) || null,
          (metadata?.updated_date as string) || null,
          (rule.query as string) || null,
          content,
          filePath,
          JSON.stringify(tactics),
          JSON.stringify(techniques),
          rule.tags ? JSON.stringify(rule.tags) : null,
          rule.references ? JSON.stringify(rule.references) : null,
          rule.false_positives ? JSON.stringify(rule.false_positives) : null,
          `${rule.name} ${rule.description || ''} ${((rule.tags as string[]) || []).join(' ')}`.toLowerCase(),
          platforms.length ? JSON.stringify(platforms) : null,
          detectionType,
          elasticDs.dataSources.length ? JSON.stringify(elasticDs.dataSources) : null,
          elasticDs.logsourceProduct,
          elasticDs.logsourceCategory,
          processNames.length ? JSON.stringify(processNames) : null,
          filePaths.length ? JSON.stringify(filePaths) : null,
          regPaths.length ? JSON.stringify(regPaths) : null,
        ]
      );
      indexed++;
    } catch (error) {
      skipped++;
      if (skipped <= 5) console.error(`[indexer] Elastic TOML skip: ${path.basename(filePath)}: ${error instanceof Error ? error.message.slice(0, 120) : error}`);
    }
  }

  database.run('COMMIT');
  saveDb();
  if (skipped > 0) console.error(`[indexer] Elastic: skipped ${skipped} of ${yamlFiles.length + tomlFiles.length} files (parse errors)`);
  return indexed;
}

function indexKqlRules(basePath: string): number {
  const files = findYamlFiles(basePath);
  let indexed = 0;
  let skipped = 0;

  const database = getDb();
  database.run('BEGIN TRANSACTION');

  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content);

      if (!rule || !rule.name) continue;

      const id = rule.id || `kql_${path.basename(filePath, path.extname(filePath))}`;
      const queryText: string = rule.query || rule.huntingquery || '';

      // Enrichment — fault-tolerant
      let kqlCategory = 'Uncategorized';
      let kqlTags: string[] = [];
      let kqlKeywords: string[] = [];
      let dataSources: string[] = [];
      let platforms: string[] = [];
      try {
        kqlCategory = extractKqlCategory(filePath, basePath);
        kqlTags = extractKqlTags(content, kqlCategory);
        kqlKeywords = extractKqlKeywords(content, queryText);
        dataSources = extractKqlDataSources(queryText);
        platforms = extractKqlPlatforms(dataSources);
      } catch { /* enrichment failed — index with basic fields */ }

      runBulkStatement(
        `INSERT OR REPLACE INTO detections
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text,
          kql_category, kql_tags, kql_keywords, data_sources, platforms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          rule.name,
          rule.description || null,
          'kql',
          rule.severity || 'medium',
          'production',
          rule.author || null,
          null,
          null,
          queryText || null,
          content,
          filePath,
          JSON.stringify(rule.tactics || []),
          JSON.stringify(rule.relevantTechniques || []),
          rule.tags ? JSON.stringify(rule.tags) : null,
          rule.references ? JSON.stringify(rule.references) : null,
          null,
          `${rule.name} ${rule.description || ''} ${(rule.tags || []).join(' ')}`.toLowerCase(),
          kqlCategory,
          kqlTags.length ? JSON.stringify(kqlTags) : null,
          kqlKeywords.length ? JSON.stringify(kqlKeywords) : null,
          dataSources.length ? JSON.stringify(dataSources) : null,
          platforms.length ? JSON.stringify(platforms) : null,
        ]
      );
      indexed++;
    } catch (error) {
      skipped++;
      if (skipped <= 5) console.error(`[indexer] KQL skip: ${path.basename(filePath)}: ${error instanceof Error ? error.message.slice(0, 120) : error}`);
    }
  }

  database.run('COMMIT');
  saveDb();
  if (skipped > 0) console.error(`[indexer] KQL: skipped ${skipped} of ${files.length} files (parse errors)`);
  return indexed;
}

function indexStories(basePath: string): number {
  const files = findYamlFiles(basePath);
  let indexed = 0;

  const database = getDb();
  database.run('BEGIN TRANSACTION');

  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const story = parseYaml(content);
      
      if (!story || !story.name) continue;
      
      const id = story.id || `story_${path.basename(filePath, path.extname(filePath))}`;
      
      runBulkStatement(
        `INSERT OR REPLACE INTO stories 
         (id, name, description, narrative, source_type, detection_ids, mitre_tactics, mitre_techniques, tags, references, file_path)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          story.name,
          story.description || null,
          story.narrative || null,
          'splunk_escu',
          story.detections ? JSON.stringify(story.detections) : null,
          null,
          null,
          story.tags ? JSON.stringify(story.tags) : null,
          story.references ? JSON.stringify(story.references) : null,
          filePath,
        ]
      );
      indexed++;
    } catch (error) {
      // Skip invalid files
    }
  }

  database.run('COMMIT');
  saveDb();
  return indexed;
}

// ─── Extraction helpers ───────────────────────────────────────────────────────

function extractLogsource(rule: Record<string, unknown>): { category: string | null; product: string | null; service: string | null } {
  const ls = (rule.logsource as Record<string, string | undefined>) || {};
  return {
    category: ls.category || null,
    product: ls.product || null,
    service: ls.service || null,
  };
}

function extractCves(tags: string[]): string[] {
  return tags
    .filter(t => /^cve\.\d{4}-\d+$/i.test(t))
    .map(t => t.replace(/^cve\./i, 'CVE-').toUpperCase());
}

function determineDetectionType(rule: Record<string, unknown>): string {
  const status = (rule.status as string || '').toLowerCase();
  const tags = (rule.tags as string[] || []).map(t => t.toLowerCase());
  if (status === 'test' || status === 'experimental' || tags.includes('hunting')) return 'Hunting';
  return 'TTP';
}

function extractDataSourcesFromLogsource(logsource: { category: string | null; product: string | null; service: string | null }): string[] {
  const sources: string[] = [];
  const { category, product, service } = logsource;
  if (product === 'windows') {
    if (category === 'process_creation') sources.push('Process Creation Events');
    else if (category === 'network_connection') sources.push('Network Connection Events');
    else if (category === 'registry_event' || category === 'registry_set' || category === 'registry_add') sources.push('Windows Registry Events');
    else if (category === 'file_event' || category === 'file_creation') sources.push('File System Events');
    else if (category === 'image_load' || category === 'driver_load') sources.push('Module Load Events');
    else if (category === 'dns_query') sources.push('DNS Query Events');
    else if (service === 'security') sources.push('Windows Security Events');
    else if (service === 'system') sources.push('Windows System Events');
    else if (service === 'sysmon') sources.push('Sysmon Events');
    else if (service === 'powershell' || service === 'powershell-classic') sources.push('PowerShell Events');
    else if (service === 'windefend') sources.push('Windows Defender Events');
    else if (category) sources.push(`Windows ${category} Events`);
  } else if (product === 'linux') {
    sources.push(service ? `Linux ${service} Events` : 'Linux Audit Events');
  } else if (product === 'aws') {
    sources.push('AWS CloudTrail');
  } else if (product === 'azure') {
    sources.push(service || 'Azure Activity Logs');
  } else if (product === 'gcp') {
    sources.push('GCP Audit Logs');
  } else if (category) {
    sources.push(category);
  }
  return sources;
}

// Recursively collect all string values from an object
function collectStrings(obj: unknown, depth = 0): string[] {
  if (depth > 6) return [];
  if (typeof obj === 'string') return [obj];
  if (Array.isArray(obj)) return obj.flatMap(v => collectStrings(v, depth + 1));
  if (obj && typeof obj === 'object') {
    return Object.values(obj as Record<string, unknown>).flatMap(v => collectStrings(v, depth + 1));
  }
  return [];
}

function extractProcessNames(detection: unknown): string[] {
  if (!detection) return [];
  const strings = collectStrings(detection);
  const seen = new Set<string>();
  for (const s of strings) {
    const matches = s.match(/\\([a-zA-Z0-9_\-]+\.exe)/gi);
    if (matches) {
      for (const m of matches) {
        const name = m.replace(/\\/g, '').toLowerCase();
        if (!name.includes('*') && name.length > 4) seen.add(name);
      }
    }
    // Also catch bare exe names like "powershell.exe"
    if (/^[a-zA-Z0-9_\-]+\.exe$/i.test(s.trim()) && !s.includes('*')) {
      seen.add(s.trim().toLowerCase());
    }
  }
  return [...seen];
}

function extractFilePaths(detection: unknown): string[] {
  if (!detection) return [];
  const strings = collectStrings(detection);
  const interestingPaths = [
    /c:\\windows\\temp/i, /\\appdata\\local\\temp/i, /\\appdata\\roaming/i,
    /c:\\programdata/i, /c:\\users\\public/i, /c:\\windows\\system32/i,
    /c:\\windows\\syswow64/i, /\\downloads\\/i, /\\desktop\\/i,
  ];
  const seen = new Set<string>();
  for (const s of strings) {
    if (interestingPaths.some(p => p.test(s))) seen.add(s);
  }
  return [...seen];
}

function extractRegistryPaths(detection: unknown): string[] {
  if (!detection) return [];
  const strings = collectStrings(detection);
  const regPatterns = [
    /hklm\\software\\microsoft\\windows\\currentversion\\run/i,
    /hkcu\\software\\microsoft\\windows\\currentversion\\run/i,
    /hklm\\system\\currentcontrolset\\services/i,
    /software\\microsoft\\windows nt\\currentversion\\image file execution options/i,
    /software\\microsoft\\windows nt\\currentversion\\windows.*appinit/i,
    /hklm\\software\\microsoft\\windows nt\\currentversion\\winlogon/i,
    /hkcu.*\\environment/i,
    /hklm\\system\\currentcontrolset\\control\\lsa/i,
  ];
  const seen = new Set<string>();
  for (const s of strings) {
    if (regPatterns.some(p => p.test(s))) seen.add(s);
  }
  return [...seen];
}

// Elastic-specific: derive logsource + data sources from index patterns
function extractElasticDataSources(indices: unknown): { dataSources: string[]; logsourceProduct: string | null; logsourceCategory: string | null } {
  const idxList: string[] = Array.isArray(indices) ? indices as string[] : (typeof indices === 'string' ? [indices] : []);
  const dataSources = new Set<string>();
  let product: string | null = null;
  let category: string | null = null;

  for (const idx of idxList) {
    if (idx.includes('winlogbeat') || idx.includes('logs-endpoint.events') || idx.includes('logs-windows')) {
      product = product || 'windows';
    }
    if (idx.includes('logs-endpoint.events.process')) {
      category = category || 'process_creation';
      dataSources.add('Process Creation Events');
    } else if (idx.includes('logs-endpoint.events.network')) {
      category = category || 'network_connection';
      dataSources.add('Network Connection Events');
    } else if (idx.includes('logs-endpoint.events.registry')) {
      category = category || 'registry_event';
      dataSources.add('Windows Registry Events');
    } else if (idx.includes('logs-endpoint.events.file')) {
      category = category || 'file_event';
      dataSources.add('File System Events');
    } else if (idx.includes('logs-endpoint.events.library')) {
      dataSources.add('Module Load Events');
    } else if (idx.includes('winlogbeat')) {
      dataSources.add('Windows Security Events');
    } else if (idx.includes('filebeat') || idx.includes('auditbeat') || idx.includes('logs-system')) {
      product = product || 'linux';
      dataSources.add('Linux Audit Events');
    } else if (idx.includes('packetbeat')) {
      dataSources.add('Network Packet Events');
    } else if (idx.includes('apm-')) {
      dataSources.add('APM Events');
    }
  }

  return { dataSources: [...dataSources], logsourceProduct: product, logsourceCategory: category };
}

// KQL-specific helpers
function extractKqlCategory(filePath: string, basePath: string): string {
  const rel = path.relative(basePath, filePath);
  const parts = rel.split(/[\\/]/);
  return parts.length > 1 ? parts[0] : 'Uncategorized';
}

function extractKqlTags(content: string, category: string): string[] {
  const tags = new Set<string>();
  tags.add(category.toLowerCase().replace(/\s+/g, '-'));
  const actorPatterns = ['APT', 'STORM-', 'FIN', 'UNC', 'DEV-'];
  for (const pattern of actorPatterns) {
    const matches = content.match(new RegExp(`${pattern}[\\d]+`, 'gi'));
    if (matches) matches.forEach(m => tags.add(m.toUpperCase()));
  }
  const topics = ['ransomware', 'hunting', 'detection', 'dfir', 'threat-intelligence', 'ti-feed', 'ioc', 'behavior', 'anomaly'];
  const lower = content.toLowerCase();
  for (const topic of topics) {
    if (lower.includes(topic.replace('-', ' ')) || lower.includes(topic)) tags.add(topic);
  }
  return [...tags];
}

function extractKqlKeywords(content: string, query: string): string[] {
  const secTerms = [
    'ransomware', 'malware', 'phishing', 'credential', 'lateral movement',
    'persistence', 'privilege escalation', 'exfiltration', 'command and control',
    'c2', 'backdoor', 'rootkit', 'exploit', 'vulnerability', 'brute force',
    'injection', 'mimikatz', 'bloodhound', 'cobalt strike', 'empire',
    'powershell', 'wmi', 'psexec', 'scheduled task', 'service', 'registry',
    'amsi', 'defender', 'bypass', 'evasion', 'lolbas',
  ];
  const combined = (content + ' ' + query).toLowerCase();
  return secTerms.filter(t => combined.includes(t));
}

function extractKqlDataSources(query: string): string[] {
  const knownTables = [
    // MDE (Microsoft Defender for Endpoint)
    'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents',
    'DeviceRegistryEvents', 'DeviceLogonEvents', 'DeviceEvents',
    'DeviceImageLoadEvents', 'DeviceInfo', 'DeviceNetworkInfo',
    'DeviceAlertEvents', 'DeviceTvmSoftwareVulnerabilities',
    // Sentinel alerts & incidents
    'AlertInfo', 'AlertEvidence', 'SecurityAlert', 'SecurityIncident',
    // Identity
    'IdentityInfo', 'IdentityLogonEvents', 'IdentityQueryEvents', 'IdentityDirectoryEvents',
    // Cloud Apps / CASB
    'CloudAppEvents',
    // Email / O365
    'EmailEvents', 'EmailAttachmentInfo', 'EmailUrlInfo', 'UrlClickEvents', 'OfficeActivity',
    // Azure AD / Entra ID
    'AADSignInEventsBeta', 'AADSpnSignInEventsBeta', 'SigninLogs', 'AADNonInteractiveUserSignInLogs',
    'AADServicePrincipalSignInLogs', 'AADManagedIdentitySignInLogs',
    'AuditLogs', 'AADProvisioningLogs', 'AADRiskyUsers', 'AADUserRiskEvents',
    // Azure platform
    'AzureActivity', 'AzureDiagnostics', 'AzureMetrics',
    'StorageFileLogs', 'StorageBlobLogs', 'StorageTableLogs', 'StorageQueueLogs',
    'AppServiceHTTPLogs', 'FunctionAppLogs', 'AppServiceConsoleLogs',
    'AKSAudit', 'ContainerLog', 'ContainerImageInventory', 'KubeNodeInventory',
    'MicrosoftGraphActivityLogs', 'NetworkAccessTrafficLogs',
    // Windows / on-prem
    'SecurityEvent', 'WindowsEvent', 'W3CIISLog', 'DnsEvents',
    'Syslog', 'CommonSecurityLog',
    // Behavior analytics
    'BehaviorAnalytics',
    // Threat intelligence
    'ThreatIntelligenceIndicator',
    // AWS / GCP
    'AWSCloudTrail', 'AWSVPCFlow', 'GCPAuditLogs',
    // AI / Copilot
    'AIAgentsInfo', 'CopilotEvents',
  ];
  return knownTables.filter(t => new RegExp(`\\b${t}\\b`, 'i').test(query));
}

function extractKqlPlatforms(dataSources: string[]): string[] {
  const platforms = new Set<string>();
  // Windows endpoint (MDE)
  if (dataSources.some(d => d.startsWith('Device'))) platforms.add('windows');
  // Windows on-prem (Security Events, IIS, DNS)
  if (dataSources.some(d => ['SecurityEvent', 'WindowsEvent', 'W3CIISLog', 'DnsEvents'].includes(d))) platforms.add('windows');
  // Azure AD / Entra ID
  if (dataSources.some(d => d.includes('AAD') || d.includes('Signin') || d.includes('AuditLogs') ||
      d.includes('AADRisky') || d.includes('AADUser') || d.includes('Provisioning'))) platforms.add('azure-ad');
  // Azure platform (non-identity)
  if (dataSources.some(d => d.includes('Azure') || d.includes('Storage') || d.includes('AppService') ||
      d.includes('Function') || d.includes('AKS') || d.includes('Container') || d.includes('Kube') ||
      d.includes('MicrosoftGraph') || d.includes('NetworkAccess'))) platforms.add('azure');
  // Office 365 / M365
  if (dataSources.some(d => d.includes('Email') || d.includes('Office') || d.includes('Url'))) platforms.add('office-365');
  // Copilot / AI
  if (dataSources.some(d => d.includes('AI') || d.includes('Copilot'))) platforms.add('azure');
  // Linux
  if (dataSources.some(d => d === 'Syslog' || d === 'CommonSecurityLog')) platforms.add('linux');
  // Cloud Apps / CASB
  if (dataSources.some(d => d.includes('CloudApp') || d.includes('Behavior'))) platforms.add('azure');
  // Sentinel alerts/incidents (platform-agnostic sentinel data)
  if (dataSources.some(d => ['SecurityAlert', 'SecurityIncident', 'AlertInfo', 'AlertEvidence',
      'ThreatIntelligenceIndicator', 'BehaviorAnalytics'].includes(d))) platforms.add('azure-sentinel');
  // Identity (cross-platform)
  if (dataSources.some(d => d.startsWith('Identity'))) platforms.add('azure-ad');
  // AWS / GCP
  if (dataSources.some(d => d.includes('AWS'))) platforms.add('aws');
  if (dataSources.some(d => d.includes('GCP'))) platforms.add('gcp');
  return [...platforms];
}

// ─── MITRE helpers ────────────────────────────────────────────────────────────

// Resolve tactics from T-IDs by querying the local MITRE ATT&CK table
function extractTacticsFromTechniqueIds(techniqueIds: string[]): string[] {
  if (!techniqueIds.length) return [];
  const tactics = new Set<string>();
  for (const tid of techniqueIds) {
    try {
      // Try the exact T-ID first, then the parent technique (strip sub-technique suffix)
      const rows = runQuery<{ tactics: string }>(
        'SELECT tactics FROM mitre_techniques_full WHERE id = ? OR id = ? LIMIT 1',
        [tid, tid.includes('.') ? tid.split('.')[0] : tid]
      );
      if (rows[0]?.tactics) {
        const parsed: string[] = JSON.parse(rows[0].tactics);
        parsed.forEach(t => tactics.add(t));
      }
    } catch { /* mitre table not yet populated — skip */ }
  }
  return [...tactics];
}

function extractMitreTechniques(rule: Record<string, unknown>): string[] {
  const tags = rule.tags as string[] | undefined;
  if (!tags) return [];
  
  return tags
    .filter(tag => tag.startsWith('attack.t') || tag.startsWith('attack.T'))
    .map(tag => tag.replace('attack.', '').toUpperCase());
}

function extractMitreTactics(rule: Record<string, unknown>): string[] {
  const tags = rule.tags as string[] | undefined;
  if (!tags) return [];
  
  const tacticNames = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact'
  ];
  
  return tags
    .filter(tag => tag.startsWith('attack.') && tacticNames.includes(tag.replace('attack.', '')))
    .map(tag => tag.replace('attack.', ''));
}

function extractMitreTechniquesFromTags(tags: string[]): string[] {
  return tags
    .filter(tag => /^T\d{4}(\.\d{3})?$/i.test(tag))
    .map(tag => tag.toUpperCase());
}

function extractMitreTacticsFromTags(tags: string[]): string[] {
  const tacticTags = tags.filter(tag => 
    ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 
     'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
     'Collection', 'Command And Control', 'Exfiltration', 'Impact'].includes(tag)
  );
  return tacticTags;
}

function mapSplunkSeverity(tags: string[] | undefined): string {
  if (!tags) return 'medium';
  if (tags.includes('risk_severity_critical')) return 'critical';
  if (tags.includes('risk_severity_high')) return 'high';
  if (tags.includes('risk_severity_medium')) return 'medium';
  if (tags.includes('risk_severity_low')) return 'low';
  return 'medium';
}
