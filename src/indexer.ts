// Detection Indexer - Parses and indexes detection rules from various sources
import fs from 'fs';
import path from 'path';
import { parse as parseYaml } from 'yaml';
import * as TOML from '@iarna/toml';
import { getDb, runQuery, runStatement } from './db/connection.js';

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

// Check which sources are missing from the DB so we can index only those
export function getMissingSources(): { sigma: boolean; splunk: boolean; elastic: boolean; kql: boolean } {
  const counts = runQuery<{ source_type: string; count: number }>(
    'SELECT source_type, COUNT(*) as count FROM detections GROUP BY source_type'
  );
  const indexed = new Set(counts.map(r => r.source_type));
  return {
    sigma: !indexed.has('sigma'),
    splunk: !indexed.has('splunk_escu'),
    elastic: !indexed.has('elastic'),
    kql: !indexed.has('kql'),
  };
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
  
  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content);
      
      if (!rule || !rule.title) continue;
      
      const id = rule.id || `sigma_${path.basename(filePath, path.extname(filePath))}`;
      const techniques = extractMitreTechniques(rule);
      const tactics = extractMitreTactics(rule);
      
      runStatement(
        `INSERT OR REPLACE INTO detections 
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        ]
      );
      indexed++;
    } catch (error) {
      // Skip invalid files
    }
  }
  
  return indexed;
}

function indexSplunkRules(basePath: string): number {
  const files = findYamlFiles(basePath);
  let indexed = 0;
  
  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content);
      
      // Splunk ESCU uses 'title' not 'name'
      const ruleName = rule?.title || rule?.name;
      if (!rule || !ruleName) continue;
      
      const id = rule.id || `splunk_${path.basename(filePath, path.extname(filePath))}`;
      
      // Extract MITRE techniques from tags object (Splunk ESCU format)
      const tagsObj = rule.tags || {};
      const mitreTags = tagsObj.mitre_attack_id || [];
      const techniques = Array.isArray(mitreTags) ? mitreTags.filter((t: string) => t.startsWith('T')) : [];
      const analyticStory = tagsObj.analytic_story || [];
      
      runStatement(
        `INSERT OR REPLACE INTO detections 
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
          JSON.stringify([]),
          JSON.stringify(techniques),
          JSON.stringify(analyticStory),
          rule.references ? JSON.stringify(rule.references) : null,
          rule.known_false_positives ? JSON.stringify([rule.known_false_positives]) : null,
          `${ruleName} ${rule.description || ''} ${analyticStory.join(' ')}`.toLowerCase(),
        ]
      );
      indexed++;
    } catch (error) {
      // Skip invalid files
    }
  }
  
  return indexed;
}

function indexElasticRules(basePath: string): number {
  // Handle both YAML and TOML files (Elastic uses TOML)
  const yamlFiles = findYamlFiles(basePath);
  const tomlFiles = findTomlFiles(basePath);
  let indexed = 0;
  
  // Index YAML files
  for (const filePath of yamlFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content);
      
      if (!rule || !rule.name) continue;
      
      const id = rule.id || rule.rule_id || `elastic_${path.basename(filePath, path.extname(filePath))}`;
      const techniques = rule.threat?.flatMap((t: { technique?: Array<{ id: string }> }) => 
        t.technique?.map(tech => tech.id) || []
      ) || [];
      const tactics = rule.threat?.map((t: { tactic?: { name: string } }) => t.tactic?.name).filter(Boolean) || [];
      
      runStatement(
        `INSERT OR REPLACE INTO detections 
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        ]
      );
      indexed++;
    } catch (error) {
      // Skip invalid files
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
      
      // Extract MITRE info from threat array
      const threat = rule.threat as Array<{ tactic?: { name: string; id: string }; technique?: Array<{ id: string; name: string }> }> | undefined;
      const techniques = threat?.flatMap(t => t.technique?.map(tech => tech.id) || []) || [];
      const tactics = threat?.map(t => t.tactic?.name).filter(Boolean) || [];
      
      runStatement(
        `INSERT OR REPLACE INTO detections 
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        ]
      );
      indexed++;
    } catch (error) {
      // Skip invalid TOML files
    }
  }
  
  return indexed;
}

function indexKqlRules(basePath: string): number {
  const files = findYamlFiles(basePath);
  let indexed = 0;
  
  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const rule = parseYaml(content);
      
      if (!rule || !rule.name) continue;
      
      const id = rule.id || `kql_${path.basename(filePath, path.extname(filePath))}`;
      
      runStatement(
        `INSERT OR REPLACE INTO detections 
         (id, name, description, source_type, severity, status, author, date_created, date_modified,
          query, raw_content, file_path, mitre_tactics, mitre_techniques, tags, refs, false_positives, search_text)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
          rule.query || rule.huntingquery || null,
          content,
          filePath,
          JSON.stringify(rule.tactics || []),
          JSON.stringify(rule.relevantTechniques || []),
          rule.tags ? JSON.stringify(rule.tags) : null,
          rule.references ? JSON.stringify(rule.references) : null,
          null,
          `${rule.name} ${rule.description || ''} ${(rule.tags || []).join(' ')}`.toLowerCase(),
        ]
      );
      indexed++;
    } catch (error) {
      // Skip invalid files
    }
  }
  
  return indexed;
}

function indexStories(basePath: string): number {
  const files = findYamlFiles(basePath);
  let indexed = 0;
  
  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const story = parseYaml(content);
      
      if (!story || !story.name) continue;
      
      const id = story.id || `story_${path.basename(filePath, path.extname(filePath))}`;
      
      runStatement(
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
  
  return indexed;
}

// Helper functions
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
