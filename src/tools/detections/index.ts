// Detection Tools - Search, filter, and analyze security detections
import { defineTool, ToolDefinition } from '../registry.js';
import { runQuery } from '../../db/connection.js';
import { cveToDetectionTool, handleCVEToDetection } from './cve-detection.js';
import { handleYARAToSigma } from './yara-to-sigma.js';
import { handleSigmaToKQL } from './sigma-to-kql.js';

interface Detection {
  id: string;
  name: string;
  description: string;
  source_type: string;
  severity: string;
  status: string;
  author: string;
  mitre_tactics: string;
  mitre_techniques: string;
  tags: string;
  query: string;
}

// Search detections by keyword
const searchDetections = defineTool({
  name: 'search_detections',
  description: 'Search security detections by keyword across name, description, and tags. Supports Sigma, Splunk ESCU, Elastic, and KQL rules.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search keyword or phrase' },
      source: { type: 'string', description: 'Filter by source: sigma, splunk_escu, elastic, kql' },
      severity: { type: 'string', description: 'Filter by severity: critical, high, medium, low' },
      limit: { type: 'number', description: 'Maximum results to return (default: 20)' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query, source, severity, limit = 20 } = args as { 
      query: string; source?: string; severity?: string; limit?: number 
    };
    
    let sql = 'SELECT id, name, description, source_type, severity, mitre_techniques FROM detections WHERE search_text LIKE ?';
    const params: unknown[] = [`%${query.toLowerCase()}%`];
    
    if (source) {
      sql += ' AND source_type = ?';
      params.push(source);
    }
    if (severity) {
      sql += ' AND severity = ?';
      params.push(severity);
    }
    
    sql += ' ORDER BY name LIMIT ?';
    params.push(limit);
    
    const results = runQuery<Detection>(sql, params);
    return {
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        description: d.description?.substring(0, 200),
        source: d.source_type,
        severity: d.severity,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      })),
    };
  },
});

// Get detection by ID
const getDetection = defineTool({
  name: 'get_detection',
  description: 'Get full details of a specific detection by ID',
  inputSchema: {
    type: 'object',
    properties: {
      id: { type: 'string', description: 'Detection ID' },
    },
    required: ['id'],
  },
  handler: async (args) => {
    const { id } = args as { id: string };
    const results = runQuery<Detection>('SELECT * FROM detections WHERE id = ?', [id]);
    
    if (results.length === 0) {
      return { error: 'Detection not found' };
    }
    
    const d = results[0];
    return {
      id: d.id,
      name: d.name,
      description: d.description,
      source: d.source_type,
      severity: d.severity,
      status: d.status,
      author: d.author,
      tactics: d.mitre_tactics ? JSON.parse(d.mitre_tactics) : [],
      techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      tags: d.tags ? JSON.parse(d.tags) : [],
      query: d.query,
    };
  },
});

// List detections by MITRE technique
const listByMitre = defineTool({
  name: 'list_by_mitre',
  description: 'List detections mapped to a specific MITRE ATT&CK technique ID (e.g., T1059, T1059.001)',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., T1059)' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id, limit = 50 } = args as { technique_id: string; limit?: number };
    
    const results = runQuery<Detection>(
      `SELECT id, name, source_type, severity, mitre_techniques 
       FROM detections 
       WHERE mitre_techniques LIKE ? 
       ORDER BY severity DESC, name 
       LIMIT ?`,
      [`%${technique_id.toUpperCase()}%`, limit]
    );
    
    return {
      technique: technique_id,
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        severity: d.severity,
      })),
    };
  },
});

// List detections by severity
const listBySeverity = defineTool({
  name: 'list_by_severity',
  description: 'List detections filtered by severity level',
  inputSchema: {
    type: 'object',
    properties: {
      severity: { type: 'string', description: 'Severity: critical, high, medium, low' },
      source: { type: 'string', description: 'Optional source filter' },
      limit: { type: 'number', description: 'Maximum results (default: 50)' },
    },
    required: ['severity'],
  },
  handler: async (args) => {
    const { severity, source, limit = 50 } = args as { severity: string; source?: string; limit?: number };
    
    let sql = 'SELECT id, name, source_type, severity, mitre_techniques FROM detections WHERE severity = ?';
    const params: unknown[] = [severity];
    
    if (source) {
      sql += ' AND source_type = ?';
      params.push(source);
    }
    
    sql += ' ORDER BY name LIMIT ?';
    params.push(limit);
    
    const results = runQuery<Detection>(sql, params);
    
    return {
      severity,
      count: results.length,
      detections: results.map(d => ({
        id: d.id,
        name: d.name,
        source: d.source_type,
        techniques: d.mitre_techniques ? JSON.parse(d.mitre_techniques) : [],
      })),
    };
  },
});

// Get detection statistics
const getStats = defineTool({
  name: 'get_stats',
  description: 'Get statistics about indexed detections including counts by source, severity, and MITRE coverage',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    const total = runQuery<{ count: number }>('SELECT COUNT(*) as count FROM detections')[0]?.count || 0;
    const bySource = runQuery<{ source_type: string; count: number }>(
      'SELECT source_type, COUNT(*) as count FROM detections GROUP BY source_type'
    );
    const bySeverity = runQuery<{ severity: string; count: number }>(
      'SELECT severity, COUNT(*) as count FROM detections GROUP BY severity ORDER BY count DESC'
    );
    
    return {
      total_detections: total,
      by_source: Object.fromEntries(bySource.map(r => [r.source_type, r.count])),
      by_severity: Object.fromEntries(bySeverity.map(r => [r.severity, r.count])),
    };
  },
});

// Analyze MITRE coverage
const analyzeCoverage = defineTool({
  name: 'analyze_coverage',
  description: 'Analyze MITRE ATT&CK technique coverage across all indexed detections',
  inputSchema: {
    type: 'object',
    properties: {
      source: { type: 'string', description: 'Optional: filter by source type' },
    },
  },
  handler: async (args) => {
    const { source } = args as { source?: string };
    
    let sql = 'SELECT mitre_techniques, mitre_tactics FROM detections WHERE mitre_techniques IS NOT NULL';
    const params: unknown[] = [];
    
    if (source) {
      sql += ' AND source_type = ?';
      params.push(source);
    }
    
    const results = runQuery<{ mitre_techniques: string; mitre_tactics: string }>(sql, params);
    
    const techniqueCounts: Record<string, number> = {};
    const tacticCounts: Record<string, number> = {};
    
    for (const row of results) {
      const techniques = JSON.parse(row.mitre_techniques || '[]') as string[];
      const tactics = JSON.parse(row.mitre_tactics || '[]') as string[];
      
      for (const t of techniques) {
        techniqueCounts[t] = (techniqueCounts[t] || 0) + 1;
      }
      for (const t of tactics) {
        tacticCounts[t] = (tacticCounts[t] || 0) + 1;
      }
    }
    
    const sortedTechniques = Object.entries(techniqueCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20);
    
    return {
      total_detections_with_mitre: results.length,
      unique_techniques: Object.keys(techniqueCounts).length,
      tactic_coverage: tacticCounts,
      top_techniques: sortedTechniques.map(([id, count]) => ({ technique: id, count })),
    };
  },
});

// Identify coverage gaps
const identifyGaps = defineTool({
  name: 'identify_gaps',
  description: 'Identify potential detection gaps for a threat profile or technique area',
  inputSchema: {
    type: 'object',
    properties: {
      profile: { 
        type: 'string', 
        description: 'Threat profile: ransomware, apt, initial-access, persistence, credential-access, etc.' 
      },
    },
    required: ['profile'],
  },
  handler: async (args) => {
    const { profile } = args as { profile: string };
    
    // Define technique families by threat profile
    const profileTechniques: Record<string, string[]> = {
      'ransomware': ['T1486', 'T1490', 'T1489', 'T1083', 'T1082', 'T1059', 'T1047', 'T1021'],
      'apt': ['T1566', 'T1059', 'T1053', 'T1547', 'T1055', 'T1003', 'T1021', 'T1041'],
      'initial-access': ['T1566', 'T1190', 'T1133', 'T1078', 'T1195', 'T1189'],
      'persistence': ['T1547', 'T1053', 'T1136', 'T1543', 'T1574', 'T1546'],
      'credential-access': ['T1003', 'T1558', 'T1552', 'T1555', 'T1110', 'T1557'],
      'defense-evasion': ['T1055', 'T1027', 'T1070', 'T1562', 'T1036', 'T1218'],
    };
    
    const targetTechniques = profileTechniques[profile.toLowerCase()] || [];
    
    if (targetTechniques.length === 0) {
      return { 
        error: `Unknown profile: ${profile}. Available: ${Object.keys(profileTechniques).join(', ')}` 
      };
    }
    
    const coverage: Record<string, number> = {};
    const gaps: string[] = [];
    
    for (const technique of targetTechniques) {
      const count = runQuery<{ count: number }>(
        'SELECT COUNT(*) as count FROM detections WHERE mitre_techniques LIKE ?',
        [`%${technique}%`]
      )[0]?.count || 0;
      
      coverage[technique] = count;
      if (count === 0) {
        gaps.push(technique);
      }
    }
    
    return {
      profile,
      target_techniques: targetTechniques,
      coverage,
      gaps,
      gap_count: gaps.length,
      coverage_percentage: Math.round(((targetTechniques.length - gaps.length) / targetTechniques.length) * 100),
    };
  },
});

// CVE to Detection - Generate detection queries from CVE
const cveToDetection = defineTool({
  name: 'cve_to_detection',
  description: 'Convert a CVE into actionable SIEM detection logic. Fetches CVE details from NVD, maps to MITRE ATT&CK techniques, and generates detection queries in KQL (Sentinel), Splunk SPL, and Sigma formats with threat hunting hypotheses, false positive considerations, and response actions.',
  inputSchema: {
    type: 'object',
    properties: {
      cve_id: { type: 'string', description: 'CVE identifier (e.g., CVE-2024-1234)' },
    },
    required: ['cve_id'],
  },
  handler: async (args) => {
    const result = await handleCVEToDetection(args as { cve_id: string });
    return result;
  },
});

// YARA to Sigma Converter
const yaraToSigma = defineTool({
  name: 'convert_yara_to_sigma',
  description: 'Convert a YARA rule to an approximate Sigma rule. Best-effort conversion focused on string/hex conditions mapped to process_creation logs (CommandLine). Always include a warning that manual review is required.',
  inputSchema: {
    type: 'object',
    properties: {
      yara_rule: { type: 'string', description: 'The full YARA rule text to convert' },
      logsource_category: { type: 'string', description: 'Sigma logsource category (default: process_creation)' },
      product: { type: 'string', description: 'Target product (default: windows)' },
      title_override: { type: 'string', description: 'Custom title for the generated Sigma rule' },
    },
    required: ['yara_rule'],
  },
  handler: async (args) => {
    const result = handleYARAToSigma(args as {
      yara_rule: string;
      logsource_category?: string;
      product?: string;
      title_override?: string;
    });
    return result;
  },
});

// Sigma to KQL Converter
const sigmaToKQL = defineTool({
  name: 'convert_sigma_to_kql',
  description: 'Convert Sigma detection rules to Kibana Query Language (KQL) for Elastic Stack (Kibana, Elasticsearch). Uses Elastic Common Schema (ECS) field mappings and simple field:value syntax. Supports modifiers, wildcards, and complex conditions.',
  inputSchema: {
    type: 'object',
    properties: {
      sigma_rule: {
        type: 'string',
        description: 'The full Sigma rule in YAML format'
      },
      timeframe: {
        type: 'string',
        description: 'Time window for the query (default: 24h). Examples: 1h, 7d, 30d'
      },
      target_platform: {
        type: 'string',
        description: 'Target platform: elastic (Elastic Stack/Kibana) - default: elastic'
      },
      include_comments: {
        type: 'boolean',
        description: 'Include explanatory comments in KQL output (default: true)'
      },
    },
    required: ['sigma_rule'],
  },
  handler: async (args) => {
    const result = handleSigmaToKQL(args as {
      sigma_rule: string;
      timeframe?: string;
      target_platform?: string;
      include_comments?: boolean;
    });
    return result;
  },
});

export const detectionTools: ToolDefinition[] = [
  searchDetections,
  getDetection,
  listByMitre,
  listBySeverity,
  getStats,
  analyzeCoverage,
  identifyGaps,
  cveToDetection,
  yaraToSigma,
  sigmaToKQL,
];

export const detectionToolCount = detectionTools.length;
