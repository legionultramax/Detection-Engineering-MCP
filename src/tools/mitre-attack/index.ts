// MITRE ATT&CK Enhanced Tools
// Query threat groups, software, campaigns, mitigations, data sources
import { defineTool, ToolDefinition } from '../registry.js';
import { runQuery } from '../../db/connection.js';
import {
  getGroupByName,
  getGroupTechniques,
  getSoftwareByName,
  getMitigationsForTechnique,
  getDataSourcesForTechnique,
  searchGroups,
  searchSoftware,
  getCampaigns,
  getMitreStats,
} from '../../db/mitre-attack.js';

// Get threat group details
const getThreatGroup = defineTool({
  name: 'get_threat_group',
  description: 'Get details about a MITRE ATT&CK threat group (APT) by name or ID. Returns aliases, description, and linked techniques.',
  inputSchema: {
    type: 'object',
    properties: {
      name: { type: 'string', description: 'Threat group name (e.g., "APT29", "MuddyWater", "Lazarus Group") or MITRE ID (e.g., "G0016")' },
    },
    required: ['name'],
  },
  handler: async (args) => {
    const { name } = args as { name: string };
    const group = getGroupByName(name) as Record<string, unknown> | null;
    
    if (!group) {
      return { error: `Threat group not found: ${name}` };
    }
    
    // Get techniques used by this group
    const techniques = getGroupTechniques(group.external_id as string || name);
    
    return {
      id: group.external_id,
      name: group.name,
      aliases: group.aliases ? JSON.parse(group.aliases as string) : [],
      description: group.description,
      url: group.url,
      techniques_count: (techniques as unknown[]).length,
      techniques: (techniques as Array<Record<string, unknown>>).slice(0, 20).map(t => ({
        id: t.external_id,
        name: t.name,
        tactics: t.tactics ? JSON.parse(t.tactics as string) : [],
      })),
    };
  },
});

// Search threat groups
const searchThreatGroups = defineTool({
  name: 'search_threat_groups',
  description: 'Search MITRE ATT&CK threat groups by keyword. Searches name, description, and aliases.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search query (e.g., "Russia", "ransomware", "financial")' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query } = args as { query: string };
    const groups = searchGroups(query) as Array<Record<string, unknown>>;
    
    return {
      count: groups.length,
      groups: groups.map(g => ({
        id: g.external_id,
        name: g.name,
        aliases: g.aliases ? JSON.parse(g.aliases as string) : [],
        description: (g.description as string)?.substring(0, 200) + '...',
      })),
    };
  },
});

// Get software/tool details
const getSoftware = defineTool({
  name: 'get_software',
  description: 'Get details about MITRE ATT&CK software (malware or tools) by name. Includes Cobalt Strike, Mimikatz, etc.',
  inputSchema: {
    type: 'object',
    properties: {
      name: { type: 'string', description: 'Software name (e.g., "Cobalt Strike", "Mimikatz", "PsExec")' },
    },
    required: ['name'],
  },
  handler: async (args) => {
    const { name } = args as { name: string };
    const software = getSoftwareByName(name) as Record<string, unknown> | null;
    
    if (!software) {
      return { error: `Software not found: ${name}` };
    }
    
    // Get techniques associated with this software
    const techniques = runQuery<Record<string, unknown>>(
      `SELECT t.external_id, t.name, t.tactics FROM mitre_techniques_full t
       JOIN mitre_relationships r ON r.target_ref = t.stix_id
       WHERE r.source_ref = ? AND r.relationship_type = 'uses'`,
      [software.stix_id as string]
    );
    
    return {
      id: software.external_id,
      name: software.name,
      type: software.software_type,
      aliases: software.aliases ? JSON.parse(software.aliases as string) : [],
      platforms: software.platforms ? JSON.parse(software.platforms as string) : [],
      description: software.description,
      url: software.url,
      techniques_count: techniques.length,
      techniques: techniques.slice(0, 20).map(t => ({
        id: t.external_id,
        name: t.name,
        tactics: t.tactics ? JSON.parse(t.tactics as string) : [],
      })),
    };
  },
});

// Search software
const searchMalwareTools = defineTool({
  name: 'search_software',
  description: 'Search MITRE ATT&CK software (malware and tools) by keyword.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search query (e.g., "backdoor", "RAT", "credential")' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query } = args as { query: string };
    const software = searchSoftware(query) as Array<Record<string, unknown>>;
    
    return {
      count: software.length,
      software: software.map(s => ({
        id: s.external_id,
        name: s.name,
        type: s.software_type,
        platforms: s.platforms ? JSON.parse(s.platforms as string) : [],
        description: (s.description as string)?.substring(0, 150) + '...',
      })),
    };
  },
});

// Get mitigations for a technique
const getMitigations = defineTool({
  name: 'get_mitigations',
  description: 'Get MITRE ATT&CK mitigations for a specific technique. Answers "How do I mitigate T1059?"',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., "T1059", "T1059.001")' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id } = args as { technique_id: string };
    const mitigations = getMitigationsForTechnique(technique_id) as Array<Record<string, unknown>>;
    
    if (mitigations.length === 0) {
      return { 
        technique_id,
        message: 'No mitigations found for this technique',
        mitigations: [],
      };
    }
    
    return {
      technique_id,
      count: mitigations.length,
      mitigations: mitigations.map(m => ({
        id: m.external_id,
        name: m.name,
        description: m.description,
        url: m.url,
      })),
    };
  },
});

// Get data sources for a technique
const getDataSources = defineTool({
  name: 'get_data_sources',
  description: 'Get required data sources and log types to detect a MITRE technique. Answers "What logs do I need for T1021?"',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., "T1021", "T1059.001")' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id } = args as { technique_id: string };
    const sources = getDataSourcesForTechnique(technique_id) as Array<Record<string, unknown>>;
    
    if (sources.length === 0) {
      // Try to get from technique's detection field
      const technique = runQuery<Record<string, unknown>>(
        `SELECT detection FROM mitre_techniques_full WHERE external_id = ?`,
        [technique_id.toUpperCase()]
      );
      
      return {
        technique_id,
        detection_guidance: technique[0]?.detection || 'No specific detection guidance available',
        data_sources: [],
      };
    }
    
    // Group by data source
    const grouped: Record<string, { source: string; components: string[] }> = {};
    for (const s of sources) {
      const sourceName = s.name as string;
      if (!grouped[sourceName]) {
        grouped[sourceName] = {
          source: sourceName,
          components: [],
        };
      }
      if (s.component_name) {
        grouped[sourceName].components.push(s.component_name as string);
      }
    }
    
    return {
      technique_id,
      count: Object.keys(grouped).length,
      data_sources: Object.values(grouped),
    };
  },
});

// List campaigns
const listCampaigns = defineTool({
  name: 'list_campaigns',
  description: 'List MITRE ATT&CK campaigns, optionally filtered by search query.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Optional search query to filter campaigns' },
    },
  },
  handler: async (args) => {
    const { query } = args as { query?: string };
    const campaigns = getCampaigns(query) as Array<Record<string, unknown>>;
    
    return {
      count: campaigns.length,
      campaigns: campaigns.map(c => ({
        id: c.external_id,
        name: c.name,
        first_seen: c.first_seen,
        last_seen: c.last_seen,
        description: (c.description as string)?.substring(0, 200) + '...',
        url: c.url,
      })),
    };
  },
});

// Get groups that use a specific technique
const getGroupsUsingTechnique = defineTool({
  name: 'get_groups_using_technique',
  description: 'Find all threat groups that use a specific MITRE technique.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., "T1059", "T1059.001")' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id } = args as { technique_id: string };
    
    const groups = runQuery<Record<string, unknown>>(
      `SELECT g.* FROM mitre_groups g
       JOIN mitre_relationships r ON r.source_ref = g.stix_id
       JOIN mitre_techniques_full t ON r.target_ref = t.stix_id
       WHERE t.external_id = ? AND r.relationship_type = 'uses'
       ORDER BY g.name`,
      [technique_id.toUpperCase()]
    );
    
    return {
      technique_id,
      count: groups.length,
      groups: groups.map(g => ({
        id: g.external_id,
        name: g.name,
        aliases: g.aliases ? JSON.parse(g.aliases as string) : [],
      })),
    };
  },
});

// Get software that uses a specific technique
const getSoftwareUsingTechnique = defineTool({
  name: 'get_software_using_technique',
  description: 'Find all malware and tools that use a specific MITRE technique.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., "T1059", "T1055")' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id } = args as { technique_id: string };
    
    const malware = runQuery<Record<string, unknown>>(
      `SELECT m.*, 'malware' as software_type FROM mitre_malware m
       JOIN mitre_relationships r ON r.source_ref = m.stix_id
       JOIN mitre_techniques_full t ON r.target_ref = t.stix_id
       WHERE t.external_id = ? AND r.relationship_type = 'uses'`,
      [technique_id.toUpperCase()]
    );
    
    const tools = runQuery<Record<string, unknown>>(
      `SELECT t2.*, 'tool' as software_type FROM mitre_tools t2
       JOIN mitre_relationships r ON r.source_ref = t2.stix_id
       JOIN mitre_techniques_full t ON r.target_ref = t.stix_id
       WHERE t.external_id = ? AND r.relationship_type = 'uses'`,
      [technique_id.toUpperCase()]
    );
    
    const software = [...malware, ...tools];
    
    return {
      technique_id,
      count: software.length,
      malware_count: malware.length,
      tools_count: tools.length,
      software: software.map(s => ({
        id: s.external_id,
        name: s.name,
        type: s.software_type,
      })),
    };
  },
});

// Get MITRE ATT&CK stats
const getMitreAttackStats = defineTool({
  name: 'get_mitre_attack_stats',
  description: 'Get statistics about the indexed MITRE ATT&CK data (groups, software, techniques, etc.)',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    return getMitreStats();
  },
});

// List all data sources
const listDataSources = defineTool({
  name: 'list_data_sources',
  description: 'List all MITRE ATT&CK data sources with their data components.',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    const sources = runQuery<Record<string, unknown>>(
      `SELECT ds.*, 
       (SELECT GROUP_CONCAT(dc.name, ', ') FROM mitre_data_components dc WHERE dc.data_source_id = ds.stix_id) as components
       FROM mitre_data_sources ds
       ORDER BY ds.name`
    );
    
    return {
      count: sources.length,
      data_sources: sources.map(s => ({
        id: s.external_id,
        name: s.name,
        platforms: s.platforms ? JSON.parse(s.platforms as string) : [],
        components: s.components ? (s.components as string).split(', ') : [],
      })),
    };
  },
});

export const mitreAttackTools: ToolDefinition[] = [
  getThreatGroup,
  searchThreatGroups,
  getSoftware,
  searchMalwareTools,
  getMitigations,
  getDataSources,
  listCampaigns,
  getGroupsUsingTechnique,
  getSoftwareUsingTechnique,
  getMitreAttackStats,
  listDataSources,
];

export const mitreAttackToolCount = mitreAttackTools.length;
