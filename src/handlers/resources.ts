// MCP Resources Handler
// Exposes detection database and threat intel as resources
import { runQuery } from '../db/connection.js';

interface Resource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

interface ResourceTemplate {
  uriTemplate: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export function listResources(): { resources: Resource[] } {
  return {
    resources: [
      {
        uri: 'detections://stats',
        name: 'Detection Statistics',
        description: 'Overview of indexed detection rules',
        mimeType: 'application/json',
      },
      {
        uri: 'detections://coverage',
        name: 'MITRE Coverage',
        description: 'MITRE ATT&CK technique coverage summary',
        mimeType: 'application/json',
      },
      {
        uri: 'threat-intel://mitre-techniques',
        name: 'MITRE Techniques',
        description: 'Cached MITRE ATT&CK technique data',
        mimeType: 'application/json',
      },
      {
        uri: 'threat-intel://lolbas',
        name: 'LOLBAS Database',
        description: 'Living Off The Land Binaries and Scripts',
        mimeType: 'application/json',
      },
      {
        uri: 'knowledge://summary',
        name: 'Knowledge Summary',
        description: 'Summary of knowledge graph contents',
        mimeType: 'application/json',
      },
    ],
  };
}

export function listResourceTemplates(): { resourceTemplates: ResourceTemplate[] } {
  return {
    resourceTemplates: [
      {
        uriTemplate: 'detections://by-technique/{technique_id}',
        name: 'Detections by Technique',
        description: 'Get detections for a specific MITRE technique',
        mimeType: 'application/json',
      },
      {
        uriTemplate: 'detections://by-severity/{severity}',
        name: 'Detections by Severity',
        description: 'Get detections filtered by severity level',
        mimeType: 'application/json',
      },
      {
        uriTemplate: 'detections://search/{query}',
        name: 'Search Detections',
        description: 'Search detections by keyword',
        mimeType: 'application/json',
      },
    ],
  };
}

export function readResource(uri: string): { contents: Array<{ uri: string; mimeType: string; text: string }> } {
  let data: unknown;
  
  // Parse URI
  const [scheme, path] = uri.split('://');
  
  switch (scheme) {
    case 'detections':
      data = handleDetectionsResource(path);
      break;
    case 'threat-intel':
      data = handleThreatIntelResource(path);
      break;
    case 'knowledge':
      data = handleKnowledgeResource(path);
      break;
    default:
      throw new Error(`Unknown resource scheme: ${scheme}`);
  }
  
  return {
    contents: [{
      uri,
      mimeType: 'application/json',
      text: JSON.stringify(data, null, 2),
    }],
  };
}

function handleDetectionsResource(path: string): unknown {
  // Handle parameterized paths
  if (path.startsWith('by-technique/')) {
    const techniqueId = path.replace('by-technique/', '');
    const detections = runQuery(
      'SELECT id, name, source_type, severity FROM detections WHERE mitre_techniques LIKE ? LIMIT 50',
      [`%${techniqueId}%`]
    );
    return { technique: techniqueId, count: detections.length, detections };
  }
  
  if (path.startsWith('by-severity/')) {
    const severity = path.replace('by-severity/', '');
    const detections = runQuery(
      'SELECT id, name, source_type, severity FROM detections WHERE severity = ? LIMIT 50',
      [severity]
    );
    return { severity, count: detections.length, detections };
  }
  
  if (path.startsWith('search/')) {
    const query = decodeURIComponent(path.replace('search/', ''));
    const detections = runQuery(
      'SELECT id, name, source_type, severity FROM detections WHERE search_text LIKE ? LIMIT 50',
      [`%${query.toLowerCase()}%`]
    );
    return { query, count: detections.length, detections };
  }
  
  // Static resources
  switch (path) {
    case 'stats': {
      const total = runQuery<{ count: number }>('SELECT COUNT(*) as count FROM detections')[0]?.count || 0;
      const bySource = runQuery<{ source_type: string; count: number }>(
        'SELECT source_type, COUNT(*) as count FROM detections GROUP BY source_type'
      );
      const bySeverity = runQuery<{ severity: string; count: number }>(
        'SELECT severity, COUNT(*) as count FROM detections GROUP BY severity'
      );
      return {
        total_detections: total,
        by_source: Object.fromEntries(bySource.map(r => [r.source_type, r.count])),
        by_severity: Object.fromEntries(bySeverity.map(r => [r.severity, r.count])),
        last_updated: new Date().toISOString(),
      };
    }
    
    case 'coverage': {
      const results = runQuery<{ mitre_techniques: string }>(
        'SELECT mitre_techniques FROM detections WHERE mitre_techniques IS NOT NULL'
      );
      const techniqueCounts: Record<string, number> = {};
      for (const row of results) {
        const techniques = JSON.parse(row.mitre_techniques || '[]') as string[];
        for (const t of techniques) {
          techniqueCounts[t] = (techniqueCounts[t] || 0) + 1;
        }
      }
      const sorted = Object.entries(techniqueCounts).sort((a, b) => b[1] - a[1]);
      return {
        total_with_mitre: results.length,
        unique_techniques: Object.keys(techniqueCounts).length,
        top_techniques: sorted.slice(0, 20),
        last_updated: new Date().toISOString(),
      };
    }
    
    default:
      throw new Error(`Unknown detections resource: ${path}`);
  }
}

function handleThreatIntelResource(path: string): unknown {
  switch (path) {
    case 'mitre-techniques': {
      const techniques = runQuery('SELECT id, name, tactic_names FROM mitre_techniques LIMIT 100');
      return {
        count: techniques.length,
        techniques,
        source: 'MITRE ATT&CK',
      };
    }
    
    case 'lolbas': {
      const lolbas = runQuery('SELECT name, description, mitre_techniques FROM lolbas');
      return {
        count: lolbas.length,
        binaries: lolbas,
        source: 'LOLBAS Project',
      };
    }
    
    case 'cisa-kev': {
      const kev = runQuery('SELECT cve_id, vendor_project, product, vulnerability_name, date_added FROM cisa_kev ORDER BY date_added DESC LIMIT 50');
      return {
        count: kev.length,
        vulnerabilities: kev,
        source: 'CISA KEV',
      };
    }
    
    default:
      throw new Error(`Unknown threat-intel resource: ${path}`);
  }
}

function handleKnowledgeResource(path: string): unknown {
  switch (path) {
    case 'summary': {
      const decisions = runQuery('SELECT COUNT(*) as count FROM kg_decisions');
      const learnings = runQuery('SELECT COUNT(*) as count FROM kg_learnings');
      const entities = runQuery('SELECT COUNT(*) as count FROM kg_entities');
      const relations = runQuery('SELECT COUNT(*) as count FROM kg_relations');
      
      return {
        decisions: (decisions[0] as { count: number })?.count || 0,
        learnings: (learnings[0] as { count: number })?.count || 0,
        entities: (entities[0] as { count: number })?.count || 0,
        relations: (relations[0] as { count: number })?.count || 0,
        last_updated: new Date().toISOString(),
      };
    }
    
    case 'decisions': {
      const decisions = runQuery('SELECT id, title, decision, created_at FROM kg_decisions ORDER BY created_at DESC LIMIT 20');
      return { decisions };
    }
    
    case 'learnings': {
      const learnings = runQuery('SELECT id, topic, insight, created_at FROM kg_learnings ORDER BY created_at DESC LIMIT 20');
      return { learnings };
    }
    
    default:
      throw new Error(`Unknown knowledge resource: ${path}`);
  }
}
