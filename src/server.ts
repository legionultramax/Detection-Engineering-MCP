// MCP Server setup and configuration
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  CompleteRequestSchema,
  SubscribeRequestSchema,
  UnsubscribeRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { handleToolCall, listTools } from './handlers/tools.js';
import { listPrompts, getPrompt } from './handlers/prompts.js';
import { listResources, listResourceTemplates, readResource } from './handlers/resources.js';

const SERVER_VERSION = '1.0.0';

const SERVER_INSTRUCTIONS = `# Harris HawkEye MCP

## Tool Categories

### Detection Search & Management (20+ tools)
- search_detections, get_detection, list_detections
- list_by_mitre, list_by_severity, list_by_source
- analyze_coverage, identify_gaps, suggest_detections

### Threat Intelligence (15+ tools)
- lookup_mitre_technique, lookup_mitre_tactic
- lookup_cve, search_nvd
- check_cisa_kev, get_kev_list
- lookup_lolbas, lookup_gtfobins
- search_malware_bazaar, check_ioc

### Knowledge Graph (Tribal Knowledge)
- create_entity, create_relation
- log_decision, add_learning
- search_knowledge, get_decisions

### Detection Engineering
- validate_sigma, convert_sigma
- analyze_detection_quality
- generate_detection_template

### Cache & Storage
- cache_result, get_cached, clear_cache
- create_table, query_table

## Data Sources
- MITRE ATT&CK Framework
- National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV)
- LOLBAS (Living Off The Land Binaries)
- GTFOBins
- Sigma Rules
- Splunk Enterprise Security Content Updates (ESCU)
- Elastic Detection Rules
- Microsoft KQL/Sentinel Rules

## Quick Start
1. get_stats() - See detection inventory
2. lookup_mitre_technique("T1059") - Research technique
3. search_detections("powershell execution") - Find detections
4. analyze_coverage() - Get MITRE coverage analysis`;

// Global server instance
let serverInstance: Server | null = null;

export function getServerInstance(): Server | null {
  return serverInstance;
}

// Helper to wrap handlers with error handling
function wrapHandler<T, R>(
  handlerName: string,
  handler: (request: T) => Promise<R>
): (request: T) => Promise<R> {
  return async (request: T): Promise<R> => {
    try {
      return await handler(request);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[harris-hawkeye-mcp] Error in ${handlerName}: ${message}`);
      throw error;
    }
  };
}

export function createServer(): Server {
  const server = new Server(
    {
      name: 'harris-hawkeye-mcp',
      version: SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
        prompts: { listChanged: true },
        resources: { subscribe: true, listChanged: true },
        completions: {},
      },
      instructions: SERVER_INSTRUCTIONS,
    }
  );

  serverInstance = server;

  // List tools handler
  server.setRequestHandler(ListToolsRequestSchema, wrapHandler('listTools', async () => listTools()));

  // Call tool handler
  server.setRequestHandler(CallToolRequestSchema, wrapHandler('callTool', async (request) => {
    const { name, arguments: args = {} } = request.params;
    const result = await handleToolCall(name, args as Record<string, unknown>);
    
    if (result && typeof result === 'object' && 'content' in result) {
      return result as { content: Array<{ type: 'text'; text: string }>; isError?: boolean };
    }
    
    return {
      content: [{ type: 'text' as const, text: JSON.stringify(result) }],
    };
  }));

  // List prompts handler
  server.setRequestHandler(ListPromptsRequestSchema, wrapHandler('listPrompts', async () => listPrompts()));

  // Get prompt handler
  server.setRequestHandler(GetPromptRequestSchema, wrapHandler('getPrompt', async (request) => {
    const { name, arguments: args = {} } = request.params;
    return getPrompt(name, args as Record<string, string>);
  }));

  // List resources handler
  server.setRequestHandler(ListResourcesRequestSchema, wrapHandler('listResources', async () => {
    const { resources } = listResources();
    const { resourceTemplates } = listResourceTemplates();
    return { resources, resourceTemplates };
  }));

  // Read resource handler
  server.setRequestHandler(ReadResourceRequestSchema, wrapHandler('readResource', async (request) => {
    return readResource(request.params.uri);
  }));

  // Completions handler for autocomplete
  server.setRequestHandler(CompleteRequestSchema, wrapHandler('complete', async (request) => {
    const { argument } = request.params;
    
    if (!argument) {
      return { completion: { values: [], hasMore: false } };
    }

    const argName = argument.name;
    const prefix = argument.value || '';
    
    let values: string[] = [];
    
    switch (argName) {
      case 'technique_id':
      case 'technique':
        values = ['T1059', 'T1059.001', 'T1059.003', 'T1547', 'T1547.001', 'T1055', 'T1003']
          .filter(t => t.toLowerCase().startsWith(prefix.toLowerCase()));
        break;
      case 'tactic':
        values = [
          'reconnaissance', 'resource-development', 'initial-access', 'execution',
          'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
          'discovery', 'lateral-movement', 'collection', 'command-and-control',
          'exfiltration', 'impact'
        ].filter(t => t.toLowerCase().startsWith(prefix.toLowerCase()));
        break;
      case 'source_type':
      case 'source':
        values = ['sigma', 'splunk_escu', 'elastic', 'kql'].filter(s => 
          s.toLowerCase().startsWith(prefix.toLowerCase())
        );
        break;
      case 'severity':
        values = ['critical', 'high', 'medium', 'low', 'informational'].filter(s =>
          s.toLowerCase().startsWith(prefix.toLowerCase())
        );
        break;
    }
    
    return { completion: { values, hasMore: false } };
  }));

  // Resource subscription handler
  server.setRequestHandler(SubscribeRequestSchema, wrapHandler('subscribe', async (request) => {
    const { uri } = request.params;
    const subscriptions = resourceSubscriptions.get(uri) ?? new Set<string>();
    const subscriptionId = `sub_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
    subscriptions.add(subscriptionId);
    resourceSubscriptions.set(uri, subscriptions);
    console.error(`[security-detections-mcp] Subscription created for ${uri}: ${subscriptionId}`);
    return {};
  }));

  // Resource unsubscription handler
  server.setRequestHandler(UnsubscribeRequestSchema, wrapHandler('unsubscribe', async (request) => {
    const { uri } = request.params;
    if (resourceSubscriptions.has(uri)) {
      resourceSubscriptions.delete(uri);
      console.error(`[security-detections-mcp] Unsubscribed from ${uri}`);
    }
    return {};
  }));

  return server;
}

// Track active resource subscriptions
const resourceSubscriptions = new Map<string, Set<string>>();

export async function notifyResourceChange(uri: string): Promise<void> {
  if (!serverInstance) return;
  
  const subscriptions = resourceSubscriptions.get(uri);
  if (!subscriptions || subscriptions.size === 0) return;
  
  try {
    await serverInstance.notification({
      method: 'notifications/resources/updated',
      params: { uri },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[security-detections-mcp] Failed to notify subscribers: ${message}`);
  }
}

export function clearSubscriptions(): void {
  resourceSubscriptions.clear();
}

export async function startServer(server: Server): Promise<void> {
  const transport = new StdioServerTransport();
  
  const cleanup = () => {
    console.error('[security-detections-mcp] Shutting down...');
    clearSubscriptions();
    serverInstance = null;
  };
  
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  
  await server.connect(transport);
  console.error(`[security-detections-mcp] Server started (v${SERVER_VERSION} - Enhanced Edition)`);
}
