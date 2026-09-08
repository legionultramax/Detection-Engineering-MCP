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
import {
  toolRegistry,
  detectionTools,
  threatIntelTools,
  knowledgeTools,
  mitreAttackTools,
  atomicRedTeamTools,
  coverageEngineTools,
  reportGeneratorTools,
  sublimeTools,
  lolfarmTools,
} from './tools/index.js';
import type { ToolDefinition } from './tools/index.js';

const SERVER_VERSION = '1.0.0';

// Server instructions are generated from the live tool registry rather than
// hand-maintained. A hardcoded list drifts the moment a tool is added, renamed,
// or dropped — and advertising a tool that does not exist causes models to emit
// calls that fail with "Unknown tool". Names are filtered through the registry's
// active profile, so a scoped deployment describes only what it will actually
// dispatch and the instructions shrink with the profile automatically.
function buildServerInstructions(): string {
  const categories: Array<{ label: string; tools: ToolDefinition[] }> = [
    { label: 'Detection Search & Analysis', tools: detectionTools },
    { label: 'Threat Intelligence', tools: threatIntelTools },
    { label: 'MITRE ATT&CK', tools: mitreAttackTools },
    { label: 'Atomic Red Team', tools: atomicRedTeamTools },
    { label: 'Coverage Engine', tools: coverageEngineTools },
    { label: 'LOLFarm (Living Off The Land)', tools: lolfarmTools },
    { label: 'Knowledge Graph', tools: knowledgeTools },
    { label: 'Sublime Security (Email)', tools: sublimeTools },
    { label: 'Reporting', tools: reportGeneratorTools },
  ];

  const sections: string[] = [];
  let total = 0;

  for (const { label, tools } of categories) {
    const names = tools
      .map(t => t.name)
      .filter(name => toolRegistry.isActive(name))
      .sort();
    if (names.length === 0) continue;
    total += names.length;
    sections.push(`### ${label} (${names.length})\n${names.join(', ')}`);
  }

  // Only advertise starting points that are actually reachable — under a scoped
  // profile some of these are not exposed.
  const startingPoints: Array<[string, string]> = [
    ['get_stats', 'get_stats() — current detection inventory'],
    ['search_detections', 'search_detections("<keywords>") — full-text search across all rule sources'],
    ['list_by_mitre', 'list_by_mitre("T1059.001") — existing coverage for a technique'],
    ['lookup_mitre_technique', 'lookup_mitre_technique("T1059.001") — technique detail, data sources, detection guidance'],
    ['get_lolfarm_context', 'get_lolfarm_context("T1059.001") — living-off-the-land context for a technique'],
  ];
  const suggestions = startingPoints
    .filter(([name]) => toolRegistry.isActive(name))
    .map(([, line]) => `- ${line}`);

  const scoped = toolRegistry.getProfile() !== null;

  return [
    '# Harris HawkEye MCP',
    '',
    `Detection engineering and threat intelligence server exposing ${total} tools.`,
    'Only the tools listed below exist. Do not call a tool that is not named here.',
    ...(scoped
      ? ['', 'This deployment runs a scoped tool profile. Other tools exist on the server but ' +
         'are not available here; do not attempt to call them.']
      : []),
    '',
    '## Tools by category',
    '',
    ...sections,
    '',
    '## Data sources',
    '- Detection rules: SigmaHQ, Splunk ESCU, Elastic, Azure Sentinel (KQL), Sublime Security',
    '- MITRE ATT&CK: techniques, groups, software, campaigns, mitigations, data sources',
    '- Atomic Red Team adversary simulation tests',
    '- LOLBAS and LOLFarm: LOLDrivers, HijackLibs, LOLRMM, LoFP, WADComs, LOTS, MalAPI',
    '- Threat intel: abuse.ch, AlienVault OTX, NVD/EPSS, CISA KEV, Malpedia, government CERT advisories',
    '',
    '## Suggested starting points',
    ...suggestions,
  ].join('\n');
}

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
      instructions: buildServerInstructions(),
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
