// Tool aggregation and registration entry point
export { toolRegistry, defineTool, registerTool } from './registry.js';
export type { ToolDefinition, ToolResult } from './registry.js';

// Tool module imports
import { detectionTools, detectionToolCount } from './detections/index.js';
import { threatIntelTools, threatIntelToolCount } from './threat-intel/index.js';
import { knowledgeTools, knowledgeToolCount } from './knowledge/index.js';
import { mitreAttackTools, mitreAttackToolCount } from './mitre-attack/index.js';

import { toolRegistry } from './registry.js';

// Re-export for direct access
export { detectionTools, detectionToolCount } from './detections/index.js';
export { threatIntelTools, threatIntelToolCount } from './threat-intel/index.js';
export { knowledgeTools, knowledgeToolCount } from './knowledge/index.js';
export { mitreAttackTools, mitreAttackToolCount } from './mitre-attack/index.js';

export function registerAllTools(): void {
  // Register all tool modules
  toolRegistry.registerAll(detectionTools);
  toolRegistry.registerAll(threatIntelTools);
  toolRegistry.registerAll(knowledgeTools);
  toolRegistry.registerAll(mitreAttackTools);
  
  console.error(`[tools] Registry initialized with ${toolRegistry.count()} tools`);
  console.error(`[tools] - Detections: ${detectionToolCount}`);
  console.error(`[tools] - Threat Intel: ${threatIntelToolCount}`);
  console.error(`[tools] - Knowledge: ${knowledgeToolCount}`);
  console.error(`[tools] - MITRE ATT&CK: ${mitreAttackToolCount}`);
}

export function getToolsSummary(): { total: number; names: string[]; threat_intel: number; byModule: Record<string, number> } {
  return {
    total: toolRegistry.count(),
    names: toolRegistry.getNames(),
    threat_intel: threatIntelToolCount,
    byModule: {
      detections: detectionToolCount,
      threat_intel: threatIntelToolCount,
      knowledge: knowledgeToolCount,
      mitre_attack: mitreAttackToolCount,
    },
  };
}
