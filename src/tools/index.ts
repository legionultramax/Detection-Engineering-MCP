// Tool aggregation and registration entry point
export { toolRegistry, defineTool, registerTool } from './registry.js';
export type { ToolDefinition, ToolResult } from './registry.js';
export { PROFILES, WRITE_TOOLS, resolveProfile, unresolvedNames, UnknownProfileError } from './profiles.js';
export type { ToolProfile } from './profiles.js';

// Tool module imports
import { detectionTools, detectionToolCount } from './detections/index.js';
import { threatIntelTools, threatIntelToolCount } from './threat-intel/index.js';
import { knowledgeTools, knowledgeToolCount } from './knowledge/index.js';
import { mitreAttackTools, mitreAttackToolCount } from './mitre-attack/index.js';
import { atomicRedTeamTools, atomicRedTeamToolCount } from './atomic-red-team/index.js';
import { coverageEngineTools, coverageEngineToolCount } from './coverage-engine/index.js';
import { reportGeneratorTools, reportGeneratorToolCount } from './report-generator/index.js';
import { sublimeTools, sublimeToolCount } from './sublime/index.js';
import { lolfarmTools, lolfarmToolCount } from './lolfarm/index.js';
import { engineeringTools, engineeringToolCount } from './engineering/index.js';

import { toolRegistry } from './registry.js';

// Re-export for direct access
export { detectionTools, detectionToolCount } from './detections/index.js';
export { threatIntelTools, threatIntelToolCount } from './threat-intel/index.js';
export { knowledgeTools, knowledgeToolCount } from './knowledge/index.js';
export { mitreAttackTools, mitreAttackToolCount } from './mitre-attack/index.js';
export { atomicRedTeamTools, atomicRedTeamToolCount } from './atomic-red-team/index.js';
export { coverageEngineTools, coverageEngineToolCount } from './coverage-engine/index.js';
export { reportGeneratorTools, reportGeneratorToolCount } from './report-generator/index.js';
export { sublimeTools, sublimeToolCount } from './sublime/index.js';
export { lolfarmTools, lolfarmToolCount } from './lolfarm/index.js';
export { engineeringTools, engineeringToolCount } from './engineering/index.js';

export function registerAllTools(): void {
  // Register all tool modules
  toolRegistry.registerAll(detectionTools);
  toolRegistry.registerAll(threatIntelTools);
  toolRegistry.registerAll(knowledgeTools);
  toolRegistry.registerAll(mitreAttackTools);
  toolRegistry.registerAll(atomicRedTeamTools);
  toolRegistry.registerAll(coverageEngineTools);
  toolRegistry.registerAll(reportGeneratorTools);
  toolRegistry.registerAll(sublimeTools);
  toolRegistry.registerAll(lolfarmTools);
  toolRegistry.registerAll(engineeringTools);

  console.error(`[tools] Registry initialized with ${toolRegistry.count()} tools`);
  console.error(`[tools] - Detections: ${detectionToolCount}`);
  console.error(`[tools] - Threat Intel: ${threatIntelToolCount}`);
  console.error(`[tools] - Knowledge: ${knowledgeToolCount}`);
  console.error(`[tools] - MITRE ATT&CK: ${mitreAttackToolCount}`);
  console.error(`[tools] - Atomic Red Team: ${atomicRedTeamToolCount}`);
  console.error(`[tools] - Coverage Engine: ${coverageEngineToolCount}`);
  console.error(`[tools] - Report Generator: ${reportGeneratorToolCount}`);
  console.error(`[tools] - Sublime Security: ${sublimeToolCount}`);
  console.error(`[tools] - LOLFarm: ${lolfarmToolCount}`);
  console.error(`[tools] - Query Engineering: ${engineeringToolCount}`);
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
      atomic_red_team: atomicRedTeamToolCount,
      coverage_engine: coverageEngineToolCount,
      report_generator: reportGeneratorToolCount,
      sublime: sublimeToolCount,
      lolfarm: lolfarmToolCount,
      engineering: engineeringToolCount,
    },
  };
}
