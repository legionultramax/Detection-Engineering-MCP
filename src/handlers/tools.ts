// MCP Tools Handler
import { toolRegistry } from '../tools/index.js';

export function listTools() {
  return {
    tools: toolRegistry.toMcpTools(),
  };
}

export async function handleToolCall(
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
  return toolRegistry.executeForMcp(name, args);
}
