// Tool Registration System - Plugin-style architecture for MCP tools

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

class ToolRegistry {
  private tools: Map<string, ToolDefinition> = new Map();

  /**
   * Active tool profile, or null for no filtering.
   *
   * Applied in two places, both necessary. `toMcpTools()` shapes what a client
   * is told exists; `execute()` enforces it. Filtering only the listing would
   * be insufficient because mcpo and Open WebUI cache tool lists, and a model
   * that saw a name earlier in a conversation will try it again.
   */
  private profile: Set<string> | null = null;

  setProfile(names: readonly string[] | null): void {
    this.profile = names === null ? null : new Set(names);
  }

  getProfile(): string[] | null {
    return this.profile === null ? null : [...this.profile];
  }

  /** Whether a tool is exposed under the active profile. */
  isActive(name: string): boolean {
    return this.profile === null ? this.tools.has(name) : this.profile.has(name) && this.tools.has(name);
  }

  /** Registered names the active profile exposes, in registration order. */
  getActiveNames(): string[] {
    return this.getNames().filter(n => this.isActive(n));
  }

  /** Count of tools the active profile exposes, as opposed to count() which is the raw total. */
  activeCount(): number {
    return this.profile === null ? this.tools.size : this.getActiveNames().length;
  }

  register(tool: ToolDefinition): void {
    if (this.tools.has(tool.name)) {
      console.warn(`[registry] Tool ${tool.name} already registered, overwriting`);
    }
    this.tools.set(tool.name, tool);
  }

  registerAll(tools: ToolDefinition[]): void {
    tools.forEach(t => this.register(t));
  }

  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  getAll(): ToolDefinition[] {
    return Array.from(this.tools.values());
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  getNames(): string[] {
    return Array.from(this.tools.keys());
  }

  async execute(name: string, args: Record<string, unknown>): Promise<unknown> {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new Error(`Unknown tool: ${name}. Available: ${this.getActiveNames().join(', ')}`);
    }
    // Registered but out of profile. Reported distinctly from "unknown" so the
    // cause is diagnosable — a client working from a cached tool list looks
    // identical to a hallucinated name otherwise.
    if (!this.isActive(name)) {
      throw new Error(
        `Tool ${name} exists but is not available under the active tool profile. ` +
        `Available: ${this.getActiveNames().join(', ')}`
      );
    }
    return tool.handler(args);
  }

  async executeForMcp(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      const result = await this.execute(name, args);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: true, message }) }],
        isError: true,
      };
    }
  }

  toMcpTools(): Array<{ name: string; description: string; inputSchema: object }> {
    return this.getAll()
      .filter(t => this.isActive(t.name))
      .map(t => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      }));
  }

  count(): number {
    return this.tools.size;
  }

  unregister(name: string): boolean {
    return this.tools.delete(name);
  }

  clear(): void {
    this.tools.clear();
  }
}

// Singleton instance
export const toolRegistry = new ToolRegistry();

// Helper to define a tool with type safety
export function defineTool(definition: ToolDefinition): ToolDefinition {
  return definition;
}

// Helper to register a tool inline
export function registerTool(definition: ToolDefinition): ToolDefinition {
  toolRegistry.register(definition);
  return definition;
}
