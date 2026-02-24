import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'sekoia',
  name:   'Sekoia.io',
  search: 'https://blog.sekoia.io/',
  rss:    'https://blog.sekoia.io/feed/',
};

export const sekoiaTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const sekoiaToolCount = sekoiaTools.length;
