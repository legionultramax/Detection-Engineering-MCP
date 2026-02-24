import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'volexity',
  name:   'Volexity',
  search: 'https://www.volexity.com/blog/',
  rss:    'https://www.volexity.com/blog/feed/',
};

export const volexityTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const volexityToolCount = volexityTools.length;
