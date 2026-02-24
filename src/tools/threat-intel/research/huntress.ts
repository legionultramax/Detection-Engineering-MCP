import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'huntress',
  name:   'Huntress Labs',
  search: 'https://www.huntress.com/blog',
  rss:    'https://www.huntress.com/blog/rss.xml',
};

export const huntressTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const huntressToolCount = huntressTools.length;
