import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'red_canary',
  name:   'Red Canary',
  search: 'https://redcanary.com/blog/',
  rss:    'https://redcanary.com/blog/feed/',
};

export const redCanaryTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const redCanaryToolCount = redCanaryTools.length;
