import { createVendorSearchTool, createVendorFetchTool } from './utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from './types.js';

const config: VendorConfig = {
  key:    'crowdstrike',
  name:   'CrowdStrike Intelligence',
  search: 'https://www.crowdstrike.com/en-us/blog/',
  rss:    'https://www.crowdstrike.com/en-us/blog/feed/',
};

export const crowdstrikeTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const crowdstrikeToolCount = crowdstrikeTools.length;
