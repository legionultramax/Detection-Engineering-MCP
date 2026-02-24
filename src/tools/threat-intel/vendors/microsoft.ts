import { createVendorSearchTool, createVendorFetchTool } from './utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from './types.js';

const config: VendorConfig = {
  key:    'microsoft',
  name:   'Microsoft Threat Intelligence',
  search: 'https://www.microsoft.com/en-us/security/blog/',
  rss:    'https://www.microsoft.com/en-us/security/blog/feed/',
};

export const microsoftTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const microsoftToolCount = microsoftTools.length;
