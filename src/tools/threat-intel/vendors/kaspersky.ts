import { createVendorSearchTool, createVendorFetchTool } from './utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from './types.js';

const config: VendorConfig = {
  key:    'kaspersky',
  name:   'Kaspersky Securelist',
  search: 'https://securelist.com/',
  rss:    'https://securelist.com/feed/',
};

export const kasperskyTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const kasperskyToolCount = kasperskyTools.length;
