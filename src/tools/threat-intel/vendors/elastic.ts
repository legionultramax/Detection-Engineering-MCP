import { createVendorSearchTool, createVendorFetchTool } from './utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from './types.js';

const config: VendorConfig = {
  key:    'elastic',
  name:   'Elastic Security Labs',
  search: 'https://www.elastic.co/security-labs',
  rss:    'https://www.elastic.co/security-labs/rss/feed.xml',
};

export const elasticTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const elasticToolCount = elasticTools.length;
