import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'intezer',
  name:   'Intezer Research',
  search: 'https://intezer.com/blog/',
  rss:    'https://intezer.com/blog/feed/',
};

export const intezerTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const intezerToolCount = intezerTools.length;
