import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'blackberry',
  name:   'BlackBerry Research',
  search: 'https://blogs.blackberry.com/en/category/research-and-intelligence',
  rss:    'https://blogs.blackberry.com/en/feed',
};

export const blackberryTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const blackberryToolCount = blackberryTools.length;
