import { createVendorSearchTool, createVendorFetchTool } from './utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from './types.js';

const config: VendorConfig = {
  key:    'unit42',
  name:   'Palo Alto Unit 42',
  search: 'https://unit42.paloaltonetworks.com/',
  rss:    'https://unit42.paloaltonetworks.com/feed/',
};

export const unit42Tools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const unit42ToolCount = unit42Tools.length;
