import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'withsecure',
  name:   'WithSecure Labs',
  search: 'https://labs.withsecure.com/',
  rss:    'https://labs.withsecure.com/feed/',
};

export const withsecureTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const withsecureToolCount = withsecureTools.length;
