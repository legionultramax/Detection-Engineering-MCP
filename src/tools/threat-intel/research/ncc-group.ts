import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'ncc_group',
  name:   'NCC Group',
  search: 'https://research.nccgroup.com/',
  rss:    'https://research.nccgroup.com/feed/',
};

export const nccGroupTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const nccGroupToolCount = nccGroupTools.length;
