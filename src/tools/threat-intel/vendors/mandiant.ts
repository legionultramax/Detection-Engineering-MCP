import { createVendorSearchTool, createVendorFetchTool } from './utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from './types.js';

const config: VendorConfig = {
  key:    'mandiant',
  name:   'Mandiant / Google Threat Intelligence',
  search: 'https://cloud.google.com/blog/topics/threat-intelligence/',
  rss:    'https://cloud.google.com/blog/topics/threat-intelligence/rss',
};

export const mandiantTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const mandiantToolCount = mandiantTools.length;
