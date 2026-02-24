import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

// Dragos specialises in OT/ICS threat intelligence — high value for
// manufacturing, energy, and critical infrastructure clients.
const config: VendorConfig = {
  key:    'dragos',
  name:   'Dragos (OT/ICS)',
  search: 'https://www.dragos.com/blog/',
  rss:    'https://www.dragos.com/blog/feed/',
};

export const dragosTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const dragosToolCount = dragosTools.length;
