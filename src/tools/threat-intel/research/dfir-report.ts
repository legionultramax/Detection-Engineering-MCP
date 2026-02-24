import { createVendorSearchTool, createVendorFetchTool } from '../vendors/utils.js';
import type { ToolDefinition } from '../../registry.js';
import type { VendorConfig } from '../vendors/types.js';

const config: VendorConfig = {
  key:    'dfir_report',
  name:   'The DFIR Report',
  search: 'https://thedfirreport.com/',
  rss:    'https://thedfirreport.com/feed/',
};

export const dfirReportTools: ToolDefinition[] = [
  createVendorSearchTool(config),
  createVendorFetchTool(config),
];

export const dfirReportToolCount = dfirReportTools.length;
