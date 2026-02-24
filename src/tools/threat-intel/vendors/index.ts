/**
 * Vendor threat intelligence tools aggregator — Phase 2.
 *
 * Registers 2 tools per vendor (search + fetch) for the top 6 high-value
 * vendors: Mandiant, Microsoft, CrowdStrike, Elastic, Unit 42, Kaspersky.
 *
 * Total from this module: 12 tools.
 *
 * Remaining 12 vendors (Talos, ESET, Trend Micro, SentinelOne, Symantec, Sophos,
 * Secureworks, Check Point, Proofpoint, Trellix, Fortinet, Cybereason) will be
 * added in subsequent phases using the same createVendorSearchTool /
 * createVendorFetchTool factory pattern from utils.ts.
 */

import type { ToolDefinition } from '../../registry.js';
import { mandiantTools,   mandiantToolCount   } from './mandiant.js';
import { microsoftTools,  microsoftToolCount  } from './microsoft.js';
import { crowdstrikeTools,crowdstrikeToolCount} from './crowdstrike.js';
import { elasticTools,    elasticToolCount    } from './elastic.js';
import { unit42Tools,     unit42ToolCount     } from './unit42.js';
import { kasperskyTools,  kasperskyToolCount  } from './kaspersky.js';

export const vendorTools: ToolDefinition[] = [
  ...mandiantTools,
  ...microsoftTools,
  ...crowdstrikeTools,
  ...elasticTools,
  ...unit42Tools,
  ...kasperskyTools,
];

export const vendorToolCount =
  mandiantToolCount   +
  microsoftToolCount  +
  crowdstrikeToolCount+
  elasticToolCount    +
  unit42ToolCount     +
  kasperskyToolCount;
