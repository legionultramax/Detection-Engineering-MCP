/**
 * Specialized research threat intelligence tools — Phase 4.
 *
 * Each source exposes two tools using the vendor factory pattern:
 *   {source}_search_reports  — keyword search against RSS feed
 *   {source}_fetch_report    — fetch + extract TTP intelligence from a URL
 *
 * Sources (10):
 *   dfir_report   — The DFIR Report    (incident response case studies)
 *   red_canary    — Red Canary          (detection engineering + TTPs)
 *   volexity      — Volexity            (espionage / nation-state)
 *   huntress      — Huntress Labs       (SMB threats, ransomware)
 *   dragos        — Dragos              (OT/ICS — critical infrastructure)
 *   ncc_group     — NCC Group           (offensive security research)
 *   withsecure    — WithSecure Labs     (Nordic + enterprise threats)
 *   intezer       — Intezer Research    (malware genome / code reuse)
 *   sekoia        — Sekoia.io           (European threat landscape)
 *   blackberry    — BlackBerry Research (advanced persistent threats)
 *
 * Total from this module: 20 tools (2 × 10 sources).
 */

import type { ToolDefinition } from '../../registry.js';
import { dfirReportTools,  dfirReportToolCount  } from './dfir-report.js';
import { redCanaryTools,   redCanaryToolCount   } from './red-canary.js';
import { volexityTools,    volexityToolCount    } from './volexity.js';
import { huntressTools,    huntressToolCount    } from './huntress.js';
import { dragosTools,      dragosToolCount      } from './dragos.js';
import { nccGroupTools,    nccGroupToolCount    } from './ncc-group.js';
import { withsecureTools,  withsecureToolCount  } from './withsecure.js';
import { intezerTools,     intezerToolCount     } from './intezer.js';
import { sekoiaTools,      sekoiaToolCount      } from './sekoia.js';
import { blackberryTools,  blackberryToolCount  } from './blackberry.js';

export const researchTools: ToolDefinition[] = [
  ...dfirReportTools,
  ...redCanaryTools,
  ...volexityTools,
  ...huntressTools,
  ...dragosTools,
  ...nccGroupTools,
  ...withsecureTools,
  ...intezerTools,
  ...sekoiaTools,
  ...blackberryTools,
];

export const researchToolCount =
  dfirReportToolCount  +
  redCanaryToolCount   +
  volexityToolCount    +
  huntressToolCount    +
  dragosToolCount      +
  nccGroupToolCount    +
  withsecureToolCount  +
  intezerToolCount     +
  sekoiaToolCount      +
  blackberryToolCount;
