/**
 * Vendor threat intelligence tools aggregator — Phase 2.
 *
 * Deprecated: Individual vendor RSS tools have been removed.
 * Vendor intelligence is now gathered via Playwright + DuckDuckGo (Tier 2).
 * The shared utilities (utils.ts) are retained for correlation engine use.
 */

import type { ToolDefinition } from '../../registry.js';

export const vendorTools: ToolDefinition[] = [];
export const vendorToolCount = 0;
