/**
 * Types for the government / CERT threat intelligence module.
 *
 * GovtSearchResult extends VendorSearchResult with government-specific
 * metadata (advisory type, issuing agencies, joint-advisory flag).
 * GovtIntelResult<T> mirrors VendorIntelResult<T> but with source typed
 * as a government key string for clarity.
 */

import type { VendorReport, VendorSearchResult, PivotSuggestion } from '../vendors/types.js';

export type { VendorReport, PivotSuggestion };

export interface GovtSearchResult extends VendorSearchResult {
  /** Advisory type filter used for the query */
  advisory_type?: 'advisory' | 'alert' | 'all';
  /** Agencies that issued the content */
  issuing_agencies?: string[];
  /** True when multiple national agencies co-authored the advisory */
  is_joint?: boolean;
}

export interface GovtIntelResult<T> {
  source: string;
  success: boolean;
  data: T | null;
  error?: string;
  queried_at: string;
  pivot_suggestions?: PivotSuggestion[];
}

/** Configuration for a government / CERT RSS source */
export interface GovtConfig {
  /** Snake-case key — used in tool name, cache key, source field */
  key: string;
  /** Human-readable agency name */
  name: string;
  /** RSS / Atom feed URL */
  rss: string;
  /** Explicit MCP tool name (govts don't follow {key}_search_reports convention) */
  toolName: string;
  /** Short operational description suffix */
  blurb: string;
}
