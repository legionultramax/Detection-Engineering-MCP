/**
 * Shared type definitions for the vendor threat intelligence layer.
 *
 * Vendor tools return VendorIntelResult<T> (source: string) rather than the
 * narrow IntelResult<T> (source: union) used by abuse.ch / OTX.  The pivot
 * suggestion type is shared and imported from the parent module.
 */

import type { PivotSuggestion } from '../types.js';

// Re-export for convenience so vendor files only need one import
export type { PivotSuggestion };

// ---------------------------------------------------------------------------
// Vendor configuration
// ---------------------------------------------------------------------------

export interface VendorConfig {
  /** Snake-case key used for tool names, cache keys, and source field */
  key: string;
  /** Human-readable display name */
  name: string;
  /** Public blog / research landing page */
  search: string;
  /** RSS or Atom feed URL */
  rss: string;
}

// ---------------------------------------------------------------------------
// Response envelope — mirrors IntelResult<T> but with source: string
// ---------------------------------------------------------------------------

export interface VendorIntelResult<T> {
  source: string;
  success: boolean;
  data: T | null;
  error?: string;
  /** ISO-8601 timestamp */
  queried_at: string;
  pivot_suggestions?: PivotSuggestion[];
}

// ---------------------------------------------------------------------------
// RSS / Atom feed item
// ---------------------------------------------------------------------------

export interface RSSItem {
  title: string;
  link: string;
  /** ISO-8601 */
  pubDate: string;
  description: string;
  categories: string[];
  /** Full article content if available (content:encoded or content) */
  content: string;
}

// ---------------------------------------------------------------------------
// Intel markers — extracted from any block of text
// ---------------------------------------------------------------------------

export interface IntelMarkers {
  techniques: string[];
  cves: string[];
  actors: string[];
  malware: string[];
  tools: string[];
  iocs: Array<{ type: string; value: string }>;
  industries: string[];
  regions: string[];
}

// ---------------------------------------------------------------------------
// Vendor search result shapes
// ---------------------------------------------------------------------------

export interface VendorReport {
  title: string;
  url: string;
  published: string;
  /** First 300 chars of description */
  snippet: string;
  tags: string[];
  actors_mentioned: string[];
  techniques_mentioned: string[];
  cves_mentioned: string[];
  malware_mentioned: string[];
}

export interface VendorSearchResult {
  reports: VendorReport[];
  total_found: number;
  source: string;
  query: string;
}

// ---------------------------------------------------------------------------
// Vendor report analysis shapes
// ---------------------------------------------------------------------------

export interface ExtractedTechnique {
  id: string;
  name: string;
  /** Sentence from the report that mentions this technique */
  context: string;
}

export interface ExtractedIOC {
  type: 'ip' | 'domain' | 'hash' | 'sha256' | 'sha1' | 'md5' | 'url' | 'email';
  value: string;
}

export interface VendorReportAnalysis {
  url: string;
  title: string;
  published: string;
  vendor: string;
  extracted_intelligence: {
    actors: string[];
    malware_families: string[];
    techniques: ExtractedTechnique[];
    cves: string[];
    iocs: ExtractedIOC[];
    tools_used: string[];
    target_industries: string[];
    target_regions: string[];
    kill_chain_phases: string[];
  };
  raw_text_length: number;
  confidence: 'high' | 'medium' | 'low';
}

// ---------------------------------------------------------------------------
// Confidence scorer input
// ---------------------------------------------------------------------------

export interface ConfidenceInput {
  sources_consulted?: string[];
  mitre_confirmed: boolean;
  vendor_count?: number;
  ioc_count?: number;
  cve_confirmed: boolean;
}
