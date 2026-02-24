/**
 * Shared type definitions for the threat intelligence integration layer.
 * Used by abusech.ts, otx.ts, and pivot.ts.
 */

// ---------------------------------------------------------------------------
// Core envelope — every API call returns this shape
// ---------------------------------------------------------------------------

export interface PivotSuggestion {
  /** IOC type to pivot into next */
  type: 'ip' | 'domain' | 'hash' | 'url' | 'family' | 'actor' | 'tag' | 'imphash' | 'technique' | 'cve';
  /** The actual value to query */
  value: string;
  /** Human-readable reason: "Imphash sibling family" / "C2 server from sandbox" */
  reason: string;
  /** Which tool/function generated this suggestion */
  source_tool: string;
  /**
   * Confidence of the UNDERLYING IOC that generated this suggestion.
   * Used by the Level-1 auto-follow gate in pivot.ts:
   *   high   → auto-follow unconditionally
   *   medium → auto-follow (default gate)
   *   low    → SKIP in Level-1 (requires manual follow-up)
   * Defaults to 'medium' when omitted.
   */
  confidence?: Confidence;
}

export interface IntelResult<T> {
  source: 'urlhaus' | 'threatfox' | 'malwarebazaar' | 'otx';
  success: boolean;
  data: T | null;
  error?: string;
  /** ISO-8601 timestamp of when the query was made */
  queried_at: string;
  /** Auto-populated next-hop suggestions for chained pivoting */
  pivot_suggestions?: PivotSuggestion[];
}

// ---------------------------------------------------------------------------
// Normalised IOC — the unified representation after deduplication
// ---------------------------------------------------------------------------

export type Confidence = 'high' | 'medium' | 'low';

export interface NormalizedIOC {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'imphash' | 'family';
  value: string;
  confidence: Confidence;
  /** All source systems that reported this IOC */
  sources: string[];
  first_seen?: string;
  last_seen?: string;
  tags: string[];
  malware_family?: string;
  threat_type?: string;
  /** MITRE ATT&CK technique IDs if mapped */
  mitre_techniques?: string[];
}

// ---------------------------------------------------------------------------
// URLhaus types  (https://urlhaus-api.abuse.ch/v1/)
// ---------------------------------------------------------------------------

export interface UrlhausBlacklists {
  gsb: 'listed' | 'not listed';
  surbl: 'listed' | 'not listed';
}

export interface UrlhausPayload {
  firstseen: string;
  filename: string | null;
  file_type: string | null;
  response_size: number | null;
  response_md5: string;
  response_sha256: string;
  urlhaus_download: string;
  signature: string | null;
  imphash: string | null;
  ssdeep: string | null;
  tlsh: string | null;
}

export interface UrlhausURLEntry {
  id: string;
  urlhaus_reference: string;
  url: string;
  url_status: 'online' | 'offline' | 'unknown';
  date_added: string;
  threat: string | null;
  reporter: string;
  larted: boolean;
  tags: string[] | null;
}

export interface UrlhausURLResult {
  query_status: string;
  id?: string;
  urlhaus_reference?: string;
  url_status?: string;
  date_added?: string;
  threat?: string | null;
  blacklists?: UrlhausBlacklists;
  reporter?: string;
  larted?: boolean;
  tags?: string[] | null;
  payloads?: UrlhausPayload[] | null;
  urls_from_same_host?: string;
}

export interface UrlhausHostResult {
  query_status: string;
  urlhaus_reference?: string;
  urls_from_this_host?: string;
  blacklists?: UrlhausBlacklists;
  urls?: UrlhausURLEntry[];
}

export interface UrlhausTagResult {
  query_status: string;
  urls?: UrlhausURLEntry[];
}

// ---------------------------------------------------------------------------
// ThreatFox types  (https://threatfox-api.abuse.ch/api/v1/)
// ---------------------------------------------------------------------------

export interface ThreatFoxIOC {
  id: string;
  ioc: string;
  ioc_type: 'ip:port' | 'domain' | 'url' | 'md5_hash' | 'sha256_hash';
  ioc_type_desc: string;
  threat_type: string;
  threat_type_desc: string;
  malware: string;
  malware_printable: string;
  malware_alias: string | null;
  malware_malpedia: string | null;
  /** 0–100; used for confidence scoring */
  confidence_level: number;
  first_seen: string;
  last_seen: string | null;
  reporter: string;
  reference: string | null;
  tags: string[] | null;
}

export interface ThreatFoxApiResponse {
  query_status: string;
  data?: ThreatFoxIOC[];
}

// ---------------------------------------------------------------------------
// MalwareBazaar types  (https://mb-api.abuse.ch/api/v1/)
// ---------------------------------------------------------------------------

export interface MalwareBazaarVendorDetection {
  detection: string;
  link: string;
}

export interface MalwareBazaarIntelligence {
  downloads: string;
  uploads: string;
  mail: string | null;
  clamav: string[] | null;
}

export interface MalwareBazaarSample {
  sha256_hash: string;
  md5_hash: string;
  sha1_hash: string;
  first_seen: string;
  last_seen: string;
  file_name: string;
  file_size: number;
  file_type: string;
  file_type_mime: string;
  imphash: string | null;
  tlsh: string | null;
  telfhash: string | null;
  ssdeep: string | null;
  signature: string | null;
  tags: string[] | null;
  reporter: string | null;
  anonymous: number;
  intelligence: MalwareBazaarIntelligence | null;
  vendor_intel: Record<string, MalwareBazaarVendorDetection> | null;
  delivery_method: string | null;
  dex_import: string | null;
  comment: string | null;
}

export interface MalwareBazaarApiResponse {
  query_status: string;
  data?: MalwareBazaarSample[];
}

// ---------------------------------------------------------------------------
// OTX (AlienVault) types  (https://otx.alienvault.com/api/v1/)
// ---------------------------------------------------------------------------

export interface OTXAttackId {
  id: string;
  name: string;
  display_name: string;
}

export interface OTXMalwareFamily {
  id: string;
}

export interface OTXPulse {
  id: string;
  name: string;
  description: string;
  author_name: string;
  modified: string;
  created: string;
  references: string[];
  tags: string[];
  targeted_countries: string[];
  adversary: string;
  malware_families: OTXMalwareFamily[];
  attack_ids: OTXAttackId[];
  TLP: string;
  industries: string[];
}

export interface OTXPulseWithIndicators extends OTXPulse {
  indicators: OTXIndicator[];
}

export interface OTXPulseInfo {
  count: number;
  pulses: OTXPulse[];
  references: string[];
  related: {
    alienvault: { adversary: string[]; malware_families: string[]; industries: string[] };
    other: { adversary: string[]; malware_families: string[]; industries: string[] };
  };
}

export interface OTXIndicator {
  id: string;
  type: string;
  indicator: string;
  description: string | null;
  title: string | null;
  created: string;
  is_active: number;
  content: string | null;
}

export interface OTXPassiveDNSRecord {
  address: string;
  first: string;
  last: string;
  hostname: string;
  record_type: string;
  indicator_link: string;
  flag_title: string;
  flag_url: string;
  asn: string;
  country: string;
}

export interface OTXIPGeneral {
  indicator: string;
  type: string;
  pulse_info: OTXPulseInfo;
  country_code: string | null;
  country_name: string | null;
  asn: string | null;
  reputation: number;
  whois: string | null;
}

export interface OTXDomainGeneral {
  indicator: string;
  type: string;
  pulse_info: OTXPulseInfo;
  whois: string | null;
  validation: Array<{ source: string; message: string; name: string }>;
}

export interface OTXDomainPassiveDNS {
  passive_dns: OTXPassiveDNSRecord[];
  count: number;
}

export interface OTXFileGeneral {
  indicator: string;
  type: string;
  pulse_info: OTXPulseInfo;
}

export interface OTXFileAnalysis {
  analysis: {
    plugins: Record<string, unknown>;
    info: {
      results: {
        file_class: string;
        file_type: string;
        magic: string;
        ssdeep?: string;
        tlsh?: string;
        imphash?: string;
      };
    } | null;
  } | null;
}

export interface OTXURLGeneral {
  indicator: string;
  type: string;
  pulse_info: OTXPulseInfo;
}

export interface OTXSearchPulsesResponse {
  results: OTXPulseWithIndicators[];
  count: number;
  next: string | null;
  previous: string | null;
}

export interface OTXPulseIndicatorsResponse {
  results: OTXIndicator[];
  count: number;
  next: string | null;
  previous: string | null;
}

// ---------------------------------------------------------------------------
// Enriched output shapes (what our functions return inside IntelResult.data)
// ---------------------------------------------------------------------------

export interface EnrichedIPResult {
  ip: string;
  pulse_count: number;
  reputation: number;
  country: string | null;
  asn: string | null;
  adversaries: string[];
  malware_families: string[];
  mitre_techniques: string[];
  tags: string[];
  top_pulses: Array<{ id: string; name: string; author: string; modified: string }>;
}

export interface EnrichedDomainResult {
  domain: string;
  pulse_count: number;
  adversaries: string[];
  malware_families: string[];
  mitre_techniques: string[];
  passive_dns_ips: string[];
  tags: string[];
  top_pulses: Array<{ id: string; name: string; author: string; modified: string }>;
}

export interface EnrichedHashResult {
  hash: string;
  pulse_count: number;
  malware_families: string[];
  mitre_techniques: string[];
  adversaries: string[];
  tags: string[];
  imphash?: string;
  file_type?: string;
  top_pulses: Array<{ id: string; name: string; author: string; modified: string }>;
}

export interface EnrichedURLResult {
  url: string;
  pulse_count: number;
  adversaries: string[];
  malware_families: string[];
  tags: string[];
  top_pulses: Array<{ id: string; name: string; author: string; modified: string }>;
}

export interface EnrichedActorResult {
  actor: string;
  pulse_count: number;
  ioc_count: number;
  iocs_by_type: Record<string, NormalizedIOC[]>;
  malware_families: string[];
  mitre_techniques: string[];
  targeted_countries: string[];
  industries: string[];
  tags: string[];
}

// ---------------------------------------------------------------------------
// Pivot result — returned by pivotExpandIOCs()
// ---------------------------------------------------------------------------

export interface KGWriteSummary {
  entities_created: number;
  relations_created: number;
  error?: string;
}

export interface PivotResult {
  input_iocs: Array<{ type: string; value: string }>;
  discovered_iocs: NormalizedIOC[];
  actors: string[];
  malware_families: string[];
  mitre_techniques: string[];
  source_results: Array<IntelResult<unknown>>;
  errors: string[];
  /** True when the auto-follow depth cap was hit */
  pivot_depth_reached: boolean;
  queried_at: string;
  /** Summary of what was written to the knowledge graph after the pivot */
  kg_write?: KGWriteSummary;
}
