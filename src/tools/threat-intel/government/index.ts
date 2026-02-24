/**
 * Government & CERT threat intelligence tools — Phase 3.
 *
 * Tools:
 *   cisa_search_advisories   — CISA cybersecurity advisories + alerts RSS
 *   ncsc_uk_search           — NCSC UK all-advisories RSS
 *   nsa_search_advisories    — NSA cybersecurity advisories
 *   fbi_flash_search         — FBI / IC3 public alerts RSS
 *   cert_eu_search           — CERT-EU threat intelligence publications
 *   anssi_search             — ANSSI / CERT-FR security alerts
 *   jpcert_search            — JPCERT/CC English advisories
 *   acsc_search              — ACSC (ASD) alerts
 *   cccs_search              — Canadian CCCS alerts & advisories
 *   govt_joint_advisory_search — Fan-out across Five Eyes (highest confidence)
 *
 * All tools:
 *   - Return GovtIntelResult<GovtSearchResult>
 *   - Cache with GOVT_FEED_TTL (1 hour)
 *   - Never throw — return structured errors
 *   - Emit pivot_suggestions for downstream correlation
 */

import { defineTool, type ToolDefinition } from '../../registry.js';
import { getCached, setCached } from '../cache.js';
import {
  parseRSS,
  extractIntelMarkers,
  fetchWithRetry,
  GOVT_FEED_TTL,
  stripHtml,
} from '../vendors/utils.js';
import type { VendorReport, PivotSuggestion } from '../vendors/types.js';
import type { GovtConfig, GovtIntelResult, GovtSearchResult } from './types.js';

// ─── GOVERNMENT SOURCE REGISTRY ──────────────────────────────────────────────

const GOVT_SOURCES: GovtConfig[] = [
  {
    key:      'cisa',
    name:     'CISA',
    rss:      'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    toolName: 'cisa_search_advisories',
    blurb:    'CISA cybersecurity advisories and ICS-CERT alerts',
  },
  {
    key:      'ncsc_uk',
    name:     'NCSC UK',
    rss:      'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
    toolName: 'ncsc_uk_search',
    blurb:    'UK National Cyber Security Centre advisories and guidance',
  },
  {
    key:      'nsa',
    name:     'NSA Cybersecurity',
    rss:      'https://www.nsa.gov/portals/75/documents/resources/everyone/cybersecurity/nsa-cybersecurity-advisories.xml',
    toolName: 'nsa_search_advisories',
    blurb:    'NSA cybersecurity advisories and technical guidance',
  },
  {
    key:      'fbi',
    name:     'FBI / IC3',
    rss:      'https://www.ic3.gov/RSS',
    toolName: 'fbi_flash_search',
    blurb:    'FBI flash alerts and IC3 public service announcements',
  },
  {
    key:      'cert_eu',
    name:     'CERT-EU',
    rss:      'https://www.cert.europa.eu/publications/threat-intelligence/feed',
    toolName: 'cert_eu_search',
    blurb:    'CERT-EU threat intelligence publications for EU institutions',
  },
  {
    key:      'anssi',
    name:     'ANSSI / CERT-FR',
    rss:      'https://www.cert.ssi.gouv.fr/feed/',
    toolName: 'anssi_search',
    blurb:    'French ANSSI (CERT-FR) security alerts and vulnerability advisories',
  },
  {
    key:      'jpcert',
    name:     'JPCERT/CC',
    rss:      'https://www.jpcert.or.jp/english/rss/jpcert-en.rdf',
    toolName: 'jpcert_search',
    blurb:    'JPCERT/CC English-language security alerts and coordination notices',
  },
  {
    key:      'acsc',
    name:     'ACSC (ASD)',
    rss:      'https://www.cyber.gov.au/sites/default/files/rss.xml',
    toolName: 'acsc_search',
    blurb:    'Australian Cyber Security Centre alerts and advisories',
  },
  {
    key:      'cccs',
    name:     'CCCS / CCIRC',
    rss:      'https://www.cyber.gc.ca/en/rss/alerts-advisories',
    toolName: 'cccs_search',
    blurb:    'Canadian Centre for Cyber Security alerts and advisories',
  },
];

/** Five Eyes sources used by the joint advisory search */
const FIVE_EYES_KEYS = ['cisa', 'ncsc_uk', 'acsc', 'cccs'];
const FIVE_EYES_SRCS = GOVT_SOURCES.filter(s => FIVE_EYES_KEYS.includes(s.key));

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function makeGovtErr(source: string, error: string): GovtIntelResult<never> {
  return {
    source,
    success: false,
    data: null,
    error,
    queried_at: new Date().toISOString(),
    pivot_suggestions: [],
  };
}

function buildGovtPivots(reports: VendorReport[], toolName: string): PivotSuggestion[] {
  const suggestions: PivotSuggestion[] = [];
  const seen = new Set<string>();

  for (const r of reports) {
    for (const t of r.techniques_mentioned.slice(0, 3)) {
      if (!seen.has(t)) {
        seen.add(t);
        suggestions.push({
          type: 'technique',
          value: t,
          reason: `Technique referenced in government advisory: "${r.title}"`,
          source_tool: toolName,
          confidence: 'high',   // government advisories carry high confidence
        });
      }
    }
    for (const cve of r.cves_mentioned.slice(0, 3)) {
      if (!seen.has(cve)) {
        seen.add(cve);
        suggestions.push({
          type: 'cve',
          value: cve,
          reason: `CVE in government advisory: "${r.title}"`,
          source_tool: toolName,
          confidence: 'high',
        });
      }
    }
    for (const actor of r.actors_mentioned.slice(0, 2)) {
      if (!seen.has(actor)) {
        seen.add(actor);
        suggestions.push({
          type: 'actor',
          value: actor,
          reason: `Actor attributed in government advisory: "${r.title}"`,
          source_tool: toolName,
          confidence: 'high',
        });
      }
    }
  }

  return suggestions.slice(0, 15);
}

/** Normalise a title for deduplication (lowercase, strip punctuation) */
function normTitle(t: string): string {
  return t.toLowerCase().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, ' ').trim();
}

// ─── FACTORY: createGovtSearchTool ───────────────────────────────────────────

function createGovtSearchTool(cfg: GovtConfig): ToolDefinition {
  return defineTool({
    name: cfg.toolName,
    description:
      `Search ${cfg.name} RSS feed for security advisories matching a keyword, ` +
      `CVE, actor name, or malware family. ${cfg.blurb}. ` +
      `Extracts MITRE techniques, CVEs, and attributed actors. Cached 1 hour.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: {
          type: 'string',
          description: 'Search keyword: actor name, CVE ID, malware family, or advisory topic',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default: 10)',
        },
      },
      required: ['query'],
    },
    handler: async (args) => {
      const { query, limit = 10 } = args as { query: string; limit?: number };
      const cap      = Math.min(Math.max(1, Math.floor(limit)), 30);
      const cacheKey = `govt:${cfg.key}:${cap}:${query.toLowerCase().trim()}`;

      const cached = getCached<GovtIntelResult<GovtSearchResult>>(cacheKey);
      if (cached !== null) return { ...cached, queried_at: new Date().toISOString() };

      try {
        const xml     = await fetchWithRetry(cfg.rss);
        const items   = parseRSS(xml);
        const qLow    = query.toLowerCase();

        const filtered = items.filter(item =>
          `${item.title} ${item.description} ${item.content}`.toLowerCase().includes(qLow),
        ).slice(0, cap);

        const reports: VendorReport[] = filtered.map(item => {
          const text = `${item.title} ${item.description} ${item.content}`;
          const m    = extractIntelMarkers(text);
          return {
            title:               item.title,
            url:                 item.link,
            published:           item.pubDate,
            snippet:             item.description.substring(0, 300),
            tags:                item.categories,
            actors_mentioned:    m.actors,
            techniques_mentioned:m.techniques,
            cves_mentioned:      m.cves,
            malware_mentioned:   m.malware,
          };
        });

        const result: GovtIntelResult<GovtSearchResult> = {
          source:   cfg.key,
          success:  true,
          data: {
            reports,
            total_found:     reports.length,
            source:          cfg.name,
            query,
            issuing_agencies:[cfg.name],
            advisory_type:   'all',
            is_joint:        false,
          },
          queried_at:       new Date().toISOString(),
          pivot_suggestions:buildGovtPivots(reports, cfg.toolName),
        };

        setCached(cacheKey, result, GOVT_FEED_TTL);
        return result;
      } catch (err) {
        return makeGovtErr(cfg.key, err instanceof Error ? err.message : String(err));
      }
    },
  });
}

// ─── CISA SPECIAL TOOL (type filter + advisory_type output field) ─────────────

const CISA_ALERTS_RSS  = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';
const CISA_ICS_RSS     = 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml';
const CISA_ALERTS_ONLY = 'https://www.cisa.gov/cybersecurity-advisories/alerts.xml';

const cisaSearchAdvisories = defineTool({
  name: 'cisa_search_advisories',
  description:
    'Search CISA cybersecurity advisories and alerts for a keyword, CVE, actor, or malware family. ' +
    'Supports filtering by type (advisory / alert / all). Advisories from CISA carry the highest ' +
    'confidence for active exploitation. Cached 1 hour.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      query: {
        type: 'string',
        description: 'Search keyword: CVE ID, actor name, malware family, or advisory topic',
      },
      type: {
        type: 'string',
        enum: ['advisory', 'alert', 'all'],
        description: 'Advisory type filter (default: all)',
      },
      limit: {
        type: 'number',
        description: 'Max results (default: 10)',
      },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const {
      query,
      type: advisoryType = 'all',
      limit = 10,
    } = args as { query: string; type?: 'advisory' | 'alert' | 'all'; limit?: number };

    const cap      = Math.min(Math.max(1, Math.floor(limit)), 30);
    const cacheKey = `govt:cisa:${advisoryType}:${cap}:${query.toLowerCase().trim()}`;

    const cached = getCached<GovtIntelResult<GovtSearchResult>>(cacheKey);
    if (cached !== null) return { ...cached, queried_at: new Date().toISOString() };

    // Choose RSS based on type filter
    const rssUrl =
      advisoryType === 'alert'    ? CISA_ALERTS_ONLY :
      advisoryType === 'advisory' ? CISA_ICS_RSS     :
                                    CISA_ALERTS_RSS;

    try {
      const xml     = await fetchWithRetry(rssUrl);
      const items   = parseRSS(xml);
      const qLow    = query.toLowerCase();

      const filtered = items.filter(item =>
        `${item.title} ${item.description} ${item.content}`.toLowerCase().includes(qLow),
      ).slice(0, cap);

      const reports: VendorReport[] = filtered.map(item => {
        const text = `${item.title} ${item.description} ${item.content}`;
        const m    = extractIntelMarkers(text);
        return {
          title:               item.title,
          url:                 item.link,
          published:           item.pubDate,
          snippet:             item.description.substring(0, 300),
          tags:                item.categories,
          actors_mentioned:    m.actors,
          techniques_mentioned:m.techniques,
          cves_mentioned:      m.cves,
          malware_mentioned:   m.malware,
        };
      });

      const result: GovtIntelResult<GovtSearchResult> = {
        source:  'cisa',
        success: true,
        data: {
          reports,
          total_found:     reports.length,
          source:          'CISA',
          query,
          advisory_type:   advisoryType,
          issuing_agencies:['CISA'],
          is_joint:        false,
        },
        queried_at:       new Date().toISOString(),
        pivot_suggestions:buildGovtPivots(reports, 'cisa_search_advisories'),
      };

      setCached(cacheKey, result, GOVT_FEED_TTL);
      return result;
    } catch (err) {
      return makeGovtErr('cisa', err instanceof Error ? err.message : String(err));
    }
  },
});

// ─── JOINT ADVISORY SEARCH ───────────────────────────────────────────────────

const govtJointAdvisorySearch = defineTool({
  name: 'govt_joint_advisory_search',
  description:
    'ELITE: Search for joint advisories across Five Eyes agencies (CISA + NCSC-UK + ACSC + CCCS) ' +
    'simultaneously. Joint advisories carry the highest confidence of any TTP source — they reflect ' +
    'real-world intelligence shared by multiple national agencies. Results are deduplicated by title.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      query: {
        type: 'string',
        description: 'Search keyword: actor name, CVE ID, malware family, or advisory topic',
      },
      year: {
        type: 'number',
        description: 'Optional: filter to a specific year (e.g., 2024, 2025)',
      },
      limit: {
        type: 'number',
        description: 'Max results per source (default: 5)',
      },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query, year, limit = 5 } = args as {
      query: string;
      year?: number;
      limit?: number;
    };

    const cap      = Math.min(Math.max(1, Math.floor(limit)), 15);
    const cacheKey = `govt:joint:${year ?? 'all'}:${cap}:${query.toLowerCase().trim()}`;

    const cached = getCached<GovtIntelResult<GovtSearchResult>>(cacheKey);
    if (cached !== null) return { ...cached, queried_at: new Date().toISOString() };

    // Fan out to all Five Eyes sources in parallel
    const settled = await Promise.allSettled(
      FIVE_EYES_SRCS.map(async src => {
        const xml   = await fetchWithRetry(src.rss);
        const items = parseRSS(xml);
        const qLow  = query.toLowerCase();

        return items
          .filter(item => {
            const text = `${item.title} ${item.description}`.toLowerCase();
            const matchesQuery = text.includes(qLow);
            const matchesYear  = year
              ? item.pubDate.startsWith(String(year))
              : true;
            return matchesQuery && matchesYear;
          })
          .slice(0, cap)
          .map(item => ({ ...item, _source: src.name }));
      }),
    );

    // Collect successful results
    const allItems: Array<ReturnType<typeof parseRSS>[number] & { _source: string }> = [];
    const agenciesHit: string[] = [];

    for (let i = 0; i < settled.length; i++) {
      const s = settled[i];
      if (s.status === 'fulfilled' && s.value.length > 0) {
        allItems.push(...s.value);
        agenciesHit.push(FIVE_EYES_SRCS[i].name);
      }
    }

    // Deduplicate by normalised title
    const seen = new Set<string>();
    const deduped = allItems.filter(item => {
      const norm = normTitle(item.title);
      if (seen.has(norm)) return false;
      seen.add(norm);
      return true;
    });

    // Sort by date descending
    deduped.sort((a, b) =>
      new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime(),
    );

    const reports: VendorReport[] = deduped.map(item => {
      const text = `${item.title} ${item.description} ${item.content}`;
      const m    = extractIntelMarkers(text);
      return {
        title:               `[${item._source}] ${item.title}`,
        url:                 item.link,
        published:           item.pubDate,
        snippet:             item.description.substring(0, 300),
        tags:                [...item.categories, item._source],
        actors_mentioned:    m.actors,
        techniques_mentioned:m.techniques,
        cves_mentioned:      m.cves,
        malware_mentioned:   m.malware,
      };
    });

    const result: GovtIntelResult<GovtSearchResult> = {
      source:  'govt_joint',
      success: true,
      data: {
        reports,
        total_found:     reports.length,
        source:          'Five Eyes Joint Advisory Search',
        query,
        issuing_agencies:agenciesHit,
        advisory_type:   'all',
        is_joint:        true,
      },
      queried_at:       new Date().toISOString(),
      pivot_suggestions:buildGovtPivots(reports, 'govt_joint_advisory_search'),
    };

    setCached(cacheKey, result, GOVT_FEED_TTL);
    return result;
  },
});

// ─── REGISTER ALL TOOLS ──────────────────────────────────────────────────────

// Individual source tools (excluding CISA which has its own bespoke definition)
const govtSourceTools: ToolDefinition[] = GOVT_SOURCES
  .filter(s => s.key !== 'cisa')       // cisa gets its own enhanced tool above
  .map(createGovtSearchTool);

export const governmentTools: ToolDefinition[] = [
  cisaSearchAdvisories,
  ...govtSourceTools,
  govtJointAdvisorySearch,
];

export const governmentToolCount = governmentTools.length;
