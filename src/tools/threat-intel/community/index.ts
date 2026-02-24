/**
 * Community & Open Research Tools — Phase 7.
 *
 * Sources (9 tools):
 *   malpedia_search         — Malpedia search (actors + families)
 *   malpedia_actor_profile  — Full Malpedia actor profile
 *   malpedia_family_profile — Full Malpedia malware family profile
 *   sans_isc_search         — SANS Internet Storm Center diary search
 *   anyrun_trending         — ANY.RUN malware trends (current top threats)
 *   bleeping_search         — BleepingComputer threat news search
 *   malwarebytes_search     — Malwarebytes Labs blog search
 *   vx_underground_search   — VX-Underground samples/news search
 *   misp_warninglist_check  — Check IOC against MISP warning lists (FP filter)
 *
 * Requires MALPEDIA_API_KEY env var for malpedia_* tools (they degrade gracefully without it).
 */

import { defineTool, type ToolDefinition } from '../../registry.js';
import {
  fetchWithRetry,
  parseRSS,
  extractIntelMarkers,
  extractArticleBody,
  VENDOR_BLOG_TTL,
  LIVE_FEED_TTL,
} from '../vendors/utils.js';
import { getCached, setCached } from '../cache.js';

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

const MALPEDIA_BASE    = 'https://malpedia.caad.fkie.fraunhofer.de/api';
const MALPEDIA_API_KEY = process.env['MALPEDIA_API_KEY'] ?? '';

const SANS_ISC_RSS     = 'https://isc.sans.edu/rssfeed.xml';
const ANYRUN_TRENDS    = 'https://any.run/malware-trends/';
const BLEEPING_RSS     = 'https://www.bleepingcomputer.com/feed/';
const MALWAREBYTES_RSS = 'https://www.malwarebytes.com/blog/feed/';
// VX-Underground does not expose a standard RSS; we fetch their papers index
const VX_PAPERS_URL   = 'https://vx-underground.org/Papers';

/** MISP warning list index — well-known FP domains/IPs */
const MISP_WARNINGLIST_URLS: Record<string, string> = {
  alexa:     'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/alexa/list.json',
  microsoft: 'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/microsoft/list.json',
  google:    'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/google/list.json',
  majestic:  'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/majestic_million/list.json',
  tranco:    'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/tranco/list.json',
  mozilla:   'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/mozilla/list.json',
};

// ─── MALPEDIA HELPERS ─────────────────────────────────────────────────────────

function malpediaHeaders(): Record<string, string> {
  const h: Record<string, string> = { 'Accept': 'application/json' };
  if (MALPEDIA_API_KEY) h['Authorization'] = `apitoken ${MALPEDIA_API_KEY}`;
  return h;
}

async function malpediaGet<T>(path: string, cacheKey: string, ttl: number): Promise<{ data: T | null; error?: string }> {
  const cached = getCached<T>(cacheKey);
  if (cached) return { data: cached };
  try {
    const res  = await fetch(`${MALPEDIA_BASE}${path}`, {
      headers: malpediaHeaders(),
      signal:  AbortSignal.timeout(12_000),
    });
    const raw  = await res.text();
    const data = JSON.parse(raw) as T;
    setCached(cacheKey, data, ttl);
    return { data };
  } catch (err) {
    return { data: null, error: (err as Error).message };
  }
}

// ─── TOOL 1: malpedia_search ─────────────────────────────────────────────────

const malpediaSearch = defineTool({
  name:        'malpedia_search',
  description: 'Search Malpedia for threat actors and malware families. ' +
               'Malpedia is the authoritative reference for malware taxonomy and actor-to-family attribution. ' +
               'Requires MALPEDIA_API_KEY for full access.',
  inputSchema: {
    type:       'object',
    properties: {
      query: { type: 'string',  description: 'Search term (actor name, malware family, alias)' },
      type:  { type: 'string',  description: 'Search scope: actor, family, or all (default: all)', enum: ['actor', 'family', 'all'] },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query, type = 'all' } = args as { query: string; type?: 'actor' | 'family' | 'all' };
    const now = new Date().toISOString();

    if (!MALPEDIA_API_KEY) {
      return {
        source:     'malpedia',
        success:    false,
        queried_at: now,
        data:       null,
        error:      'MALPEDIA_API_KEY not set. Set this environment variable to enable Malpedia integration.',
        note:       'Request a free API key at https://malpedia.caad.fkie.fraunhofer.de/api/register',
      };
    }

    const results: { type: string; name: string; url: string }[] = [];

    if (type === 'actor' || type === 'all') {
      const { data: actors, error } = await malpediaGet<Record<string, unknown>[]>(
        `/find/actor/${encodeURIComponent(query)}`,
        `malpedia:actor:search:${query.toLowerCase()}`,
        VENDOR_BLOG_TTL
      );
      if (actors && Array.isArray(actors)) {
        for (const a of actors) {
          results.push({
            type: 'actor',
            name: a.value as string || String(a),
            url:  `https://malpedia.caad.fkie.fraunhofer.de/actor/${String(a.value || a).replace(' ', '_')}`,
          });
        }
      } else if (error && type === 'actor') {
        return { source: 'malpedia', success: false, queried_at: now, data: null, error };
      }
    }

    if (type === 'family' || type === 'all') {
      const { data: families, error } = await malpediaGet<Record<string, unknown>[]>(
        `/find/family/${encodeURIComponent(query)}`,
        `malpedia:family:search:${query.toLowerCase()}`,
        VENDOR_BLOG_TTL
      );
      if (families && Array.isArray(families)) {
        for (const f of families) {
          results.push({
            type: 'family',
            name: f.value as string || String(f),
            url:  `https://malpedia.caad.fkie.fraunhofer.de/details/${String(f.value || f)}`,
          });
        }
      } else if (error && type === 'family') {
        return { source: 'malpedia', success: false, queried_at: now, data: null, error };
      }
    }

    return {
      source:     'malpedia',
      success:    true,
      queried_at: now,
      data: {
        query,
        count:   results.length,
        results,
      },
      pivot_suggestions: results.slice(0, 3).map(r => ({
        type:       r.type === 'actor' ? 'actor' : 'family' as const,
        value:      r.name,
        confidence: 'high' as const,
        tool:       r.type === 'actor' ? 'malpedia_actor_profile' : 'malpedia_family_profile',
      })),
    };
  },
});

// ─── TOOL 2: malpedia_actor_profile ──────────────────────────────────────────

const malpediaActorProfile = defineTool({
  name:        'malpedia_actor_profile',
  description: 'Get a full Malpedia threat actor profile: aliases, country attribution, motivation, ' +
               'description, and all malware families attributed to this actor. ' +
               'Authoritative source for actor-to-malware mapping. Requires MALPEDIA_API_KEY.',
  inputSchema: {
    type:       'object',
    properties: {
      actor_id: { type: 'string', description: 'Malpedia actor ID (e.g., apt.apt29, crime.fin7) or actor name' },
    },
    required: ['actor_id'],
  },
  handler: async (args) => {
    const { actor_id } = args as { actor_id: string };
    const now = new Date().toISOString();

    if (!MALPEDIA_API_KEY) {
      return {
        source: 'malpedia', success: false, queried_at: now, data: null,
        error: 'MALPEDIA_API_KEY not set.',
      };
    }

    // Malpedia actor IDs use underscores; names use spaces
    const actorSlug = actor_id.toLowerCase().replace(/\s+/g, '_');
    const { data, error } = await malpediaGet<Record<string, unknown>>(
      `/get/actor/${encodeURIComponent(actorSlug)}`,
      `malpedia:actor:profile:${actorSlug}`,
      VENDOR_BLOG_TTL
    );

    if (!data || error) {
      return {
        source: 'malpedia', success: false, queried_at: now, data: null,
        error:  error || `Actor not found: ${actor_id}`,
      };
    }

    // Parse families list (Malpedia returns a dict of family_name -> {...})
    const familiesRaw = data.families as Record<string, unknown> | null;
    const familyNames = familiesRaw ? Object.keys(familiesRaw) : [];

    return {
      source:     'malpedia',
      success:    true,
      queried_at: now,
      data: {
        actor_id:      actorSlug,
        cfr_type:      data.cfr_type,
        cfr_target:    data.cfr_target_category,
        country:       data.country,
        motivation:    data.motivation,
        names:         data.names,       // aliases array
        description:   ((data.description as string) || '').substring(0, 600),
        families:      familyNames,
        families_count: familyNames.length,
        malpedia_url:  `https://malpedia.caad.fkie.fraunhofer.de/actor/${actorSlug}`,
      },
      pivot_suggestions: familyNames.slice(0, 3).map(f => ({
        type: 'family' as const, value: f, confidence: 'high' as const, tool: 'malpedia_family_profile',
      })),
    };
  },
});

// ─── TOOL 3: malpedia_family_profile ─────────────────────────────────────────

const malpediaFamilyProfile = defineTool({
  name:        'malpedia_family_profile',
  description: 'Get a full Malpedia malware family profile: alternate names, description, ' +
               'attribution to threat actors, and reference URLs. ' +
               'The authoritative source for malware taxonomy and variant tracking. Requires MALPEDIA_API_KEY.',
  inputSchema: {
    type:       'object',
    properties: {
      family_name: { type: 'string', description: 'Malpedia family name (e.g., win.cobalt_strike, win.emotet)' },
    },
    required: ['family_name'],
  },
  handler: async (args) => {
    const { family_name } = args as { family_name: string };
    const now = new Date().toISOString();

    if (!MALPEDIA_API_KEY) {
      return {
        source: 'malpedia', success: false, queried_at: now, data: null,
        error: 'MALPEDIA_API_KEY not set.',
      };
    }

    const familySlug = family_name.toLowerCase().replace(/\s+/g, '_');
    const { data, error } = await malpediaGet<Record<string, unknown>>(
      `/get/family/${encodeURIComponent(familySlug)}`,
      `malpedia:family:profile:${familySlug}`,
      VENDOR_BLOG_TTL
    );

    if (!data || error) {
      return {
        source: 'malpedia', success: false, queried_at: now, data: null,
        error:  error || `Family not found: ${family_name}`,
      };
    }

    const altNames    = (data.alt_names as string[]) || [];
    const attribution = (data.attribution as string[]) || [];
    const urlsList    = (data.urls as Array<{ url: string }>) || [];

    return {
      source:     'malpedia',
      success:    true,
      queried_at: now,
      data: {
        family:       familySlug,
        alt_names:    altNames,
        description:  ((data.description as string) || '').substring(0, 600),
        attribution,                        // actor IDs
        references:   urlsList.slice(0, 10).map(u => u.url),
        malpedia_url: `https://malpedia.caad.fkie.fraunhofer.de/details/${familySlug}`,
      },
      pivot_suggestions: attribution.slice(0, 3).map(a => ({
        type: 'actor' as const, value: a, confidence: 'high' as const, tool: 'malpedia_actor_profile',
      })),
    };
  },
});

// ─── TOOL 4: sans_isc_search ─────────────────────────────────────────────────

const sansIscSearch = defineTool({
  name:        'sans_isc_search',
  description: 'Search the SANS Internet Storm Center (ISC) daily diary feed. ' +
               'ISC handlers post real-time observations of active exploits, ' +
               'scanning campaigns, and novel attack techniques.',
  inputSchema: {
    type:       'object',
    properties: {
      query: { type: 'string', description: 'Search keyword or CVE ID' },
      limit: { type: 'number', description: 'Max results (default: 10)' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query, limit = 10 } = args as { query: string; limit?: number };
    const now = new Date().toISOString();

    const ckey = 'community:sans_isc:feed';
    let allItems = getCached<Array<{ title: string; url: string; date: string; snippet: string }>>(ckey);

    if (!allItems) {
      try {
        const xml   = await fetchWithRetry(SANS_ISC_RSS);
        const items = parseRSS(xml);
        allItems = items.map(i => ({
          title:   i.title,
          url:     i.link,
          date:    i.pubDate,
          snippet: i.description.substring(0, 400),
        }));
        setCached(ckey, allItems, LIVE_FEED_TTL); // ISC updates frequently
      } catch (err) {
        return { source: 'sans_isc', success: false, queried_at: now, data: null, error: (err as Error).message };
      }
    }

    const q = query.toLowerCase();
    const matched = allItems
      .filter(i => i.title.toLowerCase().includes(q) || i.snippet.toLowerCase().includes(q))
      .slice(0, Math.min(limit, 25));

    const results = matched.map(item => {
      const markers = extractIntelMarkers(item.title + ' ' + item.snippet);
      return { ...item, techniques: markers.techniques, cves: markers.cves, actors: markers.actors };
    });

    return {
      source:     'sans_isc',
      success:    true,
      queried_at: now,
      data:       { query, count: results.length, results },
    };
  },
});

// ─── TOOL 5: anyrun_trending ─────────────────────────────────────────────────

const anyrunTrending = defineTool({
  name:        'anyrun_trending',
  description: 'Get currently trending malware families from ANY.RUN sandbox telemetry. ' +
               'Shows what malware is most active right now based on analysis submissions. ' +
               'Useful for real-time threat landscape awareness.',
  inputSchema: {
    type:       'object',
    properties: {},
  },
  handler: async () => {
    const now = new Date().toISOString();

    const ckey = 'community:anyrun:trending';
    const cached = getCached<Record<string, unknown>>(ckey);
    if (cached) {
      return { source: 'anyrun', success: true, queried_at: now, data: { ...cached, cached: true } };
    }

    try {
      const html = await fetchWithRetry(ANYRUN_TRENDS);
      const body = extractArticleBody(html);

      // Extract malware family names from the page
      const markers = extractIntelMarkers(body);

      // Parse table rows from the HTML — look for pattern: Name, Count, % pattern
      const rowPattern = /<tr[^>]*>[\s\S]*?<\/tr>/gi;
      const cellPattern = /<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi;

      const rows: string[][] = [];
      let rowMatch: RegExpExecArray | null;
      while ((rowMatch = rowPattern.exec(html)) !== null) {
        const row = rowMatch[0];
        const cells: string[] = [];
        let cellMatch: RegExpExecArray | null;
        const cellRegex = /<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi;
        while ((cellMatch = cellRegex.exec(row)) !== null) {
          const text = cellMatch[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
          if (text) cells.push(text);
        }
        if (cells.length >= 2) rows.push(cells);
      }

      // First row is usually the header; skip it
      const dataRows = rows.slice(1, 21);

      const result = {
        as_of:            now,
        url:              ANYRUN_TRENDS,
        trending_malware: dataRows.map((cells, i) => ({
          rank:   i + 1,
          name:   cells[0] || 'Unknown',
          count:  cells[1] || '',
          share:  cells[2] || '',
        })),
        extracted_families: markers.malware,
      };

      setCached(ckey, result, LIVE_FEED_TTL);

      return { source: 'anyrun', success: true, queried_at: now, data: result };
    } catch (err) {
      return {
        source:     'anyrun',
        success:    false,
        queried_at: now,
        data:       null,
        error:      `Failed to fetch ANY.RUN trends: ${(err as Error).message}`,
      };
    }
  },
});

// ─── RSS BLOG SEARCH FACTORY (reused for bleeping, malwarebytes, vx-underground) ──

interface CommunityBlogConfig {
  key:         string;
  name:        string;
  rss:         string;
  description: string;
  ttl?:        number;
}

const COMMUNITY_BLOGS: CommunityBlogConfig[] = [
  {
    key:         'bleeping',
    name:        'BleepingComputer',
    rss:         BLEEPING_RSS,
    description: 'Search BleepingComputer for cybersecurity news, ransomware incidents, and threat actor activity.',
  },
  {
    key:         'malwarebytes',
    name:        'Malwarebytes Labs',
    rss:         MALWAREBYTES_RSS,
    description: 'Search Malwarebytes Labs threat intelligence blog for malware analysis and threat research.',
  },
];

function createCommunitySearchTool(cfg: CommunityBlogConfig): ToolDefinition {
  return defineTool({
    name:        `${cfg.key}_search`,
    description: cfg.description + ' Extracts MITRE TTPs, CVEs, actors, and malware families automatically.',
    inputSchema: {
      type:       'object',
      properties: {
        query: { type: 'string', description: 'Search keyword, malware family, or actor name' },
        limit: { type: 'number', description: 'Max results (default: 10, max: 25)' },
      },
      required: ['query'],
    },
    handler: async (args) => {
      const { query, limit = 10 } = args as { query: string; limit?: number };
      const cap = Math.min(limit, 25);
      const now = new Date().toISOString();

      const ckey = `community:${cfg.key}:feed`;
      let allItems = getCached<Array<{ title: string; url: string; date: string; snippet: string }>>(ckey);

      if (!allItems) {
        try {
          const xml   = await fetchWithRetry(cfg.rss);
          const items = parseRSS(xml);
          allItems = items.map(i => ({
            title:   i.title,
            url:     i.link,
            date:    i.pubDate,
            snippet: i.description.substring(0, 400),
          }));
          setCached(ckey, allItems, cfg.ttl ?? VENDOR_BLOG_TTL);
        } catch (err) {
          return {
            source: cfg.key, success: false, queried_at: now, data: null,
            error: `Failed to fetch ${cfg.name}: ${(err as Error).message}`,
          };
        }
      }

      const q = query.toLowerCase();
      const matched = allItems
        .filter(i => i.title.toLowerCase().includes(q) || i.snippet.toLowerCase().includes(q))
        .slice(0, cap);

      const results = matched.map(item => {
        const markers = extractIntelMarkers(item.title + ' ' + item.snippet);
        return {
          ...item,
          techniques: markers.techniques,
          cves:       markers.cves,
          actors:     markers.actors,
          malware:    markers.malware,
        };
      });

      return {
        source:     cfg.key,
        success:    true,
        queried_at: now,
        data: { query, vendor: cfg.name, count: results.length, results },
        pivot_suggestions: [
          ...results.flatMap(r => r.actors.slice(0, 1)).slice(0, 2).map(a => ({
            type: 'actor' as const, value: a, confidence: 'medium' as const, tool: 'ti_actor_full_profile',
          })),
          ...results.flatMap(r => r.cves.slice(0, 1)).slice(0, 2).map(c => ({
            type: 'cve' as const, value: c, confidence: 'medium' as const, tool: 'epss_score_lookup',
          })),
        ],
      };
    },
  });
}

const communityBlogTools = COMMUNITY_BLOGS.map(createCommunitySearchTool);

// ─── TOOL 8: vx_underground_search ───────────────────────────────────────────

const vxUndergroundSearch = defineTool({
  name:        'vx_underground_search',
  description: 'Search VX-Underground — the largest free malware sample repository. ' +
               'Returns matching papers, write-ups, and malware samples from their public index. ' +
               'Best for technical malware analysis, source code, and underground research.',
  inputSchema: {
    type:       'object',
    properties: {
      query: { type: 'string', description: 'Malware family, actor name, or technical keyword' },
      limit: { type: 'number', description: 'Max results (default: 10)' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query, limit = 10 } = args as { query: string; limit?: number };
    const now = new Date().toISOString();

    // VX-Underground's papers index as a searchable HTML page
    const ckey = 'community:vx_underground:index';
    let html = getCached<string>(ckey);

    if (!html) {
      try {
        html = await fetchWithRetry(VX_PAPERS_URL);
        setCached(ckey, html, VENDOR_BLOG_TTL);
      } catch (err) {
        return {
          source:     'vx_underground',
          success:    false,
          queried_at: now,
          data:       null,
          error:      `Failed to fetch VX-Underground: ${(err as Error).message}`,
          note:       'VX-Underground: https://vx-underground.org',
        };
      }
    }

    // Extract links and titles from HTML
    const linkPattern = /<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
    const q = query.toLowerCase();
    const matches: Array<{ title: string; url: string }> = [];

    let match: RegExpExecArray | null;
    while ((match = linkPattern.exec(html)) !== null) {
      const href  = match[1];
      const text  = match[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
      if (
        text.length > 5 &&
        (text.toLowerCase().includes(q) || href.toLowerCase().includes(q))
      ) {
        const url = href.startsWith('http') ? href : `https://vx-underground.org${href}`;
        matches.push({ title: text, url });
      }
      if (matches.length >= Math.min(limit, 25)) break;
    }

    return {
      source:     'vx_underground',
      success:    true,
      queried_at: now,
      data: {
        query,
        count:   matches.length,
        results: matches,
        note:    'Full malware sample archive at https://vx-underground.org',
      },
    };
  },
});

// ─── TOOL 9: misp_warninglist_check ──────────────────────────────────────────

const mispWarninglistCheck = defineTool({
  name:        'misp_warninglist_check',
  description: 'Check if an IOC (domain, IP, URL) appears in MISP warning lists. ' +
               'MISP warning lists contain known false positives — legitimate infrastructure ' +
               'that commonly triggers threat intel feeds (Alexa top 1M, Microsoft, Google CDN, etc.). ' +
               'Run this BEFORE pivoting on a domain or IP to avoid wasting time on FPs.',
  inputSchema: {
    type:       'object',
    properties: {
      ioc:   { type: 'string', description: 'IOC value to check (domain, IP address, or URL)' },
      lists: {
        type:  'array',
        items: { type: 'string' },
        description: 'Warning lists to check: alexa, microsoft, google, majestic, tranco, mozilla (default: all)',
      },
    },
    required: ['ioc'],
  },
  handler: async (args) => {
    const { ioc, lists = Object.keys(MISP_WARNINGLIST_URLS) } =
      args as { ioc: string; lists?: string[] };
    const now = new Date().toISOString();

    // Normalise IOC for matching
    const iocClean = ioc
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
      .toLowerCase()
      .trim();

    const hits: Array<{ list: string; matched: string }> = [];
    const misses: string[] = [];
    const errors: string[] = [];

    await Promise.allSettled(
      lists.map(async (listName) => {
        const listUrl = MISP_WARNINGLIST_URLS[listName];
        if (!listUrl) { errors.push(`Unknown list: ${listName}`); return; }

        const ckey = `misp:wl:${listName}`;
        let listData = getCached<{ list: string[] }>(ckey);

        if (!listData) {
          try {
            const raw = await fetchWithRetry(listUrl);
            const parsed = JSON.parse(raw) as { list: string[] };
            setCached(ckey, parsed, 86_400); // 24h — these lists change rarely
            listData = parsed;
          } catch {
            errors.push(`Failed to fetch ${listName} warning list`);
            return;
          }
        }

        const entries = listData.list || [];
        const found = entries.find(e => {
          const entry = e.toLowerCase().trim();
          return entry === iocClean || iocClean.endsWith('.' + entry) || entry.endsWith('.' + iocClean);
        });

        if (found) {
          hits.push({ list: listName, matched: found });
        } else {
          misses.push(listName);
        }
      })
    );

    const is_whitelisted = hits.length > 0;

    return {
      source:     'misp_warninglists',
      success:    true,
      queried_at: now,
      data: {
        ioc:            ioc,
        ioc_normalised: iocClean,
        is_false_positive_candidate: is_whitelisted,
        verdict:        is_whitelisted
          ? `LIKELY FALSE POSITIVE — appears in ${hits.map(h => h.list).join(', ')}`
          : `NOT FOUND in checked warning lists — may be legitimate IOC`,
        hits,
        misses,
        errors,
        lists_checked: lists,
        recommendation: is_whitelisted
          ? 'Exercise caution before pivoting — this IOC appears in well-known benign infrastructure lists.'
          : 'IOC not found in warning lists. Proceed with standard pivot analysis.',
      },
    };
  },
});

// ─── EXPORTS ─────────────────────────────────────────────────────────────────

export const communityTools: ToolDefinition[] = [
  malpediaSearch,
  malpediaActorProfile,
  malpediaFamilyProfile,
  sansIscSearch,
  anyrunTrending,
  ...communityBlogTools,       // bleeping_search, malwarebytes_search
  vxUndergroundSearch,
  mispWarninglistCheck,
];

export const communityToolCount = communityTools.length;
