/**
 * Correlation Engine — Phase 5 (The Brain)
 *
 * Fuses intelligence from MITRE ATT&CK, vendor blogs, OTX, and the local
 * detection index into coherent, actionable threat intelligence packages.
 *
 * Tools (5):
 *   ti_multi_source_ttp_lookup — Fan-out across all sources for a technique
 *   ti_actor_full_profile      — Full actor profile fusion (MITRE + OTX + vendors)
 *   ti_hunt_package            — Complete hunt package for client context
 *   ti_report_ingest           — Ingest any threat report URL
 *   ti_daily_brief             — Daily TI brief from recent vendor feeds
 */

import { defineTool, type ToolDefinition } from '../../registry.js';
import { runQuery } from '../../../db/connection.js';
import {
  getGroupByName,
  getGroupTechniques,
  getMitigationsForTechnique,
  getDataSourcesForTechnique,
  searchGroups,
} from '../../../db/mitre-attack.js';
import {
  fetchWithRetry,
  parseRSS,
  extractIntelMarkers,
  extractArticleBody,
  VENDOR_ENDPOINTS,
  VENDOR_BLOG_TTL,
} from '../vendors/utils.js';
import { otxSearchActor } from '../otx.js';
import { pivotExpandIOCs } from '../pivot.js';
import { getCached, setCached } from '../cache.js';

// ─── PRIORITY VENDORS ────────────────────────────────────────────────────────

const PRIORITY_VENDORS = ['mandiant', 'microsoft', 'crowdstrike', 'elastic', 'unit42', 'kaspersky'];

// ─── INNER HELPERS ────────────────────────────────────────────────────────────

type FeedResult = { title: string; url: string; date: string; snippet: string; vendor: string };

/** Fetch + keyword-filter a vendor RSS feed */
async function searchVendorFeed(vendorKey: string, query: string, limit = 5): Promise<FeedResult[]> {
  const cfg = VENDOR_ENDPOINTS[vendorKey];
  if (!cfg) return [];

  const ckey = `corr:feed:${vendorKey}:${query.toLowerCase().slice(0, 40)}`;
  const cached = getCached<FeedResult[]>(ckey);
  if (cached) {
    const q = query.toLowerCase();
    return cached.filter(r => r.title.toLowerCase().includes(q) || r.snippet.toLowerCase().includes(q)).slice(0, limit);
  }

  try {
    const xml = await fetchWithRetry(cfg.rss);
    const items = parseRSS(xml);
    // Cache all items, filter on each query
    const all: FeedResult[] = items.map(i => ({
      title:   i.title,
      url:     i.link,
      date:    i.pubDate,
      snippet: i.description.substring(0, 300),
      vendor:  cfg.name,
    }));
    setCached(ckey, all, VENDOR_BLOG_TTL);
    const q = query.toLowerCase();
    return all.filter(r => r.title.toLowerCase().includes(q) || r.snippet.toLowerCase().includes(q)).slice(0, limit);
  } catch {
    return [];
  }
}

/** Groups that use a given technique (direct DB query) */
function groupsForTechnique(techniqueId: string): Array<{ id: string; name: string; aliases: string[] }> {
  const rows = runQuery<Record<string, unknown>>(
    `SELECT DISTINCT g.external_id, g.name, g.aliases
     FROM mitre_groups g
     JOIN mitre_relationships r ON r.source_ref = g.stix_id
     JOIN mitre_techniques_full t ON t.stix_id = r.target_ref
     WHERE r.relationship_type = 'uses' AND t.external_id = ?`,
    [techniqueId.toUpperCase()]
  );
  return rows.map(r => ({
    id:      r.external_id as string,
    name:    r.name as string,
    aliases: r.aliases ? JSON.parse(r.aliases as string) : [],
  }));
}

/** Software that uses a given technique */
function softwareForTechnique(techniqueId: string): Array<{ id: string; name: string; type: string }> {
  const malware = runQuery<Record<string, unknown>>(
    `SELECT DISTINCT m.external_id, m.name, 'malware' as stype
     FROM mitre_malware m
     JOIN mitre_relationships r ON r.source_ref = m.stix_id
     JOIN mitre_techniques_full t ON t.stix_id = r.target_ref
     WHERE r.relationship_type = 'uses' AND t.external_id = ?`,
    [techniqueId.toUpperCase()]
  );
  const tools = runQuery<Record<string, unknown>>(
    `SELECT DISTINCT tl.external_id, tl.name, 'tool' as stype
     FROM mitre_tools tl
     JOIN mitre_relationships r ON r.source_ref = tl.stix_id
     JOIN mitre_techniques_full t ON t.stix_id = r.target_ref
     WHERE r.relationship_type = 'uses' AND t.external_id = ?`,
    [techniqueId.toUpperCase()]
  );
  return [...malware, ...tools].map(r => ({
    id:   r.external_id as string,
    name: r.name as string,
    type: r.stype as string,
  }));
}

/** Count detections in local index for a technique */
function countDetections(techniqueId: string): { total: number; by_source: Record<string, number> } {
  const rows = runQuery<{ source_type: string; cnt: number }>(
    `SELECT source_type, COUNT(*) as cnt FROM detections
     WHERE mitre_techniques LIKE ? GROUP BY source_type`,
    [`%${techniqueId.toUpperCase()}%`]
  );
  const by_source: Record<string, number> = {};
  let total = 0;
  for (const r of rows) { by_source[r.source_type] = r.cnt; total += r.cnt; }
  return { total, by_source };
}

/** Classify coverage gap status */
function gapStatus(count: number): 'covered' | 'partial' | 'gap' {
  if (count >= 5) return 'covered';
  if (count >= 1) return 'partial';
  return 'gap';
}

/** Correlation confidence score */
function corrConfidence(sourcesCount: number, mitreConfirmed: boolean, vendorCount: number): 'high' | 'medium' | 'low' {
  let score = 0;
  if (sourcesCount >= 3) score += 3;
  if (mitreConfirmed)    score += 2;
  if (vendorCount >= 2)  score += 2;
  if (score >= 6) return 'high';
  if (score >= 3) return 'medium';
  return 'low';
}

// ─── TOOL 1: ti_multi_source_ttp_lookup ──────────────────────────────────────

const tiMultiSourceTTPLookup = defineTool({
  name: 'ti_multi_source_ttp_lookup',
  description:
    'ELITE CORRELATION: Given a MITRE technique ID, fan out across MITRE ATT&CK, ' +
    'vendor threat intel blogs, and the local detection index. Returns a fused picture: ' +
    'which actors use it, what malware leverages it, recent vendor reports, detection coverage, ' +
    'and telemetry requirements. The definitive first stop for any TTP investigation.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id:      { type: 'string',  description: 'MITRE ATT&CK technique ID (e.g., T1059.001)' },
      client_industry:   { type: 'string',  description: 'Optional: client industry for relevance context' },
      client_region:     { type: 'string',  description: 'Optional: client region for relevance context' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id, client_industry, client_region } =
      args as { technique_id: string; client_industry?: string; client_region?: string };
    const tid = technique_id.toUpperCase();
    const now = new Date().toISOString();

    // PHASE 1: Structured intelligence (DB — fast, cached by sqlite)
    const techRows = runQuery<Record<string, unknown>>(
      `SELECT external_id, name, tactics, description FROM mitre_techniques_full WHERE external_id = ?`,
      [tid]
    );
    const tech = techRows[0];
    const mitreConfirmed = !!tech;

    const actors   = groupsForTechnique(tid);
    const software = softwareForTechnique(tid);
    const coverage = countDetections(tid);

    const dataSrcRows = getDataSourcesForTechnique(tid) as Array<Record<string, unknown>>;
    const mitigRows   = getMitigationsForTechnique(tid) as Array<Record<string, unknown>>;

    // PHASE 2: Vendor RSS (parallel, best-effort)
    const techName = (tech?.name as string) || tid;
    const searchTerms = [techName, ...(client_industry ? [client_industry] : [])];

    const vendorPromises = PRIORITY_VENDORS.map(v => searchVendorFeed(v, techName));
    const vendorResults  = await Promise.allSettled(vendorPromises);

    const recentReports: FeedResult[] = [];
    let vendorCount = 0;
    for (const r of vendorResults) {
      if (r.status === 'fulfilled' && r.value.length > 0) {
        recentReports.push(...r.value.slice(0, 3));
        vendorCount++;
      }
    }

    // PHASE 3: FUSE
    const sourcesConsulted = ['mitre_attack', 'local_detection_index', ...PRIORITY_VENDORS.slice(0, vendorCount)];
    const confidence = corrConfidence(sourcesConsulted.length, mitreConfirmed, vendorCount);

    // Relevance filters
    const industryLower = client_industry?.toLowerCase();
    const regionLower   = client_region?.toLowerCase();

    // Deduplicate data sources
    const dataSourceMap = new Map<string, string[]>();
    for (const ds of dataSrcRows) {
      const name = ds.name as string;
      if (!dataSourceMap.has(name)) dataSourceMap.set(name, []);
      if (ds.component_name) dataSourceMap.get(name)!.push(ds.component_name as string);
    }

    return {
      technique: {
        id:          tid,
        name:        (tech?.name as string) || 'Unknown',
        tactic:      tech?.tactics ? (JSON.parse(tech.tactics as string) as string[]).join(', ') : 'Unknown',
        description: ((tech?.description as string) || 'No description available').substring(0, 500),
        mitre_url:   `https://attack.mitre.org/techniques/${tid.replace('.', '/')}`,
      },
      actors_using: actors.map(a => ({
        name:     a.name,
        aliases:  a.aliases.slice(0, 5),
        source:   'mitre_attack',
        industry_relevant: industryLower
          ? (a.name.toLowerCase().includes(industryLower) || a.aliases.some(al => al.toLowerCase().includes(industryLower)))
          : null,
        region_relevant: regionLower
          ? (a.name.toLowerCase().includes(regionLower) || a.aliases.some(al => al.toLowerCase().includes(regionLower)))
          : null,
      })),
      malware_using: software.map(s => ({ name: s.name, type: s.type, source: 'mitre_attack' })),
      recent_campaigns: recentReports.map(r => ({
        title:    r.title,
        vendor:   r.vendor,
        url:      r.url,
        date:     r.date,
        snippet:  r.snippet,
      })),
      detection_coverage: {
        total_rules: coverage.total,
        by_source:   coverage.by_source,
        gap_status:  gapStatus(coverage.total),
      },
      telemetry_requirements: {
        data_sources: Array.from(dataSourceMap.keys()),
        components:   Object.fromEntries(dataSourceMap),
      },
      mitigations: mitigRows.map(m => `${m.external_id}: ${(m.name as string) || ''}`),
      confidence,
      sources_consulted: sourcesConsulted,
      vendor_reports_found: recentReports.length,
      search_terms_used:   searchTerms,
      last_updated: now,
    };
  },
});

// ─── TOOL 2: ti_actor_full_profile ───────────────────────────────────────────

const tiActorFullProfile = defineTool({
  name: 'ti_actor_full_profile',
  description:
    'ELITE CORRELATION: Build the most complete threat actor profile available. ' +
    'Fuses MITRE ATT&CK group data, live vendor blog reports, optional OTX IOC pivot, ' +
    'and detection coverage scores across the actor\'s top 20 techniques. ' +
    'Use this before any hunting engagement against a named threat actor.',
  inputSchema: {
    type: 'object',
    properties: {
      actor:        { type: 'string',  description: 'Threat actor name (e.g., APT29, Lazarus Group, FIN7)' },
      include_iocs: { type: 'boolean', description: 'Also pivot for IOCs via OTX (default: false)' },
    },
    required: ['actor'],
  },
  handler: async (args) => {
    const { actor, include_iocs = false } = args as { actor: string; include_iocs?: boolean };
    const now = new Date().toISOString();

    // PHASE 1: MITRE structured data
    const mitreGroup = getGroupByName(actor) as Record<string, unknown> | null;
    const techniques = mitreGroup
      ? (getGroupTechniques(mitreGroup.external_id as string || actor) as Array<Record<string, unknown>>)
      : [];

    // PHASE 2: Vendor reports (parallel)
    const vendorSearches = await Promise.allSettled(
      PRIORITY_VENDORS.map(v => searchVendorFeed(v, actor, 4))
    );
    const vendorReports: FeedResult[] = [];
    let vendorHits = 0;
    for (const r of vendorSearches) {
      if (r.status === 'fulfilled' && r.value.length > 0) {
        vendorReports.push(...r.value);
        vendorHits++;
      }
    }

    // PHASE 3: OTX IOC pivot (optional)
    let otxData: Record<string, unknown> | null = null;
    if (include_iocs) {
      try {
        const otxResult = await otxSearchActor(actor);
        if (otxResult.success) otxData = otxResult as unknown as Record<string, unknown>;
      } catch { /* OTX unavailable */ }
    }

    // PHASE 4: Detection coverage for top 20 techniques
    const topTechniques = techniques.slice(0, 20);
    const coverageResults = topTechniques.map(t => {
      const tid = t.external_id as string;
      const cov = countDetections(tid);
      return {
        technique_id:   tid,
        technique_name: t.name as string,
        tactics:        t.tactics ? JSON.parse(t.tactics as string) : [],
        detection_count: cov.total,
        gap_status:     gapStatus(cov.total),
      };
    });

    const totalCovered = coverageResults.filter(c => c.gap_status === 'covered').length;
    const totalPartial  = coverageResults.filter(c => c.gap_status === 'partial').length;
    const totalGaps     = coverageResults.filter(c => c.gap_status === 'gap').length;

    const confidence = corrConfidence(
      vendorHits + (mitreGroup ? 1 : 0),
      !!mitreGroup,
      vendorHits
    );

    return {
      actor_name:    actor,
      mitre_profile: mitreGroup
        ? {
            id:          mitreGroup.external_id,
            name:        mitreGroup.name,
            aliases:     mitreGroup.aliases ? JSON.parse(mitreGroup.aliases as string) : [],
            description: ((mitreGroup.description as string) || '').substring(0, 600),
            url:         mitreGroup.url,
          }
        : null,
      techniques_total: techniques.length,
      technique_coverage: coverageResults,
      coverage_summary: {
        assessed: topTechniques.length,
        covered:  totalCovered,
        partial:  totalPartial,
        gaps:     totalGaps,
        coverage_pct: topTechniques.length > 0
          ? Math.round(((totalCovered + totalPartial * 0.5) / topTechniques.length) * 100)
          : 0,
      },
      top_uncovered_techniques: coverageResults
        .filter(c => c.gap_status === 'gap')
        .slice(0, 5),
      vendor_reports: vendorReports.map(r => ({
        title:  r.title,
        vendor: r.vendor,
        url:    r.url,
        date:   r.date,
      })),
      otx_data:  otxData,
      confidence,
      sources_consulted: [
        ...(mitreGroup ? ['mitre_attack'] : []),
        ...PRIORITY_VENDORS.slice(0, vendorHits),
        ...(otxData ? ['otx'] : []),
      ],
      last_updated: now,
    };
  },
});

// ─── TOOL 3: ti_hunt_package ──────────────────────────────────────────────────

const tiHuntPackage = defineTool({
  name: 'ti_hunt_package',
  description:
    'ELITE: THE ULTIMATE HUNT TOOL. Given a client context (industry + region + scenario), ' +
    'produce a complete hunt package: relevant threat actors, priority TTPs, detection coverage ' +
    'analysis, coverage gaps, and vendor intelligence — all fused from multi-source data. ' +
    'Output is structured for direct import into a use-case tracker.',
  inputSchema: {
    type: 'object',
    properties: {
      industry:       { type: 'string',  description: 'Client industry (e.g., healthcare, finance, energy)' },
      region:         { type: 'string',  description: 'Client region (e.g., Middle East, UK, US)' },
      scenario:       { type: 'string',  description: 'Threat scenario (e.g., ransomware, espionage, supply-chain)' },
      log_sources:    {
        type: 'array', items: { type: 'string' },
        description: 'Available log sources (e.g., ["sysmon", "crowdstrike", "azure_ad"])',
      },
      max_techniques: { type: 'number', description: 'Max techniques to analyze (default: 15)' },
    },
    required: ['industry', 'region', 'scenario'],
  },
  handler: async (args) => {
    const { industry, region, scenario, log_sources = [], max_techniques = 15 } =
      args as { industry: string; region: string; scenario: string; log_sources?: string[]; max_techniques?: number };
    const now = new Date().toISOString();

    // PHASE 1: Find relevant threat actors (keyword match on industry + region + scenario)
    const industryGroups = searchGroups(industry) as Array<Record<string, unknown>>;
    const regionGroups   = searchGroups(region)   as Array<Record<string, unknown>>;
    const scenarioGroups = searchGroups(scenario)  as Array<Record<string, unknown>>;

    // Union, deduplicate by external_id
    const allGroupsMap = new Map<string, { group: Record<string, unknown>; relevance: string[] }>();
    for (const g of industryGroups) {
      const id = g.external_id as string;
      if (!allGroupsMap.has(id)) allGroupsMap.set(id, { group: g, relevance: [] });
      allGroupsMap.get(id)!.relevance.push('industry');
    }
    for (const g of regionGroups) {
      const id = g.external_id as string;
      if (!allGroupsMap.has(id)) allGroupsMap.set(id, { group: g, relevance: [] });
      allGroupsMap.get(id)!.relevance.push('region');
    }
    for (const g of scenarioGroups) {
      const id = g.external_id as string;
      if (!allGroupsMap.has(id)) allGroupsMap.set(id, { group: g, relevance: [] });
      allGroupsMap.get(id)!.relevance.push('scenario');
    }

    // Sort: actors matching all 3 criteria first (primary), then 2 (secondary)
    const sortedActors = Array.from(allGroupsMap.values())
      .sort((a, b) => b.relevance.length - a.relevance.length)
      .slice(0, 8);

    // PHASE 2: Collect techniques from top actors
    const techniqueFreq = new Map<string, { name: string; tactics: string[]; actors: string[]; count: number }>();
    for (const entry of sortedActors.slice(0, 5)) {
      const gid = entry.group.external_id as string;
      const techs = getGroupTechniques(gid) as Array<Record<string, unknown>>;
      for (const t of techs) {
        const tid = t.external_id as string;
        if (!techniqueFreq.has(tid)) {
          techniqueFreq.set(tid, {
            name:   t.name as string,
            tactics: t.tactics ? JSON.parse(t.tactics as string) : [],
            actors: [],
            count:  0,
          });
        }
        const entry2 = techniqueFreq.get(tid)!;
        entry2.actors.push(entry.group.name as string);
        entry2.count++;
      }
    }

    // PHASE 3: Detection coverage for top techniques
    const topTechniques = Array.from(techniqueFreq.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, max_techniques);

    const priorityTechniques = topTechniques.map(([tid, info]) => {
      const cov = countDetections(tid);
      const dataSrcs = getDataSourcesForTechnique(tid) as Array<Record<string, unknown>>;
      const reqSources = [...new Set(dataSrcs.map(d => (d.name as string).toLowerCase()))];
      const dataAvailable = log_sources.length === 0 ||
        reqSources.some(s => log_sources.some(ls => ls.toLowerCase().includes(s)));

      const gap = gapStatus(cov.total);
      const priority: 'P1' | 'P2' | 'P3' =
        gap === 'gap' && info.count >= 2 ? 'P1' :
        gap === 'partial' && info.count >= 2 ? 'P1' :
        gap === 'gap' ? 'P2' : 'P3';

      return {
        technique_id:          tid,
        technique_name:        info.name,
        tactic:                info.tactics[0] || 'Unknown',
        actors_using:          [...new Set(info.actors)],
        actor_overlap_count:   info.count,
        detection_status:      gap,
        detection_count:       cov.total,
        detection_by_source:   cov.by_source,
        data_source_available: dataAvailable,
        priority,
      };
    });

    // PHASE 4: Vendor intelligence for scenario
    const vendorSearches = await Promise.allSettled(
      PRIORITY_VENDORS.map(v => searchVendorFeed(v, `${scenario} ${industry}`, 3))
    );
    const vendorIntel: FeedResult[] = [];
    for (const r of vendorSearches) {
      if (r.status === 'fulfilled') vendorIntel.push(...r.value);
    }

    // Coverage stats
    const covered = priorityTechniques.filter(t => t.detection_status === 'covered').length;
    const partial  = priorityTechniques.filter(t => t.detection_status === 'partial').length;
    const gaps     = priorityTechniques.filter(t => t.detection_status === 'gap').length;

    return {
      client_context: { industry, region, scenario, log_sources },
      threat_actors: sortedActors.map(e => ({
        name:       e.group.name as string,
        id:         e.group.external_id as string,
        relevance:  e.relevance.length >= 2 ? 'primary' : 'secondary',
        reason:     `Matched on: ${e.relevance.join(', ')}`,
        description: ((e.group.description as string) || '').substring(0, 200),
      })),
      priority_techniques:    priorityTechniques,
      detection_gaps: priorityTechniques
        .filter(t => t.detection_status === 'gap')
        .map(t => ({
          technique_id:   t.technique_id,
          technique_name: t.technique_name,
          actors:         t.actors_using,
          priority:       t.priority,
        })),
      vendor_intelligence: vendorIntel.slice(0, 10).map(r => ({
        vendor:        r.vendor,
        report_title:  r.title,
        url:           r.url,
        date:          r.date,
        relevance:     r.snippet.substring(0, 150),
      })),
      coverage_score: {
        total_techniques: priorityTechniques.length,
        covered,
        partial,
        gaps,
        percentage: priorityTechniques.length > 0
          ? Math.round(((covered + partial * 0.5) / priorityTechniques.length) * 100)
          : 0,
      },
      generated_at: now,
    };
  },
});

// ─── TOOL 4: ti_report_ingest ─────────────────────────────────────────────────

const tiReportIngest = defineTool({
  name: 'ti_report_ingest',
  description:
    'ELITE: Ingest any threat intelligence report URL. Fetches the report, extracts ALL ' +
    'intelligence markers (MITRE TTPs, CVEs, IOCs, actors, malware, tools), auto-correlates ' +
    'extracted techniques with detection coverage, and optionally pivots IOCs through OTX/abuse.ch. ' +
    'Works with any public threat blog, advisory, or research paper.',
  inputSchema: {
    type: 'object',
    properties: {
      url:              { type: 'string',  description: 'URL of any threat intelligence report or advisory' },
      auto_correlate:   { type: 'boolean', description: 'Auto-correlate extracted TTPs with detection index (default: true)' },
      auto_pivot_iocs:  { type: 'boolean', description: 'Auto-pivot extracted IOCs through OTX/abuse.ch (default: false)' },
    },
    required: ['url'],
  },
  handler: async (args) => {
    const { url, auto_correlate = true, auto_pivot_iocs = false } =
      args as { url: string; auto_correlate?: boolean; auto_pivot_iocs?: boolean };
    const now = new Date().toISOString();

    // STEP 1: Fetch the report
    let html: string;
    try {
      html = await fetchWithRetry(url);
    } catch (err) {
      return {
        success: false,
        source:  'ti_report_ingest',
        url,
        error:   `Failed to fetch report: ${(err as Error).message}`,
        queried_at: now,
      };
    }

    // STEP 2: Extract article body + intel markers
    const bodyText = extractArticleBody(html);
    const markers  = extractIntelMarkers(bodyText);

    // STEP 3: Auto-correlate TTPs with detection index
    let correlations: Array<{
      technique_id: string;
      detection_count: number;
      gap_status: string;
    }> | null = null;

    if (auto_correlate && markers.techniques.length > 0) {
      correlations = markers.techniques.map(tid => {
        const cov = countDetections(tid);
        return {
          technique_id:    tid,
          detection_count: cov.total,
          gap_status:      gapStatus(cov.total),
          by_source:       cov.by_source,
        };
      });
    }

    // STEP 4: IOC pivot (optional)
    let iocEnrichment: unknown = null;
    if (auto_pivot_iocs && markers.iocs.length > 0) {
      try {
        const pivotableIOCs = markers.iocs
          .filter(i => ['ip', 'domain', 'hash', 'url'].includes(i.type))
          .slice(0, 20) as Array<{ type: 'ip' | 'domain' | 'hash' | 'url'; value: string }>;
        if (pivotableIOCs.length > 0) {
          iocEnrichment = await pivotExpandIOCs({ iocs: pivotableIOCs });
        }
      } catch { /* pivot failed gracefully */ }
    }

    // Coverage assessment for this report
    const totalTechniques   = markers.techniques.length;
    const coveredTechniques = correlations?.filter(c => c.gap_status === 'covered').length ?? 0;
    const gapTechniques     = correlations?.filter(c => c.gap_status === 'gap').length ?? 0;

    return {
      success:     true,
      source:      'ti_report_ingest',
      url,
      queried_at:  now,
      extracted_markers: {
        techniques:    markers.techniques,
        cves:          markers.cves,
        actors:        markers.actors,
        malware:       markers.malware,
        tools:         markers.tools,
        iocs_count:    markers.iocs.length,
        iocs:          markers.iocs.slice(0, 30),
        industries:    markers.industries,
        regions:       markers.regions,
      },
      summary: {
        techniques_found:  totalTechniques,
        cves_found:        markers.cves.length,
        actors_found:      markers.actors.length,
        malware_found:     markers.malware.length,
        iocs_found:        markers.iocs.length,
      },
      ttp_correlation:   correlations,
      coverage_snapshot: correlations
        ? {
            covered:    coveredTechniques,
            gaps:       gapTechniques,
            gap_list:   correlations.filter(c => c.gap_status === 'gap').map(c => c.technique_id),
          }
        : null,
      ioc_enrichment: iocEnrichment,
    };
  },
});

// ─── TOOL 5: ti_daily_brief ───────────────────────────────────────────────────

const tiDailyBrief = defineTool({
  name: 'ti_daily_brief',
  description:
    'Generate a daily threat intelligence brief by scanning recent reports from priority vendors. ' +
    'Automatically extracts MITRE TTPs, CVEs, actors, and malware from each item. ' +
    'Filter by client industries or custom lookback window. ' +
    'Run this daily to stay current on the threat landscape.',
  inputSchema: {
    type: 'object',
    properties: {
      industries: {
        type: 'array', items: { type: 'string' },
        description: 'Client industries to filter for relevance (e.g., ["healthcare", "finance"])',
      },
      hours_lookback: { type: 'number', description: 'Hours to look back (default: 24, max: 168)' },
      vendors: {
        type: 'array', items: { type: 'string' },
        description: 'Specific vendor keys to check (default: top 6 priority vendors)',
      },
    },
  },
  handler: async (args) => {
    const {
      industries = [],
      hours_lookback = 24,
      vendors = PRIORITY_VENDORS,
    } = args as { industries?: string[]; hours_lookback?: number; vendors?: string[] };

    const now = new Date();
    const cutoff = new Date(now.getTime() - Math.min(hours_lookback, 168) * 3_600_000);
    const cutoffISO = cutoff.toISOString();

    // Fan out to all requested vendors in parallel
    const feedPromises = vendors.map(async (v) => {
      const cfg = VENDOR_ENDPOINTS[v];
      if (!cfg) return { vendor: v, items: [] as FeedResult[] };
      try {
        const xml   = await fetchWithRetry(cfg.rss);
        const items = parseRSS(xml);
        return {
          vendor: cfg.name,
          items: items.map(i => ({
            title:   i.title,
            url:     i.link,
            date:    i.pubDate,
            snippet: i.description.substring(0, 300),
            vendor:  cfg.name,
          })),
        };
      } catch {
        return { vendor: v, items: [] as FeedResult[] };
      }
    });

    const feedResults = await Promise.allSettled(feedPromises);

    // Collect, time-filter, and deduplicate
    const seenUrls = new Set<string>();
    const allItems: Array<FeedResult & { markers_preview: { techniques: string[]; cves: string[]; actors: string[]; malware: string[] } }> = [];

    for (const r of feedResults) {
      if (r.status !== 'fulfilled') continue;
      for (const item of r.value.items) {
        // Time filter: parse pubDate and compare
        if (item.date) {
          const pubDate = new Date(item.date);
          if (!isNaN(pubDate.getTime()) && pubDate < cutoff) continue;
        }
        // Dedup
        if (seenUrls.has(item.url)) continue;
        seenUrls.add(item.url);

        // Industry filter
        if (industries.length > 0) {
          const text = (item.title + item.snippet).toLowerCase();
          const relevant = industries.some(ind => text.includes(ind.toLowerCase()));
          if (!relevant) continue;
        }

        // Extract markers from snippet (fast, no full fetch)
        const quickMarkers = extractIntelMarkers(item.title + ' ' + item.snippet);
        allItems.push({
          ...item,
          markers_preview: {
            techniques: quickMarkers.techniques,
            cves:       quickMarkers.cves,
            actors:     quickMarkers.actors,
            malware:    quickMarkers.malware,
          },
        });
      }
    }

    // Sort by date descending
    allItems.sort((a, b) => {
      const da = new Date(a.date).getTime() || 0;
      const db = new Date(b.date).getTime() || 0;
      return db - da;
    });

    const topItems = allItems.slice(0, 25);

    // Aggregate unique TTPs, CVEs, actors across the brief
    const allTechniques = [...new Set(topItems.flatMap(i => i.markers_preview.techniques))];
    const allCVEs       = [...new Set(topItems.flatMap(i => i.markers_preview.cves))];
    const allActors     = [...new Set(topItems.flatMap(i => i.markers_preview.actors))];
    const allMalware    = [...new Set(topItems.flatMap(i => i.markers_preview.malware))];

    return {
      brief_date:     now.toISOString(),
      lookback_hours: hours_lookback,
      vendors_polled: vendors,
      industries_filter: industries,
      total_items:    topItems.length,
      cutoff_time:    cutoffISO,
      items: topItems,
      intel_summary: {
        unique_techniques: allTechniques,
        unique_cves:       allCVEs,
        unique_actors:     allActors,
        unique_malware:    allMalware,
        technique_count:   allTechniques.length,
        cve_count:         allCVEs.length,
        actor_count:       allActors.length,
        malware_count:     allMalware.length,
      },
      pivot_suggestions: [
        ...allTechniques.slice(0, 3).map(t => ({ type: 'technique', value: t, tool: 'ti_multi_source_ttp_lookup' })),
        ...allActors.slice(0, 2).map(a => ({ type: 'actor', value: a, tool: 'ti_actor_full_profile' })),
      ],
    };
  },
});

// ─── EXPORTS ─────────────────────────────────────────────────────────────────

export const correlationTools: ToolDefinition[] = [
  tiMultiSourceTTPLookup,
  tiActorFullProfile,
  tiHuntPackage,
  tiReportIngest,
  tiDailyBrief,
];

export const correlationToolCount = correlationTools.length;
