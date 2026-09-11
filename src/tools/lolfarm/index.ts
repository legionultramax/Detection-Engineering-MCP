// LOLFarm Tools — Living Off The Land aggregated intelligence
// Sources: LOLDrivers, HijackLibs, LOLRMM, LoFP, WADComs, LOTS, MalAPI
// Reference: https://lolol.farm

import { defineTool, ToolDefinition } from '../registry.js';
import {
  getLOLDriver, searchLOLDrivers, listLOLDrivers,
  getHijackLib,
  getLOLRMM, listLOLRMM,
  getLoFP, searchLoFP,
  searchWADComs,
  getLOTS, searchLOTS,
  getMalAPI, searchMalAPI,
  getLOLFarmContext, searchLOLFarm,
  getLOLFarmStats,
  cacheLOLDriver, cacheHijackLib, cacheLOLRMM, cacheLoFP,
  cacheWADCom, cacheLOTS, cacheMalAPI,
  getSyncStatus,
} from '../../db/lolfarm.js';
import { saveDb, runQuery } from '../../db/connection.js';
import {
  SEED_DRIVERS, SEED_HIJACKLIBS, SEED_RMM, SEED_LOFP,
  SEED_WADCOMS, SEED_LOTS, SEED_MALAPI,
} from './seed.js';
import { syncLOLFarm, SYNC_SOURCES, LIVE_SYNC_SOURCES } from './sync.js';

// ---------------------------------------------------------------------------
// Seed data loading — populates database on first use (lazy)
// ---------------------------------------------------------------------------

let seedLoaded = false;

function ensureSeedData(): void {
  if (seedLoaded) return;

  // Check if any data exists already
  const stats = getLOLFarmStats();
  if (stats.total > 0) {
    seedLoaded = true;
    return;
  }

  console.error('[lolfarm] Loading seed data...');

  for (const d of SEED_DRIVERS) cacheLOLDriver(d);
  for (const h of SEED_HIJACKLIBS) cacheHijackLib(h);
  for (const r of SEED_RMM) cacheLOLRMM(r);
  for (const f of SEED_LOFP) cacheLoFP(f);
  for (const w of SEED_WADCOMS) cacheWADCom(w);
  for (const l of SEED_LOTS) cacheLOTS(l);
  for (const m of SEED_MALAPI) cacheMalAPI(m);

  // Save to disk
  saveDb();

  seedLoaded = true;
  const finalStats = getLOLFarmStats();
  console.error(`[lolfarm] Seed data loaded: ${finalStats.total} entries across 7 sources`);
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

// 1. LOLDrivers lookup
const lookupLoldriver = defineTool({
  name: 'lookup_loldriver',
  description: 'Look up a vulnerable/malicious driver in the LOLDrivers database by name or hash (SHA256). Returns driver details, hashes for blocklisting, CVEs, and detection guidance. Essential for BYOVD (Bring Your Own Vulnerable Driver) detection.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Driver name (e.g., "RTCore64.sys") or SHA256 hash' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    ensureSeedData();
    const { query } = args as { query: string };

    const driver = getLOLDriver(query);
    if (driver) {
      return {
        found: true,
        driver: {
          name: driver.name,
          description: driver.description,
          category: driver.category,
          hashes: driver.hashes,
          cve: driver.cve,
          mitre_techniques: driver.mitre_techniques,
          detection: driver.detection,
          verified: driver.verified,
          resources: driver.resources,
        },
        reference: 'https://loldrivers.io/',
      };
    }

    // Try search
    const results = searchLOLDrivers(query);
    if (results.length > 0) {
      return {
        found: true,
        exact_match: false,
        results: results.map(d => ({
          name: d.name,
          description: d.description?.substring(0, 150),
          category: d.category,
          hashes: d.hashes,
          cve: d.cve,
        })),
        reference: 'https://loldrivers.io/',
      };
    }

    return {
      found: false,
      message: `No driver matching "${query}" in LOLDrivers database. This does not mean the driver is safe — it may not be cataloged yet.`,
      reference: 'https://loldrivers.io/',
    };
  },
});

// 2. HijackLibs lookup
const lookupHijacklib = defineTool({
  name: 'lookup_hijacklib',
  description: 'Look up DLL hijacking candidates for a given DLL name or executable. Returns vulnerable executables, hijack type (Phantom/Sideloading/Search Order), and expected DLL locations. Use for T1574.001/T1574.002 detection engineering.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'DLL name (e.g., "version.dll") or executable name (e.g., "msiexec.exe")' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    ensureSeedData();
    const { query } = args as { query: string };

    const results = getHijackLib(query);
    if (results.length > 0) {
      return {
        found: true,
        count: results.length,
        hijack_candidates: results.map(h => ({
          dll_name: h.name,
          vendor: h.vendor,
          hijack_type: h.hijack_type,
          expected_locations: h.expected_locations,
          vulnerable_executables: h.vulnerable_executables,
          resources: h.resources,
        })),
        reference: 'https://hijacklibs.net/',
      };
    }

    return {
      found: false,
      message: `No hijack candidates found for "${query}".`,
      reference: 'https://hijacklibs.net/',
    };
  },
});

// 3. LOLRMM lookup
const lookupLolrmm = defineTool({
  name: 'lookup_lolrmm',
  description: 'Look up a Remote Monitoring & Management (RMM) tool by name. Returns executable names, network artifacts (domains, ports), registry artifacts, and known abuse by threat actors. Essential for T1219 remote access tool abuse detection.',
  inputSchema: {
    type: 'object',
    properties: {
      tool_name: { type: 'string', description: 'RMM tool name (e.g., "AnyDesk", "ScreenConnect", "RustDesk")' },
    },
    required: ['tool_name'],
  },
  handler: async (args) => {
    ensureSeedData();
    const { tool_name } = args as { tool_name: string };

    const rmm = getLOLRMM(tool_name);
    if (rmm) {
      return {
        found: true,
        tool: {
          name: rmm.name,
          vendor: rmm.vendor,
          description: rmm.description,
          executable_names: rmm.executable_names,
          network_artifacts: rmm.network_artifacts,
          registry_artifacts: rmm.registry_artifacts,
          detection_guidance: rmm.detection_guidance,
          mitre_techniques: rmm.mitre_techniques,
          abused_by: rmm.abuse_references,
        },
        reference: 'https://lolrmm.io/',
      };
    }

    return {
      found: false,
      available_tools: listLOLRMM().tools.map(t => t.name),
      reference: 'https://lolrmm.io/',
    };
  },
});

// 4. LoFP lookup — false positives by technique
const lookupLofp = defineTool({
  name: 'lookup_lofp',
  description: 'Look up known false positives for a MITRE ATT&CK technique. Returns process names, command patterns, descriptions, and suppression logic. Use this during detection rule FP filter authoring.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., "T1059.001", "T1003.001")' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    ensureSeedData();
    const { technique_id } = args as { technique_id: string };

    const fps = getLoFP(technique_id);
    if (fps.length > 0) {
      return {
        technique_id,
        count: fps.length,
        false_positives: fps.map(f => ({
          process: f.process_name,
          pattern: f.command_pattern,
          description: f.description,
          suppression: f.suppression_logic,
          confidence: f.confidence,
        })),
        note: 'Apply these suppressions to your detection rule filter section. Confirmed = safe to suppress. Likely = suppress with logging. Possible = monitor before suppressing.',
      };
    }

    // Try broader search
    const broader = searchLoFP(technique_id);
    if (broader.length > 0) {
      return {
        technique_id,
        exact_match: false,
        count: broader.length,
        false_positives: broader.map(f => ({
          technique: f.technique_id,
          process: f.process_name,
          description: f.description,
          confidence: f.confidence,
        })),
      };
    }

    return {
      technique_id,
      count: 0,
      message: `No cataloged false positives for ${technique_id}. This technique may need manual FP analysis.`,
    };
  },
});

// 5. WADComs search
const lookupWadcom = defineTool({
  name: 'lookup_wadcom',
  description: 'Search Windows/Active Directory offensive commands by keyword, tool name, or technique. Returns the exact commands attackers run against AD, plus the protocol each one crosses (SMB, Kerberos, LDAP, NTLM, RPC, WMI) — which is what decides the log source a detection must read. Use for building detection conditions from real attack commands.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search keyword (e.g., "kerberoast", "dcsync", "mimikatz", "bloodhound")' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    ensureSeedData();
    const { query } = args as { query: string };

    const results = searchWADComs(query);
    const inherited = results.some(w => w.mitre_source);
    return {
      query,
      count: results.length,
      commands: results.map(w => ({
        name: w.name,
        description: w.description,
        command: w.command,
        category: w.category,
        os: w.os,
        services: w.services,
        prerequisites: w.tools_required,
        mitre_techniques: w.mitre_techniques,
        mitre_techniques_source: w.mitre_source,
      })),
      // Said on every response that carries one, because the alternative is a
      // reader treating a tool's whole ATT&CK profile as this command's mapping.
      ...(inherited
        ? {
            note:
              'WADComs publishes no ATT&CK mapping. Where mitre_techniques_source is present, the ' +
              'technique IDs were derived by resolving the tool name against ATT&CK software ' +
              'entries, so they describe the tool rather than this specific command — every ' +
              'Impacket entry carries all of Impacket\'s techniques. Good for finding a command ' +
              'from a technique; not evidence the command implements it.',
          }
        : {}),
      reference: 'https://wadcoms.github.io/',
    };
  },
});

// 6. LOTS domain lookup
const lookupLotsDomain = defineTool({
  name: 'lookup_lots_domain',
  description: 'Check if a domain is in the LOTS (Living Off Trusted Sites) database — legitimate services abused for C2, exfiltration, or payload hosting. Use for proxy/firewall rule enrichment and T1102/T1567 detection.',
  inputSchema: {
    type: 'object',
    properties: {
      domain: { type: 'string', description: 'Domain to check (e.g., "pastebin.com", "ngrok.io", "discord.com")' },
    },
    required: ['domain'],
  },
  handler: async (args) => {
    ensureSeedData();
    const { domain } = args as { domain: string };

    const entry = getLOTS(domain);
    if (entry) {
      return {
        found: true,
        domain: entry.domain,
        service: entry.service_name,
        abuse_category: entry.category,
        description: entry.description,
        mitre_techniques: entry.mitre_techniques,
        warning: 'This is a legitimate service that is commonly abused. Do NOT block outright — investigate context (process, user, volume, timing).',
        reference: 'https://lots-project.com/',
      };
    }

    // Try search
    const results = searchLOTS(domain);
    if (results.length > 0) {
      return {
        found: true,
        exact_match: false,
        results: results.map(l => ({
          domain: l.domain,
          service: l.service_name,
          category: l.category,
        })),
        reference: 'https://lots-project.com/',
      };
    }

    return {
      found: false,
      domain,
      message: `"${domain}" not in LOTS database. May still be abused — check OTX/ThreatFox for IOC data.`,
    };
  },
});

// 7. MalAPI lookup
const lookupMalapi = defineTool({
  name: 'lookup_malapi',
  description: 'Look up a Windows API by name to see its malware behavior mapping. Returns technique associations, malware families using it, and detection notes. Use for understanding what behaviors an API call indicates.',
  inputSchema: {
    type: 'object',
    properties: {
      api_name: { type: 'string', description: 'Win32 API name (e.g., "VirtualAllocEx", "CreateRemoteThread", "MiniDumpWriteDump")' },
    },
    required: ['api_name'],
  },
  handler: async (args) => {
    ensureSeedData();
    const { api_name } = args as { api_name: string };

    const entry = getMalAPI(api_name);
    if (entry) {
      return {
        found: true,
        api: entry.api_name,
        description: entry.description,
        behavior_category: entry.category,
        mitre_techniques: entry.mitre_techniques,
        malware_families: entry.malware_families,
        detection_notes: entry.detection_notes,
        reference: 'https://malapi.io/',
      };
    }

    // Try search
    const results = searchMalAPI(api_name);
    if (results.length > 0) {
      return {
        found: true,
        exact_match: false,
        results: results.map(a => ({
          api: a.api_name,
          category: a.category,
          description: a.description?.substring(0, 100),
          mitre_techniques: a.mitre_techniques,
        })),
        reference: 'https://malapi.io/',
      };
    }

    return {
      found: false,
      message: `"${api_name}" not in MalAPI database.`,
      reference: 'https://malapi.io/',
    };
  },
});

// 8. Cross-source search
const searchLolfarm = defineTool({
  name: 'search_lolfarm',
  description: 'Search across ALL LOLFarm sources (drivers, DLL hijacks, RMM tools, false positives, AD commands, abused domains, APIs) with a single query. Optional source filter to narrow results.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search keyword (e.g., "anydesk", "version.dll", "T1055")' },
      source: { type: 'string', description: 'Optional: filter to one source (drivers, hijacklibs, rmm, wadcoms, lots, malapi)' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    ensureSeedData();
    const { query, source } = args as { query: string; source?: string };
    return searchLOLFarm(query, source);
  },
});

// 9. List LOLDrivers
const listLoldrivers = defineTool({
  name: 'list_loldrivers',
  description: 'List all known vulnerable/malicious drivers in the LOLDrivers database. Optional category filter (vulnerable, malicious). Use for BYOVD blocklist generation.',
  inputSchema: {
    type: 'object',
    properties: {
      category: { type: 'string', description: 'Optional: "vulnerable" or "malicious"' },
    },
  },
  handler: async (args) => {
    ensureSeedData();
    const { category } = args as { category?: string };
    const result = listLOLDrivers(category);
    return { ...result, reference: 'https://loldrivers.io/' };
  },
});

// 10. List LOLRMM
const listLolrmm = defineTool({
  name: 'list_lolrmm',
  description: 'List all known RMM (Remote Monitoring & Management) tools with their executable names and vendors. Use to build RMM allow/deny lists and T1219 detection rules.',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    ensureSeedData();
    const result = listLOLRMM();
    return { ...result, reference: 'https://lolrmm.io/' };
  },
});

// 11. List HijackLibs
const listHijacklibs = defineTool({
  name: 'list_hijacklibs',
  description: 'List all known DLL hijacking candidates. Optional filter by hijack type (Phantom, Sideloading, Search Order, Environment Variable).',
  inputSchema: {
    type: 'object',
    properties: {
      type: { type: 'string', description: 'Optional hijack type filter: "Phantom", "Sideloading", "Search Order", "Environment Variable"' },
    },
  },
  handler: async (args) => {
    ensureSeedData();
    const { type: hijackType } = args as { type?: string };

    let sql = 'SELECT name, vendor, hijack_type, vulnerable_executables FROM lolfarm_hijacklibs';
    const params: unknown[] = [];
    if (hijackType) {
      sql += ' WHERE hijack_type = ?';
      params.push(hijackType);
    }
    sql += ' ORDER BY name LIMIT 50';

    const rows = runQuery(sql, params) as Record<string, unknown>[];

    return {
      count: rows.length,
      hijacklibs: rows.map((r: Record<string, unknown>) => ({
        dll: r.name,
        vendor: r.vendor,
        type: r.hijack_type,
        vulnerable_exe_count: r.vulnerable_executables
          ? JSON.parse(r.vulnerable_executables as string).length
          : 0,
      })),
      reference: 'https://hijacklibs.net/',
    };
  },
});

// 12. get_lolfarm_context — THE KILLER TOOL (tiered response for token efficiency)
const getLolfarmContext = defineTool({
  name: 'get_lolfarm_context',
  description: 'Get LOLFarm intelligence relevant to a MITRE ATT&CK technique. Tiered response: "summary" (default, ~500 tokens — counts + top names per source) for Step 1 recon, "detailed" (~2.5k tokens — top 15 per source with key fields) when authoring, "full" (everything — use sparingly). After summary, use per-source lookup_* tools for deep-dives instead of escalating mode.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., "T1059.001", "T1562.001", "T1574.002"). Optional in summary mode — omitted technique returns a corpus-wide overview.' },
      mode: { type: 'string', enum: ['summary', 'detailed', 'full'], description: 'Response verbosity. Default "summary" for cheap recon. Escalate only when needed.' },
    },
  },
  handler: async (args) => {
    ensureSeedData();
    const { technique_id, mode = 'summary' } = args as { technique_id?: string; mode?: 'summary' | 'detailed' | 'full' };

    if (!technique_id) {
      if (mode !== 'summary') {
        return { error: 'technique_id is required for detailed or full mode. Omit it only for summary (corpus-wide counts).' };
      }
      const stats = getLOLFarmStats();
      return {
        mode: 'summary',
        scope: 'corpus',
        summary: 'LOLFarm corpus overview — no technique filter applied.',
        sources: stats,
        next_step: 'Pass technique_id (e.g., "T1059.001") to scope this to a single MITRE technique, or use lookup_loldriver / lookup_hijacklib / lookup_lolrmm / lookup_lofp / lookup_wadcom / lookup_lots_domain / lookup_malapi for per-source lookups.',
      };
    }

    const context = getLOLFarmContext(technique_id);

    const response: Record<string, unknown> = {
      technique_id: context.technique_id,
      summary: context.summary,
      mode,
    };

    // ---- SUMMARY MODE: counts + top 5 names only (~500 tokens) ----
    if (mode === 'summary') {
      const compact: Record<string, unknown> = {};
      if (context.drivers.length > 0) {
        compact.drivers = { count: context.drivers.length, top: context.drivers.slice(0, 5).map(d => d.name) };
      }
      if (context.hijacklibs.length > 0) {
        compact.hijacklibs = { count: context.hijacklibs.length, top: context.hijacklibs.slice(0, 5).map(h => h.name) };
      }
      if (context.rmm_tools.length > 0) {
        compact.rmm_tools = { count: context.rmm_tools.length, top: context.rmm_tools.slice(0, 5).map(r => r.name) };
      }
      if (context.false_positives.length > 0) {
        compact.false_positives = { count: context.false_positives.length, top: context.false_positives.slice(0, 5).map(f => f.process_name) };
      }
      if (context.wadcoms.length > 0) {
        compact.wadcoms = { count: context.wadcoms.length, top: context.wadcoms.slice(0, 5).map(w => w.name) };
      }
      if (context.lots_domains.length > 0) {
        compact.lots_domains = { count: context.lots_domains.length, top: context.lots_domains.slice(0, 5).map(l => l.domain) };
      }
      if (context.malapis.length > 0) {
        compact.malapis = { count: context.malapis.length, top: context.malapis.slice(0, 5).map(a => a.api_name) };
      }
      response.sources = compact;
      response.next_step = 'For deep-dive on any source, call lookup_loldriver / lookup_hijacklib / lookup_lolrmm / lookup_lofp / lookup_wadcom / lookup_lots_domain / lookup_malapi by name, OR re-call get_lolfarm_context with mode="detailed".';
      return response;
    }

    // ---- DETAILED MODE: top 15 per source, key fields only (~2.5k tokens) ----
    const LIMIT = mode === 'detailed' ? 15 : Number.MAX_SAFE_INTEGER;

    if (context.drivers.length > 0) {
      response.drivers = context.drivers.slice(0, LIMIT).map(d => ({
        name: d.name, category: d.category, cve: d.cve,
        hashes: mode === 'full' ? d.hashes : (d.hashes?.sha256 ? { sha256: d.hashes.sha256 } : undefined),
        description: d.description?.substring(0, mode === 'full' ? 500 : 100),
      }));
      if (context.drivers.length > LIMIT) response.drivers_truncated = `${context.drivers.length - LIMIT} more — use lookup_loldriver`;
    }
    if (context.hijacklibs.length > 0) {
      response.hijacklibs = context.hijacklibs.slice(0, LIMIT).map(h => ({
        dll: h.name, type: h.hijack_type, vendor: h.vendor,
        exe_count: h.vulnerable_executables?.length || 0,
      }));
      if (context.hijacklibs.length > LIMIT) response.hijacklibs_truncated = `${context.hijacklibs.length - LIMIT} more — use lookup_hijacklib`;
    }
    if (context.rmm_tools.length > 0) {
      response.rmm_tools = context.rmm_tools.slice(0, LIMIT).map(r => ({
        name: r.name, vendor: r.vendor,
        executables: r.executable_names,
        abused_by: mode === 'full' ? r.abuse_references : undefined,
      }));
      if (context.rmm_tools.length > LIMIT) response.rmm_tools_truncated = `${context.rmm_tools.length - LIMIT} more — use lookup_lolrmm`;
    }
    if (context.false_positives.length > 0) {
      response.false_positives = context.false_positives.slice(0, LIMIT).map(f => ({
        process: f.process_name,
        description: f.description?.substring(0, mode === 'full' ? 500 : 120),
        suppression: f.suppression_logic, confidence: f.confidence,
      }));
      if (context.false_positives.length > LIMIT) response.fp_truncated = `${context.false_positives.length - LIMIT} more — use lookup_lofp`;
    }
    if (context.wadcoms.length > 0) {
      response.wadcoms = context.wadcoms.slice(0, LIMIT).map(w => ({
        name: w.name, command: w.command, services: w.services, prerequisites: w.tools_required,
      }));
      // These rows were reached by a technique ID that belongs to the tool, not
      // necessarily to the command. Saying so here matters more than in
      // lookup_wadcom, because here the technique is what selected them.
      if (context.wadcoms.some(w => w.mitre_source)) {
        response.wadcoms_note =
          `Matched on the parent tool's ATT&CK profile rather than a per-command mapping — ` +
          'WADComs publishes none. Expect entries for the same tool that do not perform this ' +
          'technique; read the command text before using one.';
      }
      if (context.wadcoms.length > LIMIT) response.wadcoms_truncated = `${context.wadcoms.length - LIMIT} more — use lookup_wadcom`;
    }
    if (context.lots_domains.length > 0) {
      response.lots_domains = context.lots_domains.slice(0, LIMIT).map(l => ({
        domain: l.domain, service: l.service_name, category: l.category,
      }));
      if (context.lots_domains.length > LIMIT) response.lots_truncated = `${context.lots_domains.length - LIMIT} more — use lookup_lots_domain`;
    }
    if (context.malapis.length > 0) {
      response.malapis = context.malapis.slice(0, LIMIT).map(a => ({
        api: a.api_name, category: a.category,
        families: a.malware_families,
        detection: a.detection_notes?.substring(0, mode === 'full' ? 500 : 150),
      }));
      if (context.malapis.length > LIMIT) response.malapis_truncated = `${context.malapis.length - LIMIT} more — use lookup_malapi`;
    }

    return response;
  },
});

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

// 13. sync_lolfarm — pull live data from upstream sources
const syncLolfarmTool = defineTool({
  name: 'sync_lolfarm',
  description: 'Pull fresh data from LOLFarm upstream sources into the local cache. Five of the eight sources have a live feed (LOLDrivers, HijackLibs, LOLRMM, LoFP, LOLBAS); WADComs, LOTS and MalAPI publish no machine-readable data and stay on seed data — those return status "no_upstream" with the reason, which is permanent and not worth retrying. Run weekly via scheduled task — upstreams update 1-4x per month. Failures in one source never block the others. Returns per-source counts + errors.',
  inputSchema: {
    type: 'object',
    properties: {
      source: {
        type: 'string',
        enum: SYNC_SOURCES,
        description:
          `Optional: sync only one source. Omit to sync all in parallel. ` +
          `Live: ${LIVE_SYNC_SOURCES.join(', ')}. The others return no_upstream.`,
      },
    },
  },
  handler: async (args) => {
    ensureSeedData();
    const { source } = args as { source?: typeof SYNC_SOURCES[number] };
    const result = await syncLOLFarm(source);
    return {
      ...result,
      note:
        'status "failed" usually means an upstream moved or is rate-limiting — retry is reasonable. ' +
        'status "no_upstream" means no published feed exists; the reason field explains what was ' +
        'checked, and retrying will not change it. Seed data remains intact either way.',
    };
  },
});

export const lolfarmTools: ToolDefinition[] = [
  lookupLoldriver,
  lookupHijacklib,
  lookupLolrmm,
  lookupLofp,
  lookupWadcom,
  lookupLotsDomain,
  lookupMalapi,
  searchLolfarm,
  listLoldrivers,
  listLolrmm,
  listHijacklibs,
  getLolfarmContext,
  syncLolfarmTool,
];

export const lolfarmToolCount = lolfarmTools.length;
