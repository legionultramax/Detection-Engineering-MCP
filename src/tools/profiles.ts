// Tool profiles — scoping the exposed tool surface per deployment.
//
// The registry holds 132 tools. That is fine for Claude Desktop, which routes
// well across a large surface, and it is the wrong shape for a small local
// model: Gemma 4 26B-A4B is 26B total but only 4B active, and the failure mode
// is discrimination, not context. The full `tools/list` payload is 66 KB — on
// the order of 19,000 tokens, about 15% of a 128K window — so there is room. But
// eleven `lookup_*` LOLFarm tools, thirteen `otx_*`/`threatfox_*`/`bazaar_*`
// variants, and four different plausible answers to "find me rules for
// credential dumping" degrade a 4B-active router long before it runs out of room.
//
// Profiles are opt-in. With HAWKEYE_TOOL_PROFILE unset the server exposes
// everything, exactly as it always has.

export interface ToolProfile {
  description: string;
  /** Allowlist. When present, exactly these tools are exposed. */
  include?: readonly string[];
  /** Denylist, applied only when `include` is absent. */
  exclude?: readonly string[];
}

/**
 * Tools that mutate the database. Enumerated for the `research` profile below.
 *
 * This is a convenience, not a safety boundary — HAWKEYE_READONLY is the
 * authoritative guard and it covers every write path including ones no tool
 * reaches directly. If this list drifts, read-only mode still holds.
 */
export const WRITE_TOOLS: readonly string[] = [
  'create_entity',
  'create_relation',
  'log_decision',
  'add_learning',
  'coverage_ingest_log',
  'coverage_assess_session',
  'sublime_sync',
  'sync_lolfarm',
];

export const PROFILES: Record<string, ToolProfile> = {
  /**
   * Phase 1 hypothesis authoring: everything needed to ground a detection
   * hypothesis in real data, and nothing else.
   *
   * Deliberately absent: the fifteen threat-intel vendor tools (network-bound,
   * slow, and not needed to author a query), every knowledge-graph write, the
   * report generators — `generate_hunt_report` alone is 3,899 bytes, 6% of the
   * entire tool surface, and belongs to Phase 3 — and `sync_lolfarm`, which
   * runs on a schedule rather than interactively.
   */
  'phase1-authoring': {
    description: 'Detection hypothesis authoring — grounding tools only (27 tools)',
    include: [
      // Existing rules as grounding
      'search_detections',
      'get_detection',
      'list_by_mitre',
      'list_by_mitre_tactic',
      'list_by_severity',
      // Enrichment-backed, and only usable since the corpus was re-indexed.
      // These filter on columns the indexer extracts (process_names,
      // logsource_category), which were empty on every row while the index was
      // partial — each returned zero for every input. A tool that always answers
      // with silence teaches the model there is no coverage, so they were held
      // out until the data existed. Verified against the current index:
      // powershell.exe, certutil.exe and rundll32.exe all return matches.
      'list_by_process_name',
      'list_by_logsource',
      // Still held out: list_by_cve and list_by_data_source. cves is populated
      // on only 204 of 13,942 rows, too sparse to be worth a routing slot.
      // Technique truth
      'lookup_mitre_technique',
      'search_mitre_techniques',
      'get_data_sources',
      'get_mitigations',
      'get_groups_using_technique',
      // Actor context
      'get_threat_group',
      'search_threat_groups',
      // Living-off-the-land abuse patterns
      'lookup_lolbas',
      'get_lolfarm_context',
      // Coverage framing
      'analyze_coverage',
      'identify_gaps',
      'get_stats',
      // Vulnerability context. epss_score_lookup and misp_warninglist_check are
      // here because CLAUDE.md's quality gates name them: EPSS + KEV is
      // blocking for any CVE, and WAT-21 requires the warninglist check before
      // IOC pivoting. A gate that names a tool the profile withholds is a gate
      // that cannot be satisfied, which is worse than a larger profile.
      //
      // All four reach the network, so on a host without outbound HTTPS they
      // fail visibly rather than returning nothing. That is the right trade:
      // an error says "this check did not happen", an absent tool says nothing.
      'nvd_cve_lookup',
      'epss_score_lookup',
      'check_cisa_kev',
      'misp_warninglist_check',
      // Translation grounding
      'convert_sigma_to_kql',
      // Query-language authoring. get_query_language_spec supplies the target
      // language's vocabulary and prohibitions; validate_query is the
      // deterministic gate that must run before any query is presented.
      'get_query_language_spec',
      'validate_query',
      'translate_detection',
    ],
  },

  /**
   * Everything except writes. Defined by exclusion so new read-only tools are
   * picked up automatically rather than needing to be added here.
   */
  research: {
    description: 'All read-only tools — full research surface, no mutations',
    exclude: WRITE_TOOLS,
  },

  /** The historical default. Present so it can be named explicitly. */
  full: {
    description: 'Every registered tool (default)',
  },
};

export class UnknownProfileError extends Error {
  constructor(name: string) {
    super(
      `Unknown tool profile "${name}". Available: ${Object.keys(PROFILES).join(', ')}. ` +
      'Unset HAWKEYE_TOOL_PROFILE to expose every tool.'
    );
    this.name = 'UnknownProfileError';
  }
}

/**
 * Resolve a profile name to the set of tool names it exposes.
 *
 * Returns `null` for "no filtering" — an unset name, or `full`.
 *
 * Throws on an unrecognised name rather than falling back to the full surface.
 * A typo in HAWKEYE_TOOL_PROFILE silently exposing all 129 tools is precisely
 * the outcome this feature exists to prevent, so it fails loudly instead.
 *
 * @param name       Profile name, typically from HAWKEYE_TOOL_PROFILE.
 * @param allNames   Every registered tool name, needed to apply an exclusion.
 */
export function resolveProfile(
  name: string | undefined,
  allNames: readonly string[]
): string[] | null {
  const key = (name ?? '').trim();
  if (key === '' || key === 'full') return null;

  const profile = PROFILES[key];
  if (!profile) throw new UnknownProfileError(key);

  if (profile.include) return [...profile.include];

  if (profile.exclude) {
    const denied = new Set(profile.exclude);
    return allNames.filter(n => !denied.has(n));
  }

  return null;
}

/**
 * Names a profile lists that the registry does not actually hold.
 *
 * A profile referencing a tool that has been renamed or removed would quietly
 * expose fewer tools than intended, so callers should surface this rather than
 * let the surface shrink unnoticed.
 */
export function unresolvedNames(
  name: string | undefined,
  allNames: readonly string[]
): string[] {
  const key = (name ?? '').trim();
  if (key === '' || key === 'full') return [];
  const profile = PROFILES[key];
  if (!profile?.include) return [];
  const known = new Set(allNames);
  return profile.include.filter(n => !known.has(n));
}
