// build_authoring_brief — one call replacing the six a rule used to need, and
// the LOLBAS rule turned from prose into a return value.
//
// Two problems, both identified by measurement rather than taste.
//
// Enforcement. CLAUDE.md says "every binary-scoped rule must enumerate all
// known abuse patterns before writing a condition". That is a sentence, and a
// sentence is a suggestion: a 3.8B-active router skips it some fraction of the
// time and nothing notices. A gate that cannot be skipped has to be something
// the model *receives* rather than something it is told — so the abuse matrix
// ships inside the brief. The model cannot write from this payload without
// having been handed the enumeration, and where the enumeration cannot be
// obtained the brief returns BLOCKED and withholds the authoring material
// instead of letting a partial rule look finished.
//
// Context. The six calls this replaces — lookup_mitre_technique, list_by_mitre,
// get_data_sources, get_lolfarm_context, lookup_lolbas,
// get_query_language_spec — measured ~6,000 tokens together, over a third of
// the 16,384-token window vLLM's own Gemma 4 recipe recommends. A composite
// that returned the union of its parts would make that worse. So this returns
// references rather than bodies: rule identifiers and their logsource, not
// their queries; blocking prohibitions, not worked examples. get_detection and
// get_query_language_spec stay available for when depth is actually needed.

import { runQuery } from '../../db/connection.js';
import { getLOLBAS, type LOLBASEntry } from '../../db/threat-intel.js';
import { getDataSourcesForTechnique } from '../../db/mitre-attack.js';
import { getLoFP, getLOLFarmContext } from '../../db/lolfarm.js';
import { SPECS, type LanguageId } from '../../reference/query-languages/index.js';
import {
  CATEGORY_SOURCES, FIELD_MAPPINGS, UNMAPPED_CATEGORIES,
} from '../../reference/query-languages/field-mappings.js';
import { resolveLimit } from '../../config/limits.js';

export type Gate = 'OK' | 'CAVEATS' | 'BLOCKED';

interface TechniqueRow {
  id: string;
  name: string;
  tactics: string | null;
  platforms: string | null;
  detection: string | null;
  is_deprecated: number;
}

interface RuleRow {
  id: string;
  name: string;
  source_type: string;
  severity: string | null;
  logsource_category: string | null;
  logsource_product: string | null;
  process_names: string | null;
  data_sources: string | null;
  false_positives: string | null;
}

/**
 * Enrichment columns hold JSON on most rows and comma-separated text on some,
 * depending on which indexer wrote them. Both are read rather than only the
 * shape that happens to dominate.
 */
function parseArr(v: string | null | undefined): string[] {
  if (!v) return [];
  try {
    const p = JSON.parse(v);
    if (Array.isArray(p)) return p.filter((x): x is string => typeof x === 'string' && Boolean(x));
    if (typeof p === 'string' && p) return [p];
    return [];
  } catch {
    return String(v).split(',').map(s => s.trim()).filter(Boolean);
  }
}

/** Most frequent value — used to infer rule shape from real rules, not from recall. */
function majority(values: string[]): string | null {
  if (values.length === 0) return null;
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

/**
 * Binaries the existing rules for this technique are scoped to, most-referenced
 * first.
 *
 * Read from the `process_names` column the indexer extracts, so this reflects
 * what real detections actually watch. That matters: it means the gate fires on
 * evidence from the corpus rather than on the model volunteering that a
 * technique involves a LOLBIN.
 */
function implicatedBinaries(rules: RuleRow[]): string[] {
  const counts = new Map<string, number>();
  for (const r of rules) {
    for (const p of parseArr(r.process_names)) {
      const name = p.toLowerCase().replace(/^.*[\\/]/, '').trim();
      if (/\.(exe|dll|com|scr)$/.test(name)) counts.set(name, (counts.get(name) ?? 0) + 1);
    }
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([n]) => n);
}

/** One binary's documented abuse patterns, flattened for reading. */
function abuseMatrix(entry: LOLBASEntry) {
  const commands = entry.commands ?? [];
  return {
    binary: entry.name,
    description: entry.description?.slice(0, 200) || undefined,
    paths: (entry.full_path ?? []).slice(0, 4),
    techniques: entry.mitre_techniques ?? [],
    pattern_count: commands.length,
    // The gate's actual content. A condition covering one of these and not the
    // others is a rule an attacker walks around using a different documented
    // invocation of the same signed binary.
    abuse_patterns: commands.map(c => c.slice(0, 220)),
    detection_notes: entry.detection?.slice(0, 300) || undefined,
    references: (entry.resources ?? []).slice(0, 3),
  };
}

export interface BriefArgs {
  technique_id: string;
  language: LanguageId;
  binary?: string;
  max_rules?: number;
  require_lolbas?: boolean;
}

export function buildAuthoringBrief(args: BriefArgs): Record<string, unknown> {
  const tid = String(args.technique_id ?? '').trim().toUpperCase();
  const lang = args.language;
  const spec = SPECS[lang];
  const blockers: string[] = [];
  const caveats: string[] = [];

  // --- 1. The technique -----------------------------------------------------
  const tech = runQuery<TechniqueRow>(
    `SELECT id, name, tactics, platforms, detection, is_deprecated
     FROM mitre_techniques_full
     WHERE id = ? OR external_id = ?
     LIMIT 1`,
    [tid, tid]
  )[0];

  if (!tech) {
    return {
      gate: 'BLOCKED' as Gate,
      technique_id: tid,
      blockers: [
        `${tid} is not in the local ATT&CK data. Confirm the ID with search_mitre_techniques ` +
        'before authoring — a rule written against a technique that does not exist cannot be ' +
        'mapped, reviewed or deployed.',
      ],
      next_step: 'Resolve the technique ID first. Do not write a rule from this brief.',
    };
  }
  if (tech.is_deprecated) {
    caveats.push(
      `${tid} is deprecated in ATT&CK. Check whether a replacement technique supersedes it before ` +
      'deploying anything mapped to it.'
    );
  }

  // --- 2. Reference rules ---------------------------------------------------
  const limit = resolveLimit(args.max_rules, 12);
  const rules = runQuery<RuleRow>(
    `SELECT id, name, source_type, severity, logsource_category, logsource_product,
            process_names, data_sources, false_positives
     FROM detections
     WHERE mitre_techniques LIKE ?
     ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 ELSE 3 END
     LIMIT ?`,
    [`%${tid}%`, limit]
  );

  const category = majority(
    rules.map(r => r.logsource_category).filter((c): c is string => Boolean(c))
  );

  // --- 3. The LOLBAS gate ---------------------------------------------------
  const requireLolbas = args.require_lolbas !== false;
  const named = String(args.binary ?? '').trim().toLowerCase();
  const fromRules = implicatedBinaries(rules).slice(0, 3);
  const candidates = named ? [named] : fromRules;

  const matrices: Array<ReturnType<typeof abuseMatrix>> = [];
  const unknownBinaries: string[] = [];
  for (const b of candidates) {
    const entry = getLOLBAS(b) ?? getLOLBAS(b.replace(/\.(exe|dll|com|scr)$/, ''));
    if (entry) matrices.push(abuseMatrix(entry));
    else unknownBinaries.push(b);
  }

  if (named && matrices.length === 0) {
    if (requireLolbas) {
      blockers.push(
        `A rule scoped to "${named}" was requested, and there is no LOLBAS entry for it — so its ` +
        'known abuse patterns cannot be enumerated. A binary-scoped condition written now would ' +
        'cover whichever invocation came to mind rather than all of them, and would look ' +
        `complete while doing it. Either confirm "${named}" is not a living-off-the-land binary ` +
        'and call again with require_lolbas=false, or scope the detection behaviourally instead ' +
        'of by image name.'
      );
    } else {
      caveats.push(
        `No LOLBAS entry for "${named}", and require_lolbas=false was passed. State in the output ` +
        'that the abuse matrix is unverified — do not present the rule as covering all patterns.'
      );
    }
  }
  if (!named && unknownBinaries.length > 0 && matrices.length > 0) {
    caveats.push(
      `Reference rules also watch ${unknownBinaries.join(', ')}, which have no LOLBAS entry, so ` +
      'their abuse patterns are not enumerated here.'
    );
  }

  // --- 4. Telemetry ---------------------------------------------------------
  const attackSources = (getDataSourcesForTechnique(tid) as Array<Record<string, unknown>>)
    .map(d => String(d.name ?? d.data_source ?? '').trim())
    .filter(Boolean);
  const corpusSources = [...new Set(rules.flatMap(r => parseArr(r.data_sources)))].slice(0, 8);

  if (rules.length === 0 && attackSources.length === 0) {
    blockers.push(
      `Nothing grounds a rule for ${tid}: no detection in the corpus references it, and ATT&CK ` +
      'lists no data sources for it in the local data. Writing one now would be recall rather ' +
      'than evidence. Widen to the parent technique, or report that there is no coverage to ' +
      'build on.'
    );
  } else if (rules.length === 0) {
    caveats.push(
      `No existing detection references ${tid}. That is a real coverage gap and worth saying — ` +
      'but it also means there is no reference rule to check field choices against, so the field ' +
      'names in your query are unverified until validate_query confirms them.'
    );
  }

  // --- 5. Known false positives --------------------------------------------
  // What legitimately trips a rule for this technique. The most common thing
  // missing from a generated rule, and the reason SOCs disable them.
  const lofp = getLoFP(tid).slice(0, 8).map(f => f.description);
  const ruleFps = [...new Set(rules.flatMap(r => parseArr(r.false_positives)))].slice(0, 6);

  // --- 6. Living-off-the-land context beyond LOLBAS -------------------------
  let lolfarm: Record<string, unknown> | undefined;
  try {
    const ctx = getLOLFarmContext(tid);
    const parts: Record<string, unknown> = {};
    if (ctx.drivers.length) parts.vulnerable_drivers = ctx.drivers.slice(0, 3).map(d => d.name);
    if (ctx.hijacklibs.length) parts.hijackable_dlls = ctx.hijacklibs.slice(0, 3).map(h => h.name);
    if (ctx.rmm_tools.length) parts.rmm_tools = ctx.rmm_tools.slice(0, 3).map(r => r.name);
    if (Object.keys(parts).length > 0) lolfarm = parts;
  } catch {
    // LOLFarm tables can be empty on a fresh database. Their absence is not a
    // reason to fail the brief.
  }

  // --- 7. Target language ---------------------------------------------------
  const targetSource = category ? CATEGORY_SOURCES[category]?.[lang] ?? null : null;
  const fieldTable = category ? FIELD_MAPPINGS[category] : undefined;
  const vocabulary = fieldTable
    ? Object.entries(fieldTable)
        .map(([sigmaField, t]) => [sigmaField, t[lang]] as const)
        .filter(([, to]) => typeof to === 'string' && to.length > 0)
        .slice(0, 24)
        .map(([sigmaField, to]) => `${sigmaField} -> ${to}`)
    : [];

  if (category && UNMAPPED_CATEGORIES[category]) {
    caveats.push(
      `Category "${category}" is deliberately unmapped: ${UNMAPPED_CATEGORIES[category]} ` +
      'Choose the target source yourself, then validate it.'
    );
  } else if (!targetSource) {
    caveats.push(
      category
        ? `No ${lang.toUpperCase()} source is mapped for category "${category}". Determine the ` +
          'correct table, data model or event yourself, then validate.'
        : 'No logsource category could be inferred from the reference rules, so no target source ' +
          'was selected. Identify which telemetry this detection reads before writing it.'
    );
  }

  const gate: Gate = blockers.length > 0 ? 'BLOCKED' : caveats.length > 0 ? 'CAVEATS' : 'OK';

  // A blocked brief withholds the authoring material deliberately. Returning it
  // anyway next to a BLOCKED flag would make the flag advisory, which is
  // precisely the failure this tool exists to prevent.
  if (gate === 'BLOCKED') {
    return {
      gate,
      technique_id: tid,
      technique: tech.name,
      blockers,
      ...(caveats.length > 0 ? { caveats } : {}),
      next_step:
        'Do not write a query from this brief — the material needed to write a correct one has ' +
        'been withheld. Resolve every blocker, then call build_authoring_brief again. If a ' +
        'blocker cannot be resolved, report the gap rather than producing a rule that looks ' +
        'complete.',
    };
  }

  return {
    gate,
    ...(caveats.length > 0 ? { caveats } : {}),

    technique: {
      id: tid,
      name: tech.name,
      tactics: parseArr(tech.tactics),
      platforms: parseArr(tech.platforms),
      attack_detection_guidance: tech.detection?.slice(0, 600) || undefined,
    },

    shape: category ?? 'unknown',

    // Identifiers, not bodies — this is where the token budget is saved.
    reference_rules: {
      count: rules.length,
      note: rules.length > 0
        ? 'Identifiers only. Call get_detection(id) for the condition logic of any rule worth ' +
          'modelling on.'
        : 'No existing coverage for this technique in the corpus.',
      rules: rules.map(r => ({
        id: r.id,
        name: r.name.slice(0, 90),
        source: r.source_type,
        severity: r.severity ?? undefined,
        logsource: [r.logsource_product, r.logsource_category].filter(Boolean).join('/') || undefined,
      })),
    },

    // The gate's payload, present whenever a binary is in scope. This is what
    // makes "enumerate every abuse pattern" impossible to skip rather than
    // merely mandatory.
    lolbas_gate: {
      status: matrices.length > 0 ? 'matrix supplied' : 'no binary in scope',
      binaries_in_scope: candidates,
      requirement:
        'A binary-scoped condition must account for every pattern below, not only the common ' +
        'one. An attacker reading the same list uses the invocation the rule missed.',
      matrices,
      ...(unknownBinaries.length > 0 ? { no_lolbas_entry: unknownBinaries } : {}),
    },

    telemetry: {
      attack_data_sources: attackSources.slice(0, 8),
      corpus_data_sources: corpusSources,
      note: 'Confirm the target environment actually collects these before deploying.',
    },

    known_false_positives: {
      from_lofp: lofp,
      from_reference_rules: ruleFps,
      note: lofp.length > 0 || ruleFps.length > 0
        ? 'Build exclusions from these. A rule with no false-positive handling gets turned off.'
        : 'None recorded for this technique — which means unmeasured, not zero.',
    },

    ...(lolfarm ? { lolfarm_context: lolfarm } : {}),

    target: {
      language: spec.id,
      name: spec.name,
      confidence: spec.confidence,
      source: targetSource,
      field_vocabulary: vocabulary,
      blocking_prohibitions: spec.prohibitions
        .filter(p => p.severity === 'blocking')
        .map(p => `${p.id}: ${p.title} — ${p.reason}`),
      note: `Call get_query_language_spec("${lang}") for operators, cost model and worked examples.`,
    },

    next_step:
      `Write one ${spec.name} query. Use only the names in target.field_vocabulary, cover every ` +
      'pattern in lolbas_gate.matrices, exclude the known false positives, then call ' +
      `validate_query(query, "${lang}"). Do not present the query before it validates.`,
  };
}
