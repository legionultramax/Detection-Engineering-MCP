// Deterministic validation of a generated query.
//
// This exists because a model cannot be made to never hallucinate a field name,
// and the goal is therefore not to prevent that but to make it fail loudly. A
// wrong field name produces a query that parses, submits, runs and returns zero
// rows, which is indistinguishable from "no malicious activity". A blocking
// error is a strictly better outcome.
//
// Nothing here asks a model anything. Every check is a regex or a set lookup.

import {
  SPECS, extract, locallyDefinedNames, classifyAqlProperties, type LanguageId,
} from '../../reference/query-languages/index.js';
import { AQL_EVENT_PROPERTIES, AQL_TABLES } from '../../reference/query-languages/aql.js';
import { getFieldCatalog, getCatalogError, nearest } from '../../reference/field-catalog/load.js';

export type Severity = 'blocking' | 'warning';

/**
 * Where the query is going, which changes what counts as an error.
 *
 * Only AQL uses this, and only for the two rules that encode the hunt
 * backend's behaviour rather than the language's. A query bound for the Phase 2
 * pipeline must not carry its own START/STOP or domainId, because the backend
 * appends both; a query being pasted into the QRadar console must carry a time
 * bound or it scans everything. Both are true, and a validator that enforced
 * one of them unconditionally would be wrong half the time.
 */
export type SubmissionContext = 'hunt-pipeline' | 'standalone';

/** Rules that only apply when the hunt backend is going to rewrite the query. */
const PIPELINE_ONLY_RULES = new Set(['aql.time-bound-in-query', 'aql.domain-id-in-query']);

export interface Finding {
  kind: string;
  severity: Severity;
  title: string;
  reason: string;
  fix?: string;
  /** The offending token, where there is one. */
  subject?: string;
  /** Closest known names, for an unknown field or source. */
  suggestions?: string[];
}

export interface ValidationResult {
  language: LanguageId;
  /** AQL only — echoed so a caller can see which rule set was applied. */
  submissionContext?: SubmissionContext;
  valid: boolean;
  blocking: Finding[];
  warnings: Finding[];
  /** What the validator understood the query to reference. */
  observed: { sources: string[]; fields: string[]; macros: string[]; customProperties?: string[] };
  /** Per-field confidence, so a caller can label output honestly. */
  confidence: {
    tier: 'confirmed' | 'community' | 'unconfirmed';
    note: string;
    unverifiedFields: string[];
  };
  /** Where to check anything this validator asserts. */
  authority: string;
  catalogAvailable: boolean;
}

/** Cap the number of same-kind findings so one bad query cannot flood a response. */
const MAX_PER_KIND = 8;

export function validateQuery(
  query: string,
  language: LanguageId,
  submissionContext: SubmissionContext = 'hunt-pipeline'
): ValidationResult {
  const spec = SPECS[language];
  const catalog = getFieldCatalog();
  const observed = extract(query, language);
  const local = locallyDefinedNames(query, language);
  const blocking: Finding[] = [];
  const warnings: Finding[] = [];
  const unverifiedFields: string[] = [];

  const push = (f: Finding) => {
    const bucket = f.severity === 'blocking' ? blocking : warnings;
    if (bucket.filter(x => x.kind === f.kind).length >= MAX_PER_KIND) return;
    bucket.push(f);
  };

  // --- 1. Spec prohibitions ------------------------------------------------
  // Pure pattern rules, defined alongside the language they constrain.
  for (const p of spec.prohibitions) {
    // Two AQL rules describe the hunt backend, not the language. Outside that
    // pipeline they are not merely irrelevant — enforcing the time-bound rule
    // on a console query would reject the one thing that query must have.
    if (submissionContext === 'standalone' && PIPELINE_ONLY_RULES.has(p.id)) continue;

    let re: RegExp;
    try {
      re = new RegExp(p.pattern, p.flags ?? '');
    } catch {
      continue; // a malformed rule must not break validation
    }
    const hit = re.test(query);
    const fires = p.invert ? !hit : hit;
    if (!fires) continue;

    // For non-inverted rules, report what actually matched — a model correcting
    // a query needs the offending text, not just the rule name.
    let subject: string | undefined;
    if (!p.invert) {
      const m = query.match(new RegExp(p.pattern, (p.flags ?? '').replace('g', '')));
      subject = m?.[0]?.trim().slice(0, 120);
    }
    push({
      kind: p.id, severity: p.severity, title: p.title,
      reason: p.reason, fix: p.fix, subject,
    });
  }

  // --- 2. Source validation (table / data model / event) -------------------
  //
  // AQL is checked first and separately because it is the one language here
  // with no corpus behind it. The derived catalog cannot help — there are zero
  // AQL rules to derive from — so the check is against QRadar's own normalised
  // schema, which is the part of Ariel that is identical in every deployment.
  if (language === 'aql') {
    for (const s of observed.sources) {
      if (!AQL_TABLES.includes(s)) {
        push({
          kind: 'unknown_ariel_table', severity: 'blocking',
          title: `Unknown Ariel table: ${s}`,
          reason:
            `Ariel has exactly two tables, ${AQL_TABLES.join(' and ')}. ${s} is neither, so this ` +
            'query cannot run. A table name borrowed from another SIEM is the usual cause.',
          fix: 'Select FROM events for log telemetry, or FROM flows for QRadar network flows.',
          subject: s,
          suggestions: nearest(s, [...AQL_TABLES]),
        });
      }
    }

    const { unknown } = classifyAqlProperties(observed.fields, local);
    for (const f of unknown) {
      push({
        kind: 'unknown_ariel_property', severity: 'blocking',
        title: `Not a normalised Ariel property: ${f}`,
        reason:
          `${f} is written as a bare identifier, which Ariel resolves against QRadar's ` +
          'normalised schema — and it is not in it. If this is meant to be a Custom Event ' +
          'Property it must be double-quoted, and unquoted it will not resolve.',
        fix: `Quote it as "${f}" if it is a custom property, or use a normalised property.`,
        subject: f,
        suggestions: nearest(f, [...AQL_EVENT_PROPERTIES]),
      });
    }

    // Every CEP the query names. Not an error — it is how QRadar carries
    // endpoint telemetry — but it is the single most likely reason a
    // syntactically perfect AQL query returns nothing, so it is always said.
    const ceps = observed.customProperties ?? [];
    if (ceps.length > 0) {
      unverifiedFields.push(...ceps);
      push({
        kind: 'custom_event_properties', severity: 'warning',
        title: `${ceps.length} Custom Event Propert${ceps.length === 1 ? 'y' : 'ies'} referenced`,
        reason:
          `${ceps.map(c => `"${c}"`).join(', ')} — these are not part of QRadar. Each is a regex ` +
          'or JSON extraction configured per log source in the target deployment, so the names ' +
          'are conventions rather than facts. An unconfigured or differently-named property is ' +
          'null rather than an error, which means the query runs, returns zero rows, and looks ' +
          'exactly like a clean environment.',
        fix:
          'Confirm each name against the deployment\'s custom property list before treating a ' +
          'zero-row result as evidence of absence. Where a property is missing, TEXT SEARCH over ' +
          'the payload finds the events without needing it.',
      });
    }
  } else if (catalog) {
    if (language === 'kql') {
      const known = Object.keys(catalog.kql.tables);
      const core = new Set(Object.keys(catalog.kql.coreTables));
      for (const s of observed.sources) {
        if (!known.includes(s)) {
          push({
            kind: 'unknown_table', severity: 'blocking',
            title: `Unknown table: ${s}`,
            reason:
              `${s} does not appear in any of the ${catalog.kql.source}. It may not exist, or ` +
              'may belong to a solution this workspace has not installed.',
            fix: 'Use a table the corpus references, or confirm it exists in the target workspace.',
            subject: s,
            suggestions: nearest(s, known),
          });
        } else if (!core.has(s)) {
          push({
            kind: 'solution_specific_table', severity: 'warning',
            title: `${s} is solution-specific`,
            reason:
              `${s} appears in the corpus but is not a first-party table. It exists only in ` +
              'workspaces that installed the corresponding solution, so elsewhere this query ' +
              'returns nothing — the same silent failure as a wrong field name.',
            fix: 'Confirm the target workspace has that solution, or use a core table.',
            subject: s,
          });
        }
      }
    }

    if (language === 'spl') {
      const known = Object.keys(catalog.spl.dataModels);
      for (const s of observed.sources) {
        if (!known.includes(s)) {
          push({
            kind: 'unknown_datamodel', severity: 'warning',
            title: `Data model not seen in the corpus: ${s}`,
            reason:
              `${s} is not among the ${known.length} CIM data models the ESCU corpus queries. ` +
              'It may still exist in the target Splunk, but nothing here corroborates it.',
            subject: s,
            suggestions: nearest(s, known),
          });
        }
      }
      // Macros: the dominant SPL failure mode.
      for (const name of observed.macros) {
        const m = catalog.spl.macros[name];
        if (name.endsWith('_filter')) {
          push({
            kind: 'escu_filter_macro', severity: 'warning',
            title: `Per-detection filter macro: ${name}`,
            reason:
              'ESCU detections end with a whitelist hook that is empty by default and defined ' +
              'only where that detection is installed.',
            fix: 'Omit it when porting the search, or define it in the target Splunk.',
            subject: name,
          });
        } else if (m?.kind === 'external') {
          push({
            kind: 'external_macro', severity: 'blocking',
            title: `Macro ships outside the rules: ${name}`,
            reason: m.note ?? 'Defined in a Splunk app rather than the detection content.',
            fix:
              name === 'drop_dm_object_name'
                ? 'Replace with | rename "Model.*" as * so the search does not need Splunk_SA_CIM.'
                : 'Confirm the target Splunk has the providing app installed.',
            subject: name,
          });
        } else if (m?.kind === 'datasource') {
          unverifiedFields.push(name);
          push({
            kind: 'datasource_macro', severity: 'warning',
            title: `Environment-specific macro: ${name}`,
            reason:
              `Expands by default to ${String(m.expansion).slice(0, 90)} — but ESCU's own ` +
              'description says to replace it with the target environment\'s indexes and ' +
              'sourcetypes. The expansion is a default, not a fact about any deployment.',
            fix: 'Confirm the macro is defined for the target Splunk, or inline its real value.',
            subject: name,
          });
        } else if (!m) {
          push({
            kind: 'unknown_macro', severity: 'blocking',
            title: `Unknown macro: ${name}`,
            reason: 'No definition for this macro exists in the corpus or the macro directory.',
            fix: 'Expand it inline, or remove it.',
            subject: name,
            suggestions: nearest(name, Object.keys(catalog.spl.macros)),
          });
        }
      }
    }

    if (language === 'cql') {
      const events = catalog.cql.events;
      for (const s of observed.sources) {
        const e = events[s];
        if (!e) {
          push({
            kind: 'unknown_event', severity: 'blocking',
            title: `Unknown event_simpleName: ${s}`,
            reason:
              `${s} is not among the ${catalog.cql.eventCount} events in the vendored Falcon ` +
              'dictionary. Event names are case-sensitive PascalCase.',
            fix: 'Use a known event name, and verify against the official sensor map.',
            subject: s,
            suggestions: nearest(s, Object.keys(events)),
          });
          continue;
        }
        if (!e.documented) {
          push({
            kind: 'undocumented_event', severity: 'warning',
            title: `${s} has no description in the dictionary`,
            reason:
              '337 of the 998 events are undocumented in the source extraction. The name being ' +
              'listed is not evidence that the event does what it sounds like.',
            fix: 'Verify against the official sensor map before relying on this.',
            subject: s,
          });
        }
        if (e.platforms.length && !e.platforms.some(p => /windows|linux|macos|container/i.test(p))) {
          push({
            kind: 'narrow_platform_event', severity: 'warning',
            title: `${s} is listed for ${e.platforms.join(', ')} only`,
            reason:
              'If the detection targets endpoints, an event scoped to mobile or a niche sensor ' +
              'environment will not fire. Note that the dictionary contains extraction errors in ' +
              'this column, so confirm rather than trusting it either way.',
            subject: s,
          });
        }
        if (s === 'ProcessRollup2') {
          push({
            kind: 'platform_scope_hint', severity: 'warning',
            title: 'ProcessRollup2 is listed Windows-only',
            reason:
              'A Linux or macOS process rule written against ProcessRollup2 returns nothing.',
            fix: 'Use SyntheticProcessRollup2 for cross-platform process telemetry.',
            subject: s,
          });
        }
      }
    }

    // --- 3. Field validation ----------------------------------------------
    if (language === 'kql') {
      const globalFields = new Set(Object.keys(catalog.kql.fields));
      for (const f of observed.fields) {
        // Names the query binds for itself — summarize aliases, extend, project,
        // let — are not columns and must not be checked against the catalog.
        if (local.has(f)) continue;
        const perTable = observed.sources
          .map(s => catalog.kql.tableFields[s])
          .filter(Boolean) as Array<Record<string, number>>;
        const inSomeTable = perTable.some(t => f in t);
        if (inSomeTable) continue;
        if (globalFields.has(f)) {
          // Real field, but not one the corpus associates with this table —
          // the "right field, wrong table" case a flat list cannot catch.
          if (perTable.length > 0) {
            push({
              kind: 'field_table_mismatch', severity: 'warning',
              title: `${f} is not a known column of ${observed.sources.join(', ')}`,
              reason:
                `${f} appears elsewhere in the corpus but not on this table. If the column does ` +
                'not exist on it, the predicate silently matches nothing.',
              subject: f,
              suggestions: nearest(f, Object.keys(perTable[0] ?? {})),
            });
          }
          continue;
        }
        push({
          kind: 'unknown_field', severity: 'blocking',
          title: `Unknown field: ${f}`,
          reason:
            `${f} does not appear in ${catalog.kql.source} at the required support threshold. ` +
            'A non-existent column makes the query return zero rows rather than error.',
          subject: f,
          suggestions: nearest(f, [
            ...Object.keys(catalog.kql.tableFields[observed.sources[0]] ?? {}),
            ...Object.keys(catalog.kql.fields),
          ]),
        });
      }
    }

    if (language === 'spl') {
      const known = new Set(Object.keys(catalog.spl.fields));
      for (const f of observed.fields) {
        if (local.has(f)) continue;
        if (!known.has(f)) {
          push({
            kind: 'unknown_cim_field', severity: 'warning',
            title: `CIM field not seen in the corpus: ${f}`,
            reason:
              `${f} is not among the ${known.size} model-qualified fields the ESCU corpus uses. ` +
              'It may exist in the target CIM version; nothing here corroborates it.',
            subject: f,
            suggestions: nearest(f, [...known]),
          });
        }
      }
    }
  } else {
    push({
      kind: 'catalog_unavailable', severity: 'warning',
      title: 'Field catalog not available — field checks skipped',
      reason:
        `The derived catalog could not be loaded${getCatalogError() ? `: ${getCatalogError()}` : ''}. ` +
        'Prohibition checks still ran, but nothing verified that the tables and fields exist.',
      fix: 'Run npm run catalog:build.',
    });
  }

  // --- 4. Confidence ------------------------------------------------------
  const tier = spec.confidence;
  const note =
    tier === 'confirmed'
      ? 'Tables and fields are corroborated by rules in the local corpus.'
      : tier === 'community'
        ? 'Event names come from an unofficial community extraction. Verify against the ' +
          'authority link before relying on this in production.'
        : language === 'aql'
          ? 'There are no AQL rules in the corpus, so nothing here is corroborated. Normalised ' +
            'Ariel properties were checked against QRadar\'s own schema; every quoted Custom ' +
            'Event Property is a per-deployment convention that only the target installation ' +
            'can confirm.'
          : 'Field names are conventional guesses and have not been verified against a deployment.';

  return {
    language,
    ...(language === 'aql' ? { submissionContext } : {}),
    valid: blocking.length === 0,
    blocking,
    warnings,
    observed,
    confidence: { tier, note, unverifiedFields },
    authority: spec.authority,
    // AQL never consults the derived catalog, so reporting its availability
    // would imply a check that did not happen either way.
    catalogAvailable: language === 'aql' ? false : Boolean(catalog),
  };
}
