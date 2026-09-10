// Language spec registry, and the per-language extraction used by validation.
//
// Extraction lives next to the specs rather than in the validator because it is
// a property of the language: how you find a table reference in KQL is not how
// you find one in SPL, and both belong with the language they describe.

import type { LanguageSpec } from './types.js';
import { KQL_SPEC } from './kql.js';
import { SPL_SPEC } from './spl.js';
import { CQL_SPEC } from './cql.js';
import { AQL_SPEC, AQL_EVENT_PROPERTIES, AQL_FUNCTIONS } from './aql.js';

export type LanguageId = 'kql' | 'spl' | 'cql' | 'aql';

export const SPECS: Record<LanguageId, LanguageSpec> = {
  kql: KQL_SPEC,
  spl: SPL_SPEC,
  cql: CQL_SPEC,
  aql: AQL_SPEC,
};

export const LANGUAGE_IDS: LanguageId[] = ['kql', 'spl', 'cql', 'aql'];

/** Accepts the aliases people actually type. */
export function normaliseLanguage(input: string): LanguageId | null {
  const s = String(input ?? '').trim().toLowerCase();
  const map: Record<string, LanguageId> = {
    kql: 'kql', kusto: 'kql', sentinel: 'kql', defender: 'kql', 'azure-monitor': 'kql',
    spl: 'spl', splunk: 'spl', escu: 'spl',
    cql: 'cql', crowdstrike: 'cql', logscale: 'cql', humio: 'cql', falcon: 'cql',
    aql: 'aql', ariel: 'aql', qradar: 'aql', qsip: 'aql',
  };
  return map[s] ?? null;
}

export interface Extraction {
  /** Table (KQL), data model (SPL), event_simpleName (CQL), or Ariel table (AQL). */
  sources: string[];
  /** Field references, as written. */
  fields: string[];
  /** SPL only: macro names referenced between backticks. */
  macros: string[];
  /**
   * AQL only: double-quoted Custom Event Property names.
   *
   * Kept apart from `fields` because the two are checkable to completely
   * different degrees. A normalised Ariel property either exists or does not,
   * and the validator can say which; a CEP name is a per-deployment
   * configuration choice that nothing available here can confirm. Merging them
   * would force one honest answer to be given about both.
   */
  customProperties?: string[];
}

/**
 * Comment stripping, so a field name mentioned in a comment is not validated as
 * if it were used. Without this, an explanatory `// uses ProcessCommandLine`
 * line produces a spurious unknown-field error.
 */
function stripComments(query: string, lang: LanguageId): string {
  if (lang === 'kql') return query.replace(/\/\/[^\n]*/g, '');
  if (lang === 'spl') return query.replace(/```[\s\S]*?```/g, ''); // SPL comment macro
  // Ariel documents no comment syntax, so there is nothing to strip and
  // stripping // would corrupt a URL or a Windows path inside a string literal.
  if (lang === 'aql') return query;
  return query.replace(/\/\/[^\n]*/g, '');
}

/** Kusto builtins a naive token match would mistake for column names. */
const KQL_BUILTINS = new Set([
  'isnotempty', 'isempty', 'isnull', 'isnotnull', 'tostring', 'tolower', 'toupper',
  'ago', 'now', 'datetime', 'todatetime', 'toint', 'tolong', 'todouble', 'toreal',
  'count', 'dcount', 'countif', 'dcountif', 'make_set', 'make_list', 'arg_max', 'arg_min',
  'bin', 'bin_auto', 'extract', 'extract_all', 'parse_json', 'split', 'strcat', 'strlen',
  'iff', 'iif', 'case', 'coalesce', 'array_length', 'set_union', 'materialize', 'todynamic',
  'replace_string', 'replace_regex', 'trim', 'substring', 'indexof', 'hash_sha256',
  'format_datetime', 'startofday', 'row_number', 'prev', 'next', 'min', 'max', 'avg', 'sum',
  'any', 'take_any', 'percentile', 'toscalar', 'range', 'pack', 'unpack', 'has_any', 'has_all',
  'ipv4_is_match', 'ipv4_is_private', 'parse_url', 'base64_decode_tostring', 'gettype',
  'tobool', 'totimespan', 'dayofweek', 'datetime_diff', 'datetime_add', 'series_stats',
  'geo_info_from_ip_address', 'url_decode', 'zip', 'strcat_delim',
]);

/**
 * Names the query defines for itself, which must never be validated against the
 * field catalog.
 *
 * `summarize Connections = count() | where Connections < 5` is correct, and
 * Connections is not a column of anything. Reporting it as an unknown field is
 * a false-positive blocking error, and false blocks are worse than no gate at
 * all — they teach a model that the validator is noise.
 */
export function locallyDefinedNames(query: string, lang: LanguageId): Set<string> {
  const text = stripComments(String(query ?? ''), lang);
  const names = new Set<string>();

  if (lang === 'kql') {
    // Every single-= assignment. KQL comparison is == / =~ / != / !~, so a lone
    // = is unambiguously a binding, wherever it appears: extend, summarize,
    // project, let, or inside a summarize list.
    for (const m of text.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?![=~])/g)) names.add(m[1]);
  }

  if (lang === 'spl') {
    for (const m of text.matchAll(/\beval\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/gi)) names.add(m[1]);
    // rename A as B, and stats count as B
    for (const m of text.matchAll(/\bas\s+"?([A-Za-z_][A-Za-z0-9_.]*)"?/gi)) names.add(m[1]);
  }

  if (lang === 'cql') {
    // named capture groups extract fields inline
    for (const m of text.matchAll(/\(\?<([A-Za-z_][A-Za-z0-9_]*)>/g)) names.add(m[1]);
    for (const m of text.matchAll(/\bas\s*=?\s*"?([A-Za-z_][A-Za-z0-9_]*)"?/gi)) names.add(m[1]);
  }

  if (lang === 'aql') {
    // SELECT … AS alias, and the same alias reused in GROUP BY / HAVING /
    // ORDER BY. Ariel allows an aggregate alias to be referenced downstream —
    // `HAVING accounts_tried > 10` — so without this the alias is reported as
    // an unknown property on a query that is entirely correct.
    for (const m of text.matchAll(/\bAS\s+"?([A-Za-z_][A-Za-z0-9_]*)"?/gi)) names.add(m[1]);
  }

  return names;
}

export function extract(query: string, lang: LanguageId): Extraction {
  const text = stripComments(String(query ?? ''), lang);
  const sources = new Set<string>();
  const fields = new Set<string>();
  const macros = new Set<string>();
  const customProperties = new Set<string>();

  if (lang === 'kql') {
    // Leading token before the first pipe is the table.
    const head = text.trim().split(/[\n|]/)[0]?.trim() ?? '';
    const m = head.match(/^([A-Za-z][A-Za-z0-9_]{2,})\s*$/);
    if (m) sources.add(m[1]);
    // Tables can also appear inside join(...) and union.
    for (const j of text.matchAll(/\b(?:join\s+(?:kind\s*=\s*\w+\s*)?\(\s*|union\s+)([A-Za-z][A-Za-z0-9_]{2,})/g)) {
      sources.add(j[1]);
    }
    const patterns = [
      /\bwhere\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|=~|!=|!~|>=|<=|>|<|\bhas\b|\bhas_any\b|\bhas_all\b|\bcontains\b|\bstartswith\b|\bendswith\b|\bin~?\b|\bmatches\b)/g,
      /\bproject(?:-away|-rename|-keep)?\s+([A-Za-z_][A-Za-z0-9_,\s]*)/g,
      /\bextend\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/g,
      /\bsummarize\b[^|]*?\bby\s+([A-Za-z_][A-Za-z0-9_,\s]*)/g,
      /\bdistinct\s+([A-Za-z_][A-Za-z0-9_,\s]*)/g,
    ];
    for (const re of patterns) {
      for (const mm of text.matchAll(re)) {
        for (const raw of String(mm[1]).split(',')) {
          const f = raw.trim();
          if (!f || f.length < 3) continue;
          if (KQL_BUILTINS.has(f.toLowerCase())) continue;
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(f)) continue;
          fields.add(f);
        }
      }
    }
  }

  if (lang === 'spl') {
    for (const mm of text.matchAll(/\bfrom\s+datamodel\s*[:=]\s*["']?([A-Za-z_][A-Za-z0-9_.]*)/gi)) {
      sources.add(mm[1]);
    }
    for (const mm of text.matchAll(/\bdatamodel\s*=\s*["']?([A-Za-z_][A-Za-z0-9_.]*)/gi)) {
      sources.add(mm[1]);
    }
    // CIM-qualified fields are the canonical form.
    for (const mm of text.matchAll(/\b([A-Z][A-Za-z0-9_]*\.[a-z_][A-Za-z0-9_]*)/g)) {
      fields.add(mm[1]);
    }
    for (const mm of text.matchAll(/`([a-zA-Z0-9_]+)(?:\([^)]*\))?`/g)) {
      macros.add(mm[1]);
    }
  }

  if (lang === 'cql') {
    for (const mm of text.matchAll(/\bevent_simpleName\s*=\s*"?([A-Za-z0-9_]+)"?/g)) {
      sources.add(mm[1]);
    }
    // in(event_simpleName, values=[...]) is also a selector.
    for (const mm of text.matchAll(/in\s*\(\s*event_simpleName\s*,\s*values\s*=\s*\[([^\]]*)\]/g)) {
      for (const raw of String(mm[1]).split(',')) {
        const v = raw.trim().replace(/^["']|["']$/g, '');
        if (v) sources.add(v);
      }
    }
    for (const mm of text.matchAll(/\b([A-Z][A-Za-z0-9_]{2,})\s*=\s*[/"[A-Za-z0-9*]/g)) {
      if (mm[1] !== 'event_simpleName') fields.add(mm[1]);
    }
    for (const mm of text.matchAll(/\bin\s*\(\s*([A-Z][A-Za-z0-9_]{2,})\s*,/g)) {
      if (mm[1] !== 'event_simpleName') fields.add(mm[1]);
    }
    for (const mm of text.matchAll(/groupBy\s*\(\s*\[([^\]]*)\]/g)) {
      for (const raw of String(mm[1]).split(',')) {
        const f = raw.trim();
        if (/^[A-Z][A-Za-z0-9_]{2,}$/.test(f)) fields.add(f);
      }
    }
  }

  if (lang === 'aql') {
    // Ariel table. Only events and flows exist, so an unexpected name here is
    // reported rather than treated as an unknown-table lookup.
    for (const mm of text.matchAll(/\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)/gi)) {
      sources.add(mm[1].toLowerCase());
    }

    // Custom Event Properties: double-quoted, case-sensitive, per-deployment.
    // Matched before bare identifiers so a CEP is never also counted as a
    // normalised property.
    for (const mm of text.matchAll(/"([^"\n]{1,120})"/g)) {
      const name = mm[1].trim();
      if (name) customProperties.add(name);
    }

    // Bare identifiers, which should all be normalised Ariel properties. The
    // exclusions matter more than the match: without them every SQL keyword,
    // function name and string literal becomes a phantom field, and a
    // validator that reports phantom errors on a correct query is one nobody
    // reads twice.
    //
    // Both quoting styles are blanked before this runs, and both for the same
    // reason. 'powershell.exe' must not contribute `powershell`, and
    // "Process Name" must not contribute `process` and `name` — the latter
    // produced four blocking errors on this spec's own worked example, which
    // would have made the gate actively harmful.
    const KEYWORDS = new Set([
      'select', 'from', 'where', 'group', 'by', 'order', 'having', 'limit',
      'and', 'or', 'not', 'in', 'is', 'null', 'like', 'ilike', 'matches',
      'imatches', 'between', 'as', 'asc', 'desc', 'text', 'search', 'case',
      'when', 'then', 'else', 'end', 'distinct', 'events', 'flows',
      'parameters', 'into', 'true', 'false',
      // Time-bound clause, including the unit words, which are otherwise read
      // as properties: LAST 24 HOURS contributed a field called `hours`.
      'last', 'start', 'stop', 'minute', 'minutes', 'hour', 'hours',
      'day', 'days', 'week', 'weeks', 'month', 'months',
      // Join vocabulary. Ariel supports none of it, and aql.no-join already
      // reports that — repeating it as four unknown-property errors buries the
      // one finding that explains what is wrong.
      'join', 'inner', 'outer', 'left', 'right', 'full', 'on', 'union', 'all',
    ]);
    const blanked = text
      .replace(/'[^']*'/g, "''")
      .replace(/"[^"\n]*"/g, '""');
    for (const mm of blanked.matchAll(/\b([A-Za-z_][A-Za-z0-9_]{1,63})\b(?!\s*\()/g)) {
      const low = mm[1].toLowerCase();
      if (KEYWORDS.has(low)) continue;
      if (AQL_FUNCTIONS.has(low)) continue;
      fields.add(low);
    }
  }

  return {
    sources: [...sources],
    fields: [...fields],
    macros: [...macros],
    ...(lang === 'aql' ? { customProperties: [...customProperties] } : {}),
  };
}

/**
 * Split extracted AQL identifiers into the ones QRadar normalises and the ones
 * it does not.
 *
 * Exported so both the validator and the translation brief classify the same
 * way — two implementations of "is this a real property" would eventually
 * disagree, and the disagreement would show up as a validator that rejects a
 * query the brief told the model to write.
 */
export function classifyAqlProperties(
  fields: readonly string[],
  locallyDefined: ReadonlySet<string>
): { normalised: string[]; unknown: string[] } {
  const normalised: string[] = [];
  const unknown: string[] = [];
  const localLower = new Set([...locallyDefined].map(n => n.toLowerCase()));
  for (const f of fields) {
    if (localLower.has(f)) continue;
    if (AQL_EVENT_PROPERTIES.has(f)) normalised.push(f);
    else unknown.push(f);
  }
  return { normalised, unknown };
}

export type { LanguageSpec } from './types.js';
export { SHARED_PRINCIPLES } from './types.js';
