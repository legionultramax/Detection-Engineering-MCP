// synthesize_killchain — the correlation scaffold, generated server-side.
//
// WAT-42 is the primary deliverable of a Standard or Deep hunt and the step
// most often skipped, because inventing correlation structure from nothing
// means deciding the phase ordering, the pivot entity, the window and the
// language's join idiom all at once — and a mistake in any of them produces a
// query that runs, returns rows, and correlates the wrong things.
//
// Three of those four are deterministic. Phase ordering comes from the ATT&CK
// tactic each technique belongs to. The pivot follows from the telemetry shape.
// The join idiom is a property of the language. So they are computed here, and
// the model is left with the one genuinely generative part: the per-phase
// predicates.
//
// The AQL path is the reason this is not a template string. Ariel has no JOIN,
// no UNION and no subquery, and `validate_query` blocks all three — so a tool
// that emitted a joined AQL scaffold would be emitting something this server
// then rejects. For AQL it emits one query per phase plus a written correlation
// spec, which is the honest shape of the answer rather than a convenient one.

import { runQuery } from '../../db/connection.js';
import { SPECS, type LanguageId } from '../../reference/query-languages/index.js';
import { CATEGORY_SOURCES } from '../../reference/query-languages/field-mappings.js';

/**
 * ATT&CK Enterprise tactic order.
 *
 * Phase ordering is the first thing a correlation rule has to get right, and
 * it is not something to ask a model to recall — a chain asserted in the wrong
 * order correlates a plausible-looking sequence that never happens that way.
 */
const TACTIC_ORDER: readonly string[] = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

function tacticRank(tactics: string[]): number {
  let best = TACTIC_ORDER.length;
  for (const t of tactics) {
    const i = TACTIC_ORDER.indexOf(t.toLowerCase().replace(/\s+/g, '-'));
    if (i >= 0 && i < best) best = i;
  }
  return best;
}

/**
 * The entity that links one phase to the next, per language.
 *
 * Host is the default because it is the only pivot every telemetry shape in
 * this corpus carries. User is available but weaker — a service account spans
 * hosts and produces false correlation; process lineage is stronger but is not
 * present across event types, so it cannot anchor a whole chain.
 */
const PIVOTS: Record<LanguageId, Record<string, string>> = {
  kql: { host: 'DeviceName', user: 'AccountName', process: 'InitiatingProcessId' },
  spl: { host: 'dest', user: 'user', process: 'process_id' },
  cql: { host: 'ComputerName', user: 'UserName', process: 'TargetProcessId' },
  aql: { host: 'sourceip', user: 'username', process: '"Process ID"' },
};

interface TechRow {
  id: string;
  name: string;
  tactics: string | null;
}

interface Phase {
  order: number;
  technique_id: string;
  technique: string;
  tactic: string;
  source: string | null;
  shape: string | null;
  reference_rules: number;
}

/**
 * Correlation window in seconds.
 *
 * KQL and CQL take a timespan literal (`1h`) directly; SPL compares against
 * `_time`, which is epoch seconds, so it needs a number. Returning both lets
 * each scaffold use the form its language actually accepts instead of pasting
 * the literal everywhere and producing one silently-broken query.
 */
function windowSeconds(window: string): number | null {
  const m = String(window).trim().match(/^(\d+(?:\.\d+)?)\s*(s|m|h|d)$/i);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  const mult = unit === 's' ? 1 : unit === 'm' ? 60 : unit === 'h' ? 3600 : 86400;
  return Math.round(n * mult);
}

const parseArr = (v: string | null): string[] => {
  if (!v) return [];
  try {
    const p = JSON.parse(v);
    return Array.isArray(p) ? p.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return String(v).split(',').map(s => s.trim()).filter(Boolean);
  }
};

function majority(values: string[]): string | null {
  if (values.length === 0) return null;
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

// --- Per-language scaffolds -------------------------------------------------

function kqlScaffold(phases: Phase[], pivot: string, window: string): string {
  const lets = phases.map((p, i) =>
    `let phase${i + 1} = ${p.source ?? '<Table>'}\n` +
    `    | where <predicate for ${p.technique_id} — ${p.technique}>\n` +
    `    | project ${pivot}, t${i + 1} = Timestamp;`
  ).join('\n');

  const joins = phases.slice(1).map((_, i) =>
    `| join kind=inner (phase${i + 2}) on ${pivot}\n` +
    `| where t${i + 2} between (t${i + 1} .. t${i + 1} + ${window})`
  ).join('\n');

  return `${lets}\nphase1\n${joins}\n| project ${pivot}, ${phases.map((_, i) => `t${i + 1}`).join(', ')}\n| order by t1 asc`;
}

function splScaffold(phases: Phase[], pivot: string, windowSeconds: number, window: string): string {
  const flags = phases.map((p, i) =>
    `| eval phase${i + 1} = if(<predicate for ${p.technique_id} — ${p.technique}>, 1, 0)`
  ).join('\n');

  // `_time` is epoch seconds, so the window has to be a number here. A literal
  // `<= 1h` parses as a field reference and silently compares against null,
  // which drops the window constraint without erroring — the correlation then
  // fires on events days apart.
  return `index=<index> earliest=-<range>\n` +
    `${flags}\n` +
    `| stats ${phases.map((_, i) => `max(phase${i + 1}) as phase${i + 1}`).join(', ')},\n` +
    `        min(_time) as first_seen, max(_time) as last_seen by ${pivot}\n` +
    `| where ${phases.map((_, i) => `phase${i + 1}=1`).join(' AND ')}\n` +
    `| where (last_seen - first_seen) <= ${windowSeconds}  \`\`\` ${window} \`\`\`\n` +
    `| eval phases_matched = ${phases.map((_, i) => `phase${i + 1}`).join(' + ')}\n` +
    `| sort - phases_matched`;
}

function cqlScaffold(phases: Phase[], pivot: string, windowSeconds: number, window: string): string {
  const cases = phases.map((p, i) =>
    `| case { <predicate for ${p.technique_id} — ${p.technique}> | phase${i + 1} := 1; * | phase${i + 1} := 0 }`
  ).join('\n');

  // @timestamp is epoch milliseconds in LogScale, so the window is expressed in
  // millis here rather than as a duration literal — test() evaluates an
  // arithmetic expression, not a timespan.
  return `#repo=falcon\n${cases}\n` +
    `| groupBy([${pivot}], function=[${phases.map((_, i) => `max(phase${i + 1}, as=phase${i + 1})`).join(', ')}, min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])\n` +
    `| ${phases.map((_, i) => `phase${i + 1}=1`).join(' | ')}\n` +
    `| test(last_seen - first_seen <= ${windowSeconds * 1000})  // ${window}`;
}

function aqlPerPhase(phases: Phase[], pivot: string): Array<Record<string, string>> {
  return phases.map((p, i) => ({
    phase: `${i + 1} — ${p.tactic}`,
    technique: `${p.technique_id} ${p.technique}`,
    query:
      `SELECT ${pivot}, starttime, <fields for ${p.technique_id}>\n` +
      `FROM events\n` +
      `WHERE <predicate for ${p.technique_id} — ${p.technique}>\n` +
      `ORDER BY starttime ASC\n` +
      `LIMIT 1000`,
  }));
}

export interface KillchainArgs {
  technique_ids: string[];
  language: LanguageId;
  window?: string;
  pivot?: 'host' | 'user' | 'process';
}

export function synthesizeKillchain(args: KillchainArgs): Record<string, unknown> {
  const lang = args.language;
  const spec = SPECS[lang];
  const ids = (Array.isArray(args.technique_ids) ? args.technique_ids : [])
    .map(t => String(t ?? '').trim().toUpperCase())
    .filter(Boolean);

  if (ids.length < 2) {
    return {
      error: true,
      message:
        'A kill chain needs at least two techniques. For a single technique use ' +
        'build_authoring_brief — correlation across one phase is just a detection.',
    };
  }

  const unknown: string[] = [];
  const phases: Phase[] = [];

  for (const tid of ids) {
    const row = runQuery<TechRow>(
      `SELECT id, name, tactics FROM mitre_techniques_full
       WHERE id = ? OR external_id = ? LIMIT 1`,
      [tid, tid]
    )[0];

    if (!row) { unknown.push(tid); continue; }

    const tactics = parseArr(row.tactics);
    const shapes = runQuery<{ logsource_category: string | null }>(
      `SELECT logsource_category FROM detections
       WHERE mitre_techniques LIKE ? AND logsource_category IS NOT NULL LIMIT 40`,
      [`%${tid}%`]
    ).map(r => r.logsource_category).filter((c): c is string => Boolean(c));

    const shape = majority(shapes);
    const count = runQuery<{ n: number }>(
      'SELECT COUNT(*) n FROM detections WHERE mitre_techniques LIKE ?',
      [`%${tid}%`]
    )[0]?.n ?? 0;

    phases.push({
      order: tacticRank(tactics),
      technique_id: tid,
      technique: row.name,
      tactic: tactics[0] ?? 'unknown',
      shape,
      source: shape ? CATEGORY_SOURCES[shape]?.[lang] ?? null : null,
      reference_rules: count,
    });
  }

  if (phases.length < 2) {
    return {
      error: true,
      message:
        `Only ${phases.length} of ${ids.length} technique IDs resolved against the local ATT&CK ` +
        `data${unknown.length ? ` (unknown: ${unknown.join(', ')})` : ''}. Confirm them with ` +
        'search_mitre_techniques before synthesising a chain.',
    };
  }

  // Kill-chain order, not the order the caller happened to list them in.
  phases.sort((a, b) => a.order - b.order);
  phases.forEach((p, i) => { p.order = i + 1; });

  const pivotKind = args.pivot ?? 'host';
  const pivot = PIVOTS[lang][pivotKind] ?? PIVOTS[lang].host;
  const window = String(args.window ?? '1h').trim();
  const seconds = windowSeconds(window);

  const unlinkable = phases.filter(p => !p.source);
  const noCoverage = phases.filter(p => p.reference_rules === 0);

  const caveats: string[] = [];
  if (unknown.length > 0) {
    caveats.push(
      `Not in the local ATT&CK data and therefore excluded from the chain: ${unknown.join(', ')}.`
    );
  }
  if (unlinkable.length > 0) {
    caveats.push(
      `No ${lang.toUpperCase()} source is mapped for ${unlinkable.map(p => p.technique_id).join(', ')} ` +
      '— the scaffold marks these <Table> and you must supply the source, or drop the phase and ' +
      'say the chain is incomplete.'
    );
  }
  if (noCoverage.length > 0) {
    caveats.push(
      `No detection in the corpus covers ${noCoverage.map(p => p.technique_id).join(', ')}, so ` +
      'there is no reference rule to model those predicates on. They are the phases most likely ' +
      'to be wrong.'
    );
  }

  const isAql = lang === 'aql';
  const correlation = isAql
    ? {
        form: 'one query per phase, correlated outside the query',
        reason:
          'Ariel has no JOIN, no UNION and no subquery in FROM, so a multi-phase chain cannot be ' +
          'expressed as a single AQL query. validate_query blocks all three — a joined scaffold ' +
          'would be rejected by this same server. Run the phase queries separately and correlate ' +
          `on ${pivot} downstream.`,
        pivot,
        window,
        queries: aqlPerPhase(phases, pivot),
        correlation_spec:
          `Collect the ${pivot} values returned by phase 1. For each subsequent phase, keep only ` +
          `rows whose ${pivot} appears in the previous phase's results and whose starttime falls ` +
          `within ${window} of it. A host that survives every phase in order is the finding. ` +
          'The alternative, if a single query is required: collapse the phases into one pass with ' +
          `conditional aggregation — SELECT ${pivot}, SUM(CASE WHEN <phase 1> THEN 1 ELSE 0 END) ` +
          `AS p1, … GROUP BY ${pivot} — but only when the hunt range is 7 days or less, because ` +
          'the backend chunks longer ranges daily and would aggregate each day separately.',
      }
    : {
        form: lang === 'kql' ? 'single query, let + join on the pivot'
          : lang === 'spl' ? 'single query, stats with per-phase flags'
          : 'single query, groupBy with per-phase flags',
        pivot,
        window,
        scaffold: lang === 'kql' ? kqlScaffold(phases, pivot, window)
          : lang === 'spl' ? splScaffold(phases, pivot, seconds ?? 3600, window)
          : cqlScaffold(phases, pivot, seconds ?? 3600, window),
      };

  if (seconds === null) {
    caveats.push(
      `Window "${window}" is not a recognised duration (expected forms: 30m, 1h, 24h, 7d). The ` +
      'scaffold uses it literally where the language accepts a timespan, and falls back to one ' +
      'hour where a number is required — check it before running.'
    );
  }

  return {
    language: spec.id,
    technique_count: phases.length,
    pivot: { entity: pivotKind, field: pivot,
      note: 'Host is the default because it is the only entity every telemetry shape here ' +
        'carries. A user pivot correlates a service account across unrelated hosts; a process ' +
        'pivot is stronger but is not present on every event type.' },
    window,

    phases: phases.map(p => ({
      order: p.order,
      tactic: p.tactic,
      technique_id: p.technique_id,
      technique: p.technique,
      shape: p.shape ?? 'unknown',
      source: p.source,
      reference_rules: p.reference_rules,
    })),

    correlation,
    ...(caveats.length > 0 ? { caveats } : {}),

    instructions: [
      'The phase ordering, pivot and window above are computed — do not reorder them. ATT&CK ' +
        'tactic order decides the sequence, not the order the techniques were listed in.',
      'Replace every <predicate> with a real condition. Use build_authoring_brief(technique_id, ' +
        `"${lang}") per phase to get the field vocabulary and the LOLBAS matrix for that phase.`,
      `The scaffold is a skeleton and will not validate while it still contains placeholders. ` +
        `Fill it in, then call validate_query(query, "${lang}").`,
      'State the correlation window explicitly in your output, and name any phase you could not ' +
        'express rather than quietly dropping it.',
      ...(isAql
        ? ['Do not attempt to join these AQL queries. Emit them separately with the correlation ' +
           'spec, and do not write START, STOP or domainId into any of them.']
        : []),
    ],
  };
}
