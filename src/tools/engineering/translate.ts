// translate_detection — builds a translation brief, and deliberately does not
// return a query.
//
// The reasoning: a transpiler is weeks of work per language and permanently
// partial, and the rules worth translating are exactly the ones a partial
// transpiler drops. A model, by contrast, is good at translation and bad at
// recall. So this retrieves a real rule and hands over everything needed to
// translate it — vocabulary, field mappings with confidence, prohibitions,
// shape-matched examples — and validate_query then gates what comes back.
//
// That division is the whole point. The tool supplies truth; the model supplies
// fluency; a deterministic gate decides whether the result ships.

import { runQuery } from '../../db/connection.js';
import { SPECS, type LanguageId } from '../../reference/query-languages/index.js';
import {
  FIELD_MAPPINGS, CATEGORY_SOURCES, MODIFIER_TRANSLATION, categoriesWithMappings,
} from '../../reference/query-languages/field-mappings.js';
import { getFieldCatalog } from '../../reference/field-catalog/load.js';

export interface MappedField {
  sigmaField: string;
  target: string | null;
  confidence: 'confirmed' | 'community' | 'unconfirmed' | 'none';
  evidence: string;
  note?: string;
}

interface DetectionRow {
  id: string;
  name: string;
  description: string | null;
  source_type: string;
  severity: string | null;
  query: string | null;
  raw_content: string | null;
  logsource_category: string | null;
  logsource_product: string | null;
  logsource_service: string | null;
  mitre_techniques: string | null;
  false_positives: string | null;
  refs: string | null;
}

const parseSafe = (v: string | null): unknown[] => {
  if (!v) return [];
  try {
    const p = JSON.parse(v);
    return Array.isArray(p) ? p : [p];
  } catch { return []; }
};

/**
 * Sigma logsource category, from the enrichment column where the indexer
 * extracted one, otherwise from the rule text.
 *
 * Worth reading from the YAML as a fallback: the column is populated on 3,140
 * of 4,030 Sigma rules, so roughly a fifth would otherwise arrive shapeless.
 */
function resolveCategory(row: DetectionRow | null, rawContent: string | null): string | null {
  if (row?.logsource_category) return row.logsource_category;
  if (!rawContent) return null;
  const m = rawContent.match(/^\s*logsource:[\s\S]*?^\s*category:\s*([a-z_]+)/m);
  return m ? m[1] : null;
}

/**
 * How deeply nested the Sigma condition is.
 *
 * Upstream's own guidance is that deeply nested AND/OR/NOT compiles badly
 * through pySigma backends and that flat structures translate better. The same
 * applies to a model: a condition with four levels of grouping is where
 * translations quietly lose a clause. Measure it and say so rather than
 * translating and hoping.
 */
function conditionComplexity(rawContent: string | null): {
  condition: string | null; depth: number; operators: number; warning?: string;
} {
  if (!rawContent) return { condition: null, depth: 0, operators: 0 };
  const m = rawContent.match(/^\s*condition:\s*(.+)$/m);
  if (!m) return { condition: null, depth: 0, operators: 0 };
  const cond = m[1].trim();
  let depth = 0, max = 0;
  for (const ch of cond) {
    if (ch === '(') { depth++; max = Math.max(max, depth); }
    else if (ch === ')') depth--;
  }
  const operators = (cond.match(/\b(and|or|not|all of|1 of)\b/gi) ?? []).length;
  const result: { condition: string; depth: number; operators: number; warning?: string } =
    { condition: cond, depth: max, operators };
  if (max >= 2 || operators >= 4) {
    result.warning =
      `This condition nests ${max} level(s) deep with ${operators} operator(s). Nested ` +
      'AND/OR/NOT is where translations lose a clause. Translate one selection block at a ' +
      'time, then assemble, and state explicitly if any clause could not be expressed.';
  }
  return result;
}

/** Sigma selection blocks, so the model sees the predicates rather than re-parsing YAML. */
function extractSelections(rawContent: string | null): Record<string, string> {
  if (!rawContent) return {};
  const out: Record<string, string> = {};
  const det = rawContent.match(/^detection:\s*$([\s\S]*?)(?=^\S|\Z)/m);
  if (!det) return out;
  const body = det[1];
  const blockRe = /^\s{2,4}([A-Za-z_][A-Za-z0-9_]*):\s*$([\s\S]*?)(?=^\s{2,4}[A-Za-z_][A-Za-z0-9_]*:|\Z)/gm;
  for (const m of body.matchAll(blockRe)) {
    const name = m[1];
    if (name === 'condition' || name === 'timeframe') continue;
    out[name] = m[2].replace(/\s+$/, '');
  }
  return out;
}

/** Sigma value modifiers actually used, so only relevant translations are shown. */
function usedModifiers(rawContent: string | null): string[] {
  if (!rawContent) return [];
  const found = new Set<string>();
  for (const m of rawContent.matchAll(/\|([a-z0-9]+)(?=\s*:|\|)/g)) {
    if (m[1] in MODIFIER_TRANSLATION) found.add(m[1]);
  }
  return [...found];
}

/**
 * Map the source rule's fields into the target language, and grade each one
 * against the catalog.
 *
 * The grading is the honest part. The mapping table is authored, so a target it
 * names is a claim; the catalog either corroborates that claim or it does not,
 * and the difference is reported rather than smoothed over.
 */
function mapFields(
  category: string | null,
  target: LanguageId,
  fieldsUsed: string[]
): { mapped: MappedField[]; targetSource: string | null; unmappable: string[] } {
  const table = category ? FIELD_MAPPINGS[category] : undefined;
  const targetSource = category ? CATEGORY_SOURCES[category]?.[target] ?? null : null;
  const catalog = getFieldCatalog();
  const mapped: MappedField[] = [];
  const unmappable: string[] = [];

  const names = fieldsUsed.length > 0 ? fieldsUsed : Object.keys(table ?? {});

  for (const f of names) {
    const t = table?.[f];
    if (!t) {
      unmappable.push(f);
      continue;
    }
    const to = t[target];
    if (!to) {
      mapped.push({
        sigmaField: f, target: null, confidence: 'none',
        evidence: `No equivalent in ${target.toUpperCase()}.`,
        note: t.note,
      });
      continue;
    }

    let confidence: MappedField['confidence'] = 'unconfirmed';
    let evidence = 'Mapping is authored and not corroborated by the catalog.';

    if (catalog) {
      if (target === 'kql') {
        const tf = targetSource ? catalog.kql.tableFields[targetSource] : undefined;
        if (tf && to in tf) {
          confidence = 'confirmed';
          evidence = `Appears on ${targetSource} in ${tf[to]} corpus rule(s).`;
        } else if (to in catalog.kql.fields) {
          confidence = 'unconfirmed';
          evidence =
            `Appears in ${catalog.kql.fields[to]} corpus rule(s), but not associated with ` +
            `${targetSource}. Confirm the column exists on that table.`;
        } else {
          evidence = 'Not found in the corpus at the support threshold. Verify before use.';
        }
      } else if (target === 'spl') {
        if (to in catalog.spl.fields) {
          confidence = 'confirmed';
          evidence = `Appears in ${catalog.spl.fields[to]} ESCU rule(s).`;
        } else {
          evidence = 'Not seen in the ESCU corpus. It may exist in the target CIM version.';
        }
      } else {
        // CQL fields are not enumerated by the dictionary — it lists events, not
        // their columns — so the strongest available claim is that the event
        // exists. Saying so beats implying a verification that did not happen.
        const ev = targetSource ? catalog.cql.events[targetSource] : undefined;
        confidence = 'community';
        evidence = ev
          ? `Event ${targetSource} exists in the vendored dictionary` +
            `${ev.documented ? '' : ' but has no description'}. Field names are not enumerated ` +
            'there, so this field is unverified.'
          : 'Event not found in the vendored dictionary. Verify against the sensor map.';
      }
    } else {
      evidence = 'Field catalog unavailable — nothing was verified.';
    }

    mapped.push({ sigmaField: f, target: to, confidence, evidence, note: t.note });
  }

  return { mapped, targetSource, unmappable };
}

/**
 * Fields the rule actually references, so the brief is scoped to what matters.
 *
 * The optional `- ` prefix is load-bearing. Sigma expresses OR between fields as
 * a list of maps:
 *
 *     selection_img:
 *         - Description|contains: '7-Zip'
 *         - Image|endswith: '\7z.exe'
 *
 * Requiring the field name immediately after indentation silently drops every
 * field in that form. On the rule this was first tested against it kept one
 * field of four, which would have produced a query matching any command line
 * containing '.dmp' — no error, just far too broad.
 */
function sigmaFieldsUsed(rawContent: string | null, category: string | null): string[] {
  if (!rawContent) return [];
  const table = category ? FIELD_MAPPINGS[category] : undefined;
  const known = new Set(Object.keys(table ?? {}));
  const found = new Set<string>();
  const FIELD_LINE = /^[ \t]{4,}(?:-[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)(?:\|[a-z0-9|]+)?[ \t]*:/gm;
  for (const m of rawContent.matchAll(FIELD_LINE)) {
    // Anything referenced but not in the mapping table is genuinely unmapped,
    // and the caller needs to know rather than have it disappear.
    if (known.has(m[1]) || /^[A-Z]/.test(m[1])) found.add(m[1]);
  }
  return [...found];
}

export interface TranslateArgs {
  detection_id?: string;
  query?: string;
  source_language?: string;
  target_language: string;
  shape?: string;
}

export function buildTranslationBrief(
  target: LanguageId,
  opts: { detectionId?: string; rawQuery?: string; sourceLanguage?: string; shapeHint?: string }
): Record<string, unknown> {
  let row: DetectionRow | null = null;

  if (opts.detectionId) {
    const rows = runQuery<DetectionRow>('SELECT * FROM detections WHERE id = ?', [opts.detectionId]);
    if (rows.length === 0) {
      return {
        error: true,
        message: `Detection ${opts.detectionId} not found. Use search_detections to find one.`,
      };
    }
    row = rows[0];
  }

  const rawContent = row?.raw_content ?? opts.rawQuery ?? null;
  const sourceLanguage = row?.source_type ?? opts.sourceLanguage ?? 'unknown';
  const category = resolveCategory(row, rawContent) ?? opts.shapeHint ?? null;
  const isSigma = sourceLanguage === 'sigma';

  const fieldsUsed = isSigma ? sigmaFieldsUsed(rawContent, category) : [];
  const { mapped, targetSource, unmappable } = mapFields(category, target, fieldsUsed);
  const spec = SPECS[target];
  const complexity = isSigma ? conditionComplexity(rawContent) : { condition: null, depth: 0, operators: 0 };
  const mods = isSigma ? usedModifiers(rawContent) : [];

  const examples = (() => {
    const want = (category ?? '').toLowerCase();
    const m = spec.examples.filter(e => e.shape === want);
    return (m.length > 0 ? m : spec.examples).slice(0, 3);
  })();

  const lowConfidence = mapped.filter(f => f.confidence !== 'confirmed' && f.target);
  const noEquivalent = mapped.filter(f => !f.target);

  return {
    // --- what is being translated ---
    source: row
      ? {
          id: row.id,
          name: row.name,
          description: row.description,
          language: sourceLanguage,
          severity: row.severity,
          techniques: parseSafe(row.mitre_techniques),
          falsePositives: parseSafe(row.false_positives),
          references: parseSafe(row.refs),
          logsource: {
            category: row.logsource_category,
            product: row.logsource_product,
            service: row.logsource_service,
          },
          rule: rawContent,
        }
      : { language: sourceLanguage, rule: rawContent, note: 'Supplied inline rather than retrieved.' },

    // --- where it is going ---
    target: {
      language: spec.id,
      name: spec.name,
      confidence: spec.confidence,
      authority: spec.authority,
      dataModel: spec.dataModel,
      source: targetSource,
      sourceNote: targetSource
        ? `Write the query against ${targetSource}.`
        : 'No source mapping for this category — determine the correct table/model/event yourself, ' +
          'then validate it.',
      operators: spec.operators,
      cost: spec.cost,
      prohibitions: spec.prohibitions.map(p => ({
        id: p.id, severity: p.severity, title: p.title, reason: p.reason, fix: p.fix,
      })),
      notes: spec.notes,
    },

    // --- how to get there ---
    shape: category ?? 'unknown',
    fieldMappings: mapped,
    modifierTranslation: Object.fromEntries(
      mods.map(m => [m, MODIFIER_TRANSLATION[m][target]])
    ),
    selections: isSigma ? extractSelections(rawContent) : undefined,
    condition: complexity,
    examples,

    // --- what to be careful about ---
    cautions: [
      ...(unmappable.length > 0
        ? [`${unmappable.length} referenced field(s) have no mapping entry and must be resolved ` +
           `manually: ${unmappable.join(', ')}.`]
        : []),
      ...(noEquivalent.length > 0
        ? [`${noEquivalent.length} field(s) have no ${target.toUpperCase()} equivalent: ` +
           `${noEquivalent.map(f => f.sigmaField).join(', ')}. Say so in the output rather than ` +
           'substituting something approximate.']
        : []),
      ...(lowConfidence.length > 0
        ? [`${lowConfidence.length} mapping(s) are not corroborated by the catalog: ` +
           `${lowConfidence.map(f => `${f.sigmaField}->${f.target}`).join(', ')}. A wrong field ` +
           'name produces a query that runs and returns zero rows.']
        : []),
      ...(complexity.warning ? [complexity.warning] : []),
      ...(category === null
        ? ['No logsource category could be determined, so no field mapping or table could be ' +
           'selected. Identify the telemetry the rule needs before translating.']
        : []),
    ],

    instructions: [
      `Write a ${spec.name} query implementing the source rule's detection logic.`,
      'Use only the target field names in fieldMappings. Do not invent field names.',
      'Respect every prohibition above — the blocking ones will be rejected.',
      'Then call validate_query with this target language. Do not present the query before it validates.',
      'State any field marked unconfirmed or community, and anything you could not express, ' +
        'alongside the query. Do not present a guess as a fact.',
    ],

    availableCategories: categoriesWithMappings(),
  };
}
