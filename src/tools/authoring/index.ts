// Composite authoring tools.
//
// Each of these collapses a multi-step procedure that was previously written
// down as instructions and therefore optional. The point is not convenience —
// it is that a step encoded in code runs every time, and a step described in
// prose runs whenever the model remembers it.
//
// Schemas here stay inside the complexity ceiling Gemma 4 is documented to
// handle: flat properties, no nested objects, no anyOf/oneOf, at most a handful
// of arguments. `technique_ids` is an array of strings, which is the deepest
// construct any schema in this server uses.

import { defineTool, type ToolDefinition } from '../registry.js';
import { normaliseLanguage, LANGUAGE_IDS } from '../../reference/query-languages/index.js';
import { buildAuthoringBrief } from './brief.js';
import { synthesizeKillchain } from './killchain.js';

const LANG_HELP =
  'kql | spl | cql | aql. Aliases accepted: sentinel, defender, splunk, escu, crowdstrike, ' +
  'logscale, falcon, qradar, ariel.';

const buildBrief = defineTool({
  name: 'build_authoring_brief',
  description:
    'CALL THIS FIRST when writing a detection rule. One call returns everything needed: the ' +
    'technique, reference rules, required telemetry, known false positives, the target field ' +
    'vocabulary, and the LOLBAS abuse matrix for any binary in scope. Replaces calling ' +
    'lookup_mitre_technique, list_by_mitre, get_data_sources, get_lolfarm_context, lookup_lolbas ' +
    'and get_query_language_spec separately, using far fewer tokens. Returns gate=OK, CAVEATS or ' +
    'BLOCKED; BLOCKED means the material was withheld and you must not write a rule. Then write ' +
    'the query and call validate_query.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: {
        type: 'string',
        description: 'MITRE ATT&CK technique ID, e.g. "T1059.001" or "T1003".',
      },
      language: { type: 'string', description: LANG_HELP },
      binary: {
        type: 'string',
        description:
          'Optional executable the rule is scoped to, e.g. "certutil.exe". Supplying it makes the ' +
          'LOLBAS abuse matrix mandatory — no matrix means BLOCKED. Omit to infer binaries from ' +
          'the reference rules.',
      },
      max_rules: {
        type: 'number',
        description: 'Optional. Reference rules to return (default 12).',
      },
      require_lolbas: {
        type: 'boolean',
        description:
          'Optional, default true. Set false only after confirming the named binary is not a ' +
          'living-off-the-land binary; the brief then proceeds with a caveat.',
      },
    },
    required: ['technique_id', 'language'],
  },
  handler: async (args) => {
    const a = args as unknown as {
      technique_id: string; language: string; binary?: string;
      max_rules?: number; require_lolbas?: boolean;
    };
    const lang = normaliseLanguage(a.language);
    if (!lang) {
      return {
        error: true,
        message: `Unknown language "${a.language}". Supported: ${LANGUAGE_IDS.join(', ')}.`,
        supported: LANGUAGE_IDS,
      };
    }
    if (!a.technique_id || !String(a.technique_id).trim()) {
      return { error: true, message: 'technique_id is required, e.g. "T1059.001".' };
    }
    return buildAuthoringBrief({
      technique_id: a.technique_id,
      language: lang,
      binary: a.binary,
      max_rules: a.max_rules,
      require_lolbas: a.require_lolbas,
    });
  },
});

const killchain = defineTool({
  name: 'synthesize_killchain',
  description:
    'Build a multi-phase correlation scaffold across two or more ATT&CK techniques. Sorts the ' +
    'phases into ATT&CK tactic order, picks the pivot entity linking them, and emits the ' +
    'correlation idiom for the language — KQL let+join, SPL stats with per-phase flags, CQL ' +
    'groupBy. For QRadar AQL it returns one query per phase plus a written correlation spec, ' +
    'because Ariel has no JOIN. You fill in the per-phase predicates; the structure is computed. ' +
    'Use build_authoring_brief per phase to get those predicates.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_ids: {
        type: 'array',
        items: { type: 'string' },
        description:
          'Two or more MITRE technique IDs, e.g. ["T1566.001","T1059.001"]. Order does not ' +
          'matter — phases are sorted into ATT&CK tactic order.',
      },
      language: { type: 'string', description: LANG_HELP },
      window: {
        type: 'string',
        description: 'Optional correlation window: "30m", "1h", "24h", "7d". Default "1h".',
      },
      pivot: {
        type: 'string',
        enum: ['host', 'user', 'process'],
        description:
          'Optional, default "host" — the entity linking one phase to the next. Host is the only ' +
          'pivot every telemetry shape carries.',
      },
    },
    required: ['technique_ids', 'language'],
  },
  handler: async (args) => {
    const a = args as unknown as {
      technique_ids: string[]; language: string; window?: string;
      pivot?: 'host' | 'user' | 'process';
    };
    const lang = normaliseLanguage(a.language);
    if (!lang) {
      return {
        error: true,
        message: `Unknown language "${a.language}". Supported: ${LANGUAGE_IDS.join(', ')}.`,
        supported: LANGUAGE_IDS,
      };
    }
    if (!Array.isArray(a.technique_ids)) {
      return { error: true, message: 'technique_ids must be an array of MITRE technique IDs.' };
    }
    return synthesizeKillchain({
      technique_ids: a.technique_ids,
      language: lang,
      window: a.window,
      pivot: a.pivot,
    });
  },
});

export const authoringTools: ToolDefinition[] = [buildBrief, killchain];
export const authoringToolCount = authoringTools.length;
