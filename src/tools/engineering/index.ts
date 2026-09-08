// Query-language tooling: the spec a model needs before writing a query, and
// the deterministic gate that checks what it wrote.

import { defineTool, type ToolDefinition } from '../registry.js';
import {
  SPECS, LANGUAGE_IDS, normaliseLanguage, SHARED_PRINCIPLES, type LanguageId,
} from '../../reference/query-languages/index.js';
import { getFieldCatalog } from '../../reference/field-catalog/load.js';
import { validateQuery } from './validate.js';

/** Shapes a caller can ask for, matched against a Sigma logsource category. */
function examplesFor(lang: LanguageId, shape?: string, limit = 3) {
  const all = SPECS[lang].examples;
  if (!shape) return all.slice(0, limit);
  const want = String(shape).toLowerCase().replace(/[\s-]+/g, '_');
  const matched = all.filter(e => e.shape === want);
  // Fall back to a spread rather than nothing — an unmatched shape should not
  // leave the model with zero examples.
  return (matched.length > 0 ? matched : all).slice(0, limit);
}

const getQueryLanguageSpec = defineTool({
  name: 'get_query_language_spec',
  description:
    'Get the authoring specification for a detection query language: data model, ' +
    'operator/index table, cost model, hard prohibitions, and worked examples. Call this BEFORE ' +
    'writing a query in KQL (Microsoft Sentinel/Defender), SPL (Splunk), or CQL (CrowdStrike ' +
    'Falcon LogScale). Pass a shape (process_creation, network_connection, dns_query, ' +
    'file_event, registry_event, authentication, credential_access) to get examples matched to ' +
    'the detection you are writing instead of a generic set. Returns roughly 1,500 tokens.',
  inputSchema: {
    type: 'object',
    properties: {
      language: {
        type: 'string',
        description:
          'kql | spl | cql. Aliases accepted: kusto, sentinel, defender, splunk, escu, ' +
          'crowdstrike, logscale, humio, falcon.',
      },
      shape: {
        type: 'string',
        description:
          'Optional detection shape, so examples match what you are writing. Typically the ' +
          'Sigma logsource category: process_creation, network_connection, dns_query, ' +
          'file_event, registry_event, authentication, credential_access.',
      },
      include_examples: {
        type: 'boolean',
        description: 'Include worked examples (default: true).',
      },
    },
    required: ['language'],
  },
  handler: async (args) => {
    const { language, shape, include_examples = true } = args as {
      language: string; shape?: string; include_examples?: boolean;
    };
    const lang = normaliseLanguage(language);
    if (!lang) {
      return {
        error: true,
        message: `Unknown language "${language}". Supported: ${LANGUAGE_IDS.join(', ')}.`,
        supported: LANGUAGE_IDS,
      };
    }

    const spec = SPECS[lang];
    const catalog = getFieldCatalog();

    // Ground the spec in what the catalog actually holds, so the model is told
    // the real vocabulary rather than being left to recall it.
    let vocabulary: Record<string, unknown> = {
      available: false,
      note: 'Field catalog not built — run npm run catalog:build. Field names are unverified.',
    };
    if (catalog) {
      if (lang === 'kql') {
        vocabulary = {
          available: true,
          confidence: catalog.kql.confidence,
          derivedFrom: catalog.kql.source,
          coreTables: Object.keys(catalog.kql.coreTables).slice(0, 30),
          customTableWarning: catalog.kql.customTableNote,
          fieldsByTable: Object.fromEntries(
            Object.keys(catalog.kql.coreTables).slice(0, 8).map(t => [
              t, Object.keys(catalog.kql.tableFields[t] ?? {}).slice(0, 20),
            ])
          ),
        };
      } else if (lang === 'spl') {
        vocabulary = {
          available: true,
          confidence: catalog.spl.confidence,
          derivedFrom: catalog.spl.source,
          dataModels: Object.keys(catalog.spl.dataModels),
          commonFields: Object.keys(catalog.spl.fields).slice(0, 40),
          macroWarning:
            `The corpus averages ${(catalog.spl.macroInvocations / 2185).toFixed(1)} macros per ` +
            'query. Macros classified: ' +
            Object.entries(catalog.spl.macroSummary).map(([k, v]) => `${k} ${v}`).join(', ') +
            '. External macros (drop_dm_object_name, globedistance, get_asset) ship with ' +
            'Splunk_SA_CIM, not the rules, and will break a search on a Splunk without it.',
        };
      } else {
        vocabulary = {
          available: true,
          confidence: catalog.cql.confidence,
          derivedFrom: catalog.cql.source,
          authority: catalog.cql.authority,
          eventCount: catalog.cql.eventCount,
          undocumentedCount: catalog.cql.eventCount - catalog.cql.documentedCount,
          commonEvents: [
            'ProcessRollup2', 'SyntheticProcessRollup2', 'DnsRequest', 'NetworkConnectIP4',
            'NetworkReceiveAcceptIP4', 'NewExecutableWritten', 'CommandHistory',
            'RegSystemConfigValueUpdate', 'ScriptControlScanTelemetry',
            'SuspiciousCredentialModuleLoad', 'ProcessTokenStolen', 'DllInjection',
          ].filter(e => e in catalog.cql.events),
        };
      }
    }

    return {
      language: spec.id,
      name: spec.name,
      engine: spec.engine,
      confidence: spec.confidence,
      authority: spec.authority,
      dataModel: spec.dataModel,
      operators: spec.operators,
      cost: spec.cost,
      prohibitions: spec.prohibitions.map(p => ({
        id: p.id, severity: p.severity, title: p.title, reason: p.reason, fix: p.fix,
      })),
      notes: spec.notes,
      sharedPrinciples: SHARED_PRINCIPLES,
      vocabulary,
      examples: include_examples ? examplesFor(lang, shape) : undefined,
      nextStep:
        'Write the query, then call validate_query with the same language to check it before ' +
        'presenting it. Do not present an unvalidated query as final.',
    };
  },
});

const validateQueryTool = defineTool({
  name: 'validate_query',
  description:
    'Check a detection query deterministically before presenting it. Verifies every table, ' +
    'field, data model, event name and Splunk macro against a catalog derived from the local ' +
    'detection corpus, and enforces per-language prohibitions. Call this on every KQL, SPL or ' +
    'CQL query you generate. Blocking findings mean the query would fail or silently return ' +
    'nothing and must be fixed; warnings mean it works but is slower or less portable than it ' +
    'should be. Returns structured findings with suggested corrections.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'The query text to validate.' },
      language: {
        type: 'string',
        description: 'kql | spl | cql (aliases accepted: sentinel, splunk, crowdstrike, logscale).',
      },
    },
    required: ['query', 'language'],
  },
  handler: async (args) => {
    const { query, language } = args as { query: string; language: string };
    const lang = normaliseLanguage(language);
    if (!lang) {
      return {
        error: true,
        message: `Unknown language "${language}". Supported: ${LANGUAGE_IDS.join(', ')}.`,
        supported: LANGUAGE_IDS,
      };
    }
    if (!query || !String(query).trim()) {
      return { error: true, message: 'No query provided.' };
    }

    const result = validateQuery(String(query), lang);
    return {
      ...result,
      summary:
        result.valid
          ? `Passes. ${result.warnings.length} warning(s).`
          : `${result.blocking.length} blocking issue(s) must be fixed. ` +
            `${result.warnings.length} warning(s).`,
      guidance: result.valid
        ? result.warnings.length > 0
          ? 'Safe to present. Address the warnings if performance or portability matter, and ' +
            'state any confidence caveats alongside the query.'
          : 'Safe to present.'
        : 'Do not present this query. Fix each blocking finding — the suggestions field carries ' +
          'the closest known names — then validate again.',
    };
  },
});

export const engineeringTools: ToolDefinition[] = [getQueryLanguageSpec, validateQueryTool];
export const engineeringToolCount = engineeringTools.length;
