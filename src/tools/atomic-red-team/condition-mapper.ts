/**
 * Sigma Condition → ART Artifact Mapper
 *
 * Static analysis only — never executes anything.
 * Parses Sigma YAML detection blocks into structured conditions,
 * then cross-references each condition against stored ART test commands.
 *
 * Honest scope:
 *   MATCHED         — CommandLine/Image conditions verified against ART command text
 *   INFERRED        — ParentImage/executor inferred from ART executor type
 *   UNABLE_TO_VERIFY — registry, network, file, access mask, user context (ART doesn't record these)
 */

import { getTestsByTechnique, type ARTTestRow } from '../../db/atomic-red-team.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ParsedCondition {
  field: string;
  modifier: string;       // 'contains' | 'endswith' | 'startswith' | 'is' | 're' | 'contains|all' | 'base64offset|contains'
  values: string[];       // one or more values (list in YAML becomes multiple)
  block: string;          // 'selection', 'selection_cmd', 'filter_main', etc.
  raw: string;            // original YAML line for display
  isFilter: boolean;      // true if block name starts with 'filter'
}

export type MatchStatus = 'MATCHED' | 'INFERRED' | 'PARTIAL' | 'UNABLE_TO_VERIFY' | 'NOT_IN_ART';

export interface ConditionMatch {
  condition: ParsedCondition;
  status: MatchStatus;
  reason: string;
  artMatches: Array<{
    testNum: number;
    testName: string;
    matchedIn: 'command' | 'input_arguments' | 'description' | 'executor';
    excerpt: string;  // the matching fragment, max 120 chars
  }>;
}

export interface UncoveredTest {
  testNum: number;
  testName: string;
  guid: string;
  commandPreview: string;
  reason: string;
}

export interface MapResult {
  parseStatus: 'OK' | 'PARTIAL_PARSE' | 'PARSE_FAILED';
  parseWarnings: string[];
  conditions: ParsedCondition[];
  matchMatrix: ConditionMatch[];
  uncoveredArtTests: UncoveredTest[];
  summary: {
    totalConditions: number;
    matched: number;
    inferred: number;
    unableToVerify: number;
    notInArt: number;
    conditionCoverage: string;   // "3/5 (60%)"
    artTestsTotal: number;
    artTestsCovered: number;
    artCoverage: string;          // "2/4 (50%)"
  };
}

// ── Field classification ───────────────────────────────────────────────────
// Which Sigma fields can we validate against ART command text?

const COMMAND_LINE_FIELDS = new Set([
  'commandline', 'command_line', 'processcommandline',
  'parentcommandline', 'initiatingprocesscommandline',
]);

const IMAGE_FIELDS = new Set([
  'image', 'sourceimage', 'targetimage', 'parentimage',
  'initiatingprocessfilename', 'filename', 'originalfilename',
  'processname', 'process_name', 'newprocessname',
]);

const PARENT_FIELDS = new Set([
  'parentimage', 'parentcommandline', 'initiatingprocessfilename',
  'initiatingprocesscommandline',
]);

// Fields ART data fundamentally cannot verify
const UNVERIFIABLE_FIELDS = new Set([
  'targetobject', 'details',                                    // registry
  'targetfilename',                                              // file create (partial — see input_arguments)
  'destinationip', 'destinationport', 'sourceip', 'sourceport', // network
  'destinationhostname', 'queryname', 'queryresults',           // dns
  'grantedaccess', 'calltrace',                                 // process access
  'hashes', 'md5', 'sha256', 'sha1', 'imphash',               // hashes
  'user', 'subjectusername', 'targetusername', 'accountname',   // user context
  'integritylevel', 'logonid', 'logontype',                     // auth
  'signed', 'signature', 'signaturestatus',                     // signing
  'pipename',                                                    // named pipes
  'imageloaded',                                                 // dll load
  'currentdirectory',
]);

// Executor → likely parent process path
const EXECUTOR_PARENT_MAP: Record<string, string> = {
  'command_prompt': '\\cmd.exe',
  'powershell': '\\powershell.exe',
  'bash': '/bin/bash',
  'sh': '/bin/sh',
  'manual': '',
};

// Common LOL binary → full paths (for Image|endswith matching)
const BINARY_PATH_MAP: Record<string, string[]> = {
  'certutil': ['\\certutil.exe'],
  'certutil.exe': ['\\certutil.exe'],
  'powershell': ['\\powershell.exe', '\\pwsh.exe'],
  'powershell.exe': ['\\powershell.exe'],
  'cmd': ['\\cmd.exe'],
  'cmd.exe': ['\\cmd.exe'],
  'mshta': ['\\mshta.exe'],
  'mshta.exe': ['\\mshta.exe'],
  'rundll32': ['\\rundll32.exe'],
  'rundll32.exe': ['\\rundll32.exe'],
  'regsvr32': ['\\regsvr32.exe'],
  'regsvr32.exe': ['\\regsvr32.exe'],
  'wmic': ['\\wmic.exe'],
  'wmic.exe': ['\\wmic.exe'],
  'bitsadmin': ['\\bitsadmin.exe'],
  'bitsadmin.exe': ['\\bitsadmin.exe'],
  'cscript': ['\\cscript.exe'],
  'cscript.exe': ['\\cscript.exe'],
  'wscript': ['\\wscript.exe'],
  'wscript.exe': ['\\wscript.exe'],
  'schtasks': ['\\schtasks.exe'],
  'schtasks.exe': ['\\schtasks.exe'],
  'reg': ['\\reg.exe'],
  'reg.exe': ['\\reg.exe'],
  'net': ['\\net.exe'],
  'net.exe': ['\\net.exe'],
  'net1': ['\\net1.exe'],
  'net1.exe': ['\\net1.exe'],
  'sc': ['\\sc.exe'],
  'sc.exe': ['\\sc.exe'],
  'nltest': ['\\nltest.exe'],
  'nltest.exe': ['\\nltest.exe'],
  'whoami': ['\\whoami.exe'],
  'whoami.exe': ['\\whoami.exe'],
  'ipconfig': ['\\ipconfig.exe'],
  'ipconfig.exe': ['\\ipconfig.exe'],
  'tasklist': ['\\tasklist.exe'],
  'tasklist.exe': ['\\tasklist.exe'],
  'cmstp': ['\\cmstp.exe'],
  'cmstp.exe': ['\\cmstp.exe'],
  'esentutl': ['\\esentutl.exe'],
  'esentutl.exe': ['\\esentutl.exe'],
  'expand': ['\\expand.exe'],
  'expand.exe': ['\\expand.exe'],
  'findstr': ['\\findstr.exe'],
  'findstr.exe': ['\\findstr.exe'],
  'forfiles': ['\\forfiles.exe'],
  'forfiles.exe': ['\\forfiles.exe'],
  'installutil': ['\\installutil.exe'],
  'installutil.exe': ['\\installutil.exe'],
  'msiexec': ['\\msiexec.exe'],
  'msiexec.exe': ['\\msiexec.exe'],
  'msconfig': ['\\msconfig.exe'],
  'msconfig.exe': ['\\msconfig.exe'],
};

// ── Sigma detection block parser ───────────────────────────────────────────

/**
 * Parse a Sigma YAML rule string into structured conditions.
 * Handles the 85% case: key-value pairs with pipe modifiers.
 * Returns PARTIAL_PARSE for complex constructs (1 of selection_*, all of them).
 */
export function parseSigmaDetection(sigmaYaml: string): {
  conditions: ParsedCondition[];
  parseStatus: 'OK' | 'PARTIAL_PARSE' | 'PARSE_FAILED';
  warnings: string[];
} {
  const conditions: ParsedCondition[] = [];
  const warnings: string[] = [];

  // Find the detection block
  const detectionMatch = sigmaYaml.match(/^detection:\s*$/m);
  if (!detectionMatch) {
    // Try inline detection
    const inlineMatch = sigmaYaml.match(/detection:/);
    if (!inlineMatch) {
      return { conditions: [], parseStatus: 'PARSE_FAILED', warnings: ['No detection: block found in YAML'] };
    }
  }

  // Extract everything after "detection:" until the next top-level key or EOF
  const detectionStart = sigmaYaml.indexOf('detection:');
  const afterDetection = sigmaYaml.substring(detectionStart + 'detection:'.length);

  // Find where the detection block ends (next top-level key with no indent)
  const lines = afterDetection.split('\n');
  const detectionLines: string[] = [];
  for (const line of lines) {
    // Skip empty lines
    if (line.trim() === '') {
      detectionLines.push(line);
      continue;
    }
    // Top-level key (no leading whitespace, has colon) = end of detection block
    if (/^[a-zA-Z_][\w]*:/.test(line)) break;
    detectionLines.push(line);
  }

  // Parse block structure
  let currentBlock = '';
  let pendingField = '';
  let pendingModifier = '';
  let pendingRaw = '';

  for (let i = 0; i < detectionLines.length; i++) {
    const line = detectionLines[i];
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    // Detect block headers (e.g., "    selection:", "    filter_main:", "    selection_cmd:")
    const blockMatch = trimmed.match(/^(selection[\w]*|filter[\w]*|condition):\s*(.*)$/);
    if (blockMatch) {
      const blockName = blockMatch[1];

      // Skip condition line — we don't need to parse boolean logic for matching
      if (blockName === 'condition') {
        // But check for complex constructs we can't fully parse
        const condValue = blockMatch[2].trim();
        if (condValue.includes('1 of') || condValue.includes('all of them')) {
          warnings.push(`Complex condition: "${condValue}" — parsed available blocks but boolean logic not fully evaluated`);
        }
        continue;
      }

      currentBlock = blockName;

      // Check if there's an inline value (e.g., "selection: value")
      if (blockMatch[2] && blockMatch[2].trim()) {
        // Rare but handle it
      }
      continue;
    }

    if (!currentBlock || currentBlock === 'condition') continue;

    const isFilter = currentBlock.startsWith('filter');

    // Field: value line (e.g., "        Image|endswith: '\certutil.exe'")
    const fieldMatch = trimmed.match(/^([\w.]+?)(\|[\w|]+)?:\s*(.*)$/);
    if (fieldMatch) {
      // If we had a pending multi-value field, flush it
      if (pendingField && pendingRaw) {
        // This shouldn't happen normally — pendingField gets flushed below
      }

      const field = fieldMatch[1];
      const modifier = fieldMatch[2] ? fieldMatch[2].substring(1) : 'is'; // remove leading |
      const value = fieldMatch[3].trim();

      if (value === '' || value === '|') {
        // Multi-line value list follows — collect on next lines
        pendingField = field;
        pendingModifier = modifier;
        pendingRaw = trimmed;
        continue;
      }

      // Single value — check if it's a YAML list start
      if (value.startsWith('- ')) {
        // Shouldn't happen on same line as field, but handle it
        const cleanVal = cleanYamlValue(value.substring(2));
        conditions.push({
          field, modifier, values: [cleanVal],
          block: currentBlock, raw: trimmed, isFilter,
        });
        pendingField = field;
        pendingModifier = modifier;
        pendingRaw = trimmed;
        continue;
      }

      // Plain single value
      const cleanVal = cleanYamlValue(value);
      conditions.push({
        field, modifier, values: [cleanVal],
        block: currentBlock, raw: trimmed, isFilter,
      });
      pendingField = '';
      continue;
    }

    // List item line (e.g., "            - '-decode'")
    const listMatch = trimmed.match(/^-\s+(.+)$/);
    if (listMatch && pendingField) {
      const val = cleanYamlValue(listMatch[1]);

      // Check if last condition is for the same field+block — append to its values
      const lastCond = conditions[conditions.length - 1];
      if (lastCond && lastCond.field === pendingField && lastCond.block === currentBlock) {
        lastCond.values.push(val);
        lastCond.raw += ` | ${val}`;
      } else {
        // First list item for this field
        conditions.push({
          field: pendingField,
          modifier: pendingModifier,
          values: [val],
          block: currentBlock,
          raw: `${pendingField}|${pendingModifier}: [${val}, ...]`,
          isFilter,
        });
      }
      continue;
    }

    // Unrecognized line in detection block
    if (trimmed && !trimmed.startsWith('#')) {
      warnings.push(`Unparsed line in ${currentBlock}: "${trimmed}"`);
    }
  }

  const parseStatus = conditions.length === 0
    ? 'PARSE_FAILED'
    : warnings.length > 0
      ? 'PARTIAL_PARSE'
      : 'OK';

  return { conditions, parseStatus, warnings };
}

function cleanYamlValue(raw: string): string {
  let v = raw.trim();
  // Remove YAML quotes
  if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) {
    v = v.substring(1, v.length - 1);
  }
  return v;
}

// ── ART command expansion ──────────────────────────────────────────────────

/**
 * Expand ART command by substituting input_arguments with their default values.
 * ART commands use #{variable_name} syntax.
 */
function expandArtCommand(command: string | null, inputArgs: string | null): string {
  if (!command) return '';
  let expanded = command;
  if (inputArgs) {
    try {
      const args = JSON.parse(inputArgs) as Record<string, { default?: string | number | boolean }>;
      for (const [key, val] of Object.entries(args)) {
        if (val && val.default !== undefined) {
          expanded = expanded.replace(
            new RegExp(`#\\{${key}\\}`, 'g'),
            String(val.default)
          );
        }
      }
    } catch { /* ignore parse errors */ }
  }
  return expanded;
}

/**
 * Extract the first binary/executable token from an ART command.
 * e.g., "certutil -decode foo bar" → "certutil"
 * e.g., "C:\Windows\System32\certutil.exe -decode" → "certutil.exe"
 */
function extractBinaryFromCommand(command: string): string {
  const trimmed = command.trim();
  // Handle common prefixes
  let cleaned = trimmed;
  // Remove common PowerShell invocations
  if (cleaned.toLowerCase().startsWith('start-process ')) {
    cleaned = cleaned.substring('start-process '.length).trim();
  }
  if (cleaned.toLowerCase().startsWith('invoke-expression ')) {
    cleaned = cleaned.substring('invoke-expression '.length).trim();
  }

  // Get first token (split on space, pipe, semicolon, ampersand)
  const firstToken = cleaned.split(/[\s|;&]+/)[0];
  // Get just the filename from a path
  const parts = firstToken.split(/[\\/]/);
  return parts[parts.length - 1].replace(/['"]/g, '').toLowerCase();
}

// ── Core matching engine ───────────────────────────────────────────────────

/**
 * Check if a single value matches against text using the specified modifier.
 */
function matchValue(text: string, value: string, modifier: string): boolean {
  const textLower = text.toLowerCase();
  const valLower = value.toLowerCase();

  // Handle compound modifiers like "contains|all" — for single value, treat as contains
  const primaryMod = modifier.split('|')[0];

  switch (primaryMod) {
    case 'contains':
      return textLower.includes(valLower);
    case 'endswith':
      return textLower.endsWith(valLower);
    case 'startswith':
      return textLower.startsWith(valLower);
    case 'is':
    case 'equals':
      return textLower === valLower;
    case 're':
      try {
        return new RegExp(value, 'i').test(text);
      } catch {
        return textLower.includes(valLower); // fallback
      }
    case 'base64offset':
      // Check if the plaintext value appears in the command (base64 patterns hard to verify statically)
      return textLower.includes(valLower);
    default:
      // Unknown modifier — fall back to contains
      return textLower.includes(valLower);
  }
}

/**
 * Check if a condition matches against an ART test.
 * Returns match details or null if no match.
 */
function matchConditionAgainstTest(
  cond: ParsedCondition,
  test: ARTTestRow,
  expandedCommand: string,
): ConditionMatch['artMatches'][number] | null {
  const fieldLower = cond.field.toLowerCase();
  const isAllModifier = cond.modifier.includes('all');

  // Determine what text to match against based on the field type
  if (COMMAND_LINE_FIELDS.has(fieldLower)) {
    // Direct match against ART command text
    const matched = isAllModifier
      ? cond.values.every(v => matchValue(expandedCommand, v, cond.modifier))
      : cond.values.some(v => matchValue(expandedCommand, v, cond.modifier));

    if (matched) {
      const excerpt = expandedCommand.substring(0, 120);
      return { testNum: test.test_number, testName: test.test_name, matchedIn: 'command', excerpt };
    }
    return null;
  }

  if (IMAGE_FIELDS.has(fieldLower)) {
    // For Image/OriginalFileName fields, try to match against the binary in the command
    const binary = extractBinaryFromCommand(expandedCommand);
    const binaryPaths = BINARY_PATH_MAP[binary] || [`\\${binary}`];

    const matched = cond.values.some(v => {
      const valLower = v.toLowerCase();
      // Check if any known path for this binary matches the condition
      return binaryPaths.some(bp => matchValue(bp, valLower, cond.modifier))
        || matchValue(binary, valLower, cond.modifier)
        || matchValue(expandedCommand, valLower, cond.modifier);
    });

    if (matched) {
      return { testNum: test.test_number, testName: test.test_name, matchedIn: 'command', excerpt: binary };
    }
    return null;
  }

  if (PARENT_FIELDS.has(fieldLower)) {
    // Infer parent from executor type
    const parentSuffix = EXECUTOR_PARENT_MAP[test.executor_name] || '';
    if (!parentSuffix) return null;

    const matched = cond.values.some(v => matchValue(parentSuffix, v, cond.modifier));
    if (matched) {
      return { testNum: test.test_number, testName: test.test_name, matchedIn: 'executor', excerpt: `executor=${test.executor_name} → parent=${parentSuffix}` };
    }
    return null;
  }

  // For TargetFilename — try input_arguments (ART sometimes stores file paths there)
  if (fieldLower === 'targetfilename' && test.input_arguments) {
    try {
      const args = JSON.parse(test.input_arguments) as Record<string, { default?: string | number | boolean }>;
      for (const [, val] of Object.entries(args)) {
        if (val && val.default && typeof val.default === 'string') {
          const matched = cond.values.some(v => matchValue(String(val.default), v, cond.modifier));
          if (matched) {
            return { testNum: test.test_number, testName: test.test_name, matchedIn: 'input_arguments', excerpt: String(val.default).substring(0, 120) };
          }
        }
      }
    } catch { /* ignore */ }
  }

  // For registry fields — try matching against command text (reg add, Set-ItemProperty, etc.)
  if (fieldLower === 'targetobject' || fieldLower === 'details') {
    // ART commands often contain the full registry path inline
    const matched = cond.values.some(v => matchValue(expandedCommand, v, cond.modifier));
    if (matched) {
      return { testNum: test.test_number, testName: test.test_name, matchedIn: 'command', excerpt: expandedCommand.substring(0, 120) };
    }
    // Don't return null yet — fall through to UNABLE_TO_VERIFY
  }

  return null;
}

// ── Main export ────────────────────────────────────────────────────────────

/**
 * Map Sigma rule conditions to ART test artifacts.
 *
 * @param sigmaYaml - Full Sigma rule YAML text
 * @param techniqueId - MITRE technique ID (e.g., "T1059.001")
 * @returns Structured match matrix with honest status per condition
 */
export function mapConditionsToArt(sigmaYaml: string, techniqueId: string): MapResult {
  // Step 1: Parse Sigma conditions
  const { conditions, parseStatus, warnings } = parseSigmaDetection(sigmaYaml);

  if (parseStatus === 'PARSE_FAILED') {
    return {
      parseStatus: 'PARSE_FAILED',
      parseWarnings: warnings,
      conditions: [],
      matchMatrix: [],
      uncoveredArtTests: [],
      summary: {
        totalConditions: 0, matched: 0, inferred: 0,
        unableToVerify: 0, notInArt: 0,
        conditionCoverage: '0/0', artTestsTotal: 0,
        artTestsCovered: 0, artCoverage: '0/0',
      },
    };
  }

  // Step 2: Get ART tests
  const tid = techniqueId.toUpperCase().trim();
  const artTests = getTestsByTechnique(tid);

  // Also try parent technique if sub-technique has no tests
  let allTests = artTests;
  if (artTests.length === 0 && tid.includes('.')) {
    const parentTid = tid.split('.')[0];
    allTests = getTestsByTechnique(parentTid);
  }

  // Expand all ART commands with default argument values
  const expandedTests = allTests.map(t => ({
    test: t,
    expandedCommand: expandArtCommand(t.command, t.input_arguments),
  }));

  // Step 3: Match each condition
  const matchMatrix: ConditionMatch[] = [];
  const artTestMatchedSet = new Set<number>(); // track which tests got matched

  // Only match selection conditions (not filters — filters are FP suppression, not detection)
  const selectionConditions = conditions.filter(c => !c.isFilter);
  const filterConditions = conditions.filter(c => c.isFilter);

  for (const cond of selectionConditions) {
    const fieldLower = cond.field.toLowerCase();

    // If no ART tests at all
    if (expandedTests.length === 0) {
      matchMatrix.push({
        condition: cond,
        status: 'NOT_IN_ART',
        reason: `No ART tests found for ${tid}`,
        artMatches: [],
      });
      continue;
    }

    // Check if field is fundamentally unverifiable
    if (UNVERIFIABLE_FIELDS.has(fieldLower)) {
      // But first try — some "unverifiable" fields might be partially matchable from command text
      const partialMatches: ConditionMatch['artMatches'] = [];
      for (const { test, expandedCommand } of expandedTests) {
        const match = matchConditionAgainstTest(cond, test, expandedCommand);
        if (match) {
          partialMatches.push(match);
          artTestMatchedSet.add(test.test_number);
        }
      }
      if (partialMatches.length > 0) {
        matchMatrix.push({
          condition: cond,
          status: 'INFERRED',
          reason: `Field "${cond.field}" found in ART command text (not structured telemetry)`,
          artMatches: partialMatches,
        });
      } else {
        matchMatrix.push({
          condition: cond,
          status: 'UNABLE_TO_VERIFY',
          reason: `ART does not record ${cond.field} telemetry — requires live test or manual review`,
          artMatches: [],
        });
      }
      continue;
    }

    // Try matching against each ART test
    const matches: ConditionMatch['artMatches'] = [];
    for (const { test, expandedCommand } of expandedTests) {
      const match = matchConditionAgainstTest(cond, test, expandedCommand);
      if (match) {
        matches.push(match);
        artTestMatchedSet.add(test.test_number);
      }
    }

    if (matches.length > 0) {
      // Determine if MATCHED or INFERRED based on field type
      const isInferred = PARENT_FIELDS.has(fieldLower);
      matchMatrix.push({
        condition: cond,
        status: isInferred ? 'INFERRED' : 'MATCHED',
        reason: isInferred
          ? `Inferred from ART executor type (${expandedTests[0]?.test.executor_name})`
          : `Condition verified against ${matches.length} ART test(s)`,
        artMatches: matches,
      });
    } else {
      matchMatrix.push({
        condition: cond,
        status: 'NOT_IN_ART',
        reason: `No ART test for ${tid} produces an artifact matching ${cond.field}|${cond.modifier}: ${cond.values[0]}`,
        artMatches: [],
      });
    }
  }

  // Add filter conditions as informational (not scored)
  for (const cond of filterConditions) {
    matchMatrix.push({
      condition: cond,
      status: 'UNABLE_TO_VERIFY',
      reason: 'Filter/FP suppression — not a detection condition, excluded from scoring',
      artMatches: [],
    });
  }

  // Step 4: Find uncovered ART tests (tests no rule condition would catch)
  const uncoveredArtTests: UncoveredTest[] = [];
  for (const { test, expandedCommand } of expandedTests) {
    if (!artTestMatchedSet.has(test.test_number)) {
      uncoveredArtTests.push({
        testNum: test.test_number,
        testName: test.test_name,
        guid: test.guid,
        commandPreview: expandedCommand.substring(0, 200),
        reason: 'No selection condition in the rule matches this test\'s artifacts',
      });
    }
  }

  // Step 5: Compute summary
  const selectionMatches = matchMatrix.filter(m => !m.condition.isFilter);
  const matched = selectionMatches.filter(m => m.status === 'MATCHED').length;
  const inferred = selectionMatches.filter(m => m.status === 'INFERRED').length;
  const unableToVerify = selectionMatches.filter(m => m.status === 'UNABLE_TO_VERIFY').length;
  const notInArt = selectionMatches.filter(m => m.status === 'NOT_IN_ART').length;
  const total = selectionMatches.length;

  const verifiableCount = matched + inferred; // conditions we could check
  const condPct = total > 0 ? Math.round((verifiableCount / total) * 100) : 0;
  const artCoveredCount = artTestMatchedSet.size;
  const artTotal = expandedTests.length;
  const artPct = artTotal > 0 ? Math.round((artCoveredCount / artTotal) * 100) : 0;

  return {
    parseStatus,
    parseWarnings: warnings,
    conditions,
    matchMatrix,
    uncoveredArtTests,
    summary: {
      totalConditions: total,
      matched,
      inferred,
      unableToVerify,
      notInArt,
      conditionCoverage: `${verifiableCount}/${total} (${condPct}%)`,
      artTestsTotal: artTotal,
      artTestsCovered: artCoveredCount,
      artCoverage: `${artCoveredCount}/${artTotal} (${artPct}%)`,
    },
  };
}
