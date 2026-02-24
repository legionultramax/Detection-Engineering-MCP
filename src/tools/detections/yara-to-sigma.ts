// YARA to Sigma Converter Tool
// Best-effort conversion from YARA rules to Sigma detection rules

interface YARAMeta {
  description?: string;
  author?: string;
  reference?: string;
  date?: string;
  tags?: string[];
  [key: string]: unknown;
}

interface YARAString {
  name: string;
  type: 'text' | 'regex' | 'hex';
  value: string;
  modifiers: string[];
}

interface ParsedYARA {
  ruleName: string;
  meta: YARAMeta;
  strings: YARAString[];
  condition: string;
}

interface ConversionResult {
  sigma_rule: string;
  notes: string[];
  warnings: string[];
}

// Generate UUID for Sigma rule
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Parse YARA rule into components
function parseYARARule(yaraRule: string): ParsedYARA {
  const result: ParsedYARA = {
    ruleName: 'unknown_rule',
    meta: {},
    strings: [],
    condition: '',
  };

  // Extract rule name
  const ruleNameMatch = yaraRule.match(/rule\s+(\w+)/i);
  if (ruleNameMatch) {
    result.ruleName = ruleNameMatch[1];
  }

  // Extract meta section
  const metaMatch = yaraRule.match(/meta\s*:\s*([\s\S]*?)(?=strings\s*:|condition\s*:|$)/i);
  if (metaMatch) {
    const metaContent = metaMatch[1];
    
    // Parse individual meta fields
    const descMatch = metaContent.match(/description\s*=\s*"([^"]*)"/i);
    if (descMatch) result.meta.description = descMatch[1];
    
    const authorMatch = metaContent.match(/author\s*=\s*"([^"]*)"/i);
    if (authorMatch) result.meta.author = authorMatch[1];
    
    const refMatch = metaContent.match(/reference\s*=\s*"([^"]*)"/i);
    if (refMatch) result.meta.reference = refMatch[1];
    
    const dateMatch = metaContent.match(/date\s*=\s*"([^"]*)"/i);
    if (dateMatch) result.meta.date = dateMatch[1];

    // Extract tags/mitre references
    const tagsMatches = metaContent.matchAll(/(?:mitre_attack|attack|technique|tactic)\s*=\s*"([^"]*)"/gi);
    const tags: string[] = [];
    for (const match of tagsMatches) {
      tags.push(match[1]);
    }
    if (tags.length > 0) result.meta.tags = tags;
  }

  // Extract strings section
  const stringsMatch = yaraRule.match(/strings\s*:\s*([\s\S]*?)(?=condition\s*:|$)/i);
  if (stringsMatch) {
    const stringsContent = stringsMatch[1];
    
    // Text strings: $name = "text" [modifiers]
    const textStringRegex = /(\$\w+)\s*=\s*"([^"]*)"(\s+(?:nocase|wide|ascii|fullword))?/g;
    let match;
    while ((match = textStringRegex.exec(stringsContent)) !== null) {
      const modifiers: string[] = [];
      if (match[3]) {
        if (match[3].includes('nocase')) modifiers.push('nocase');
        if (match[3].includes('wide')) modifiers.push('wide');
        if (match[3].includes('ascii')) modifiers.push('ascii');
        if (match[3].includes('fullword')) modifiers.push('fullword');
      }
      result.strings.push({
        name: match[1],
        type: 'text',
        value: match[2],
        modifiers,
      });
    }
    
    // Regex strings: $name = /regex/ [modifiers]
    const regexStringRegex = /(\$\w+)\s*=\s*\/([^\/]*)\/(\w*)/g;
    while ((match = regexStringRegex.exec(stringsContent)) !== null) {
      const modifiers: string[] = [];
      if (match[3]?.includes('i')) modifiers.push('nocase');
      result.strings.push({
        name: match[1],
        type: 'regex',
        value: match[2],
        modifiers,
      });
    }
    
    // Hex strings: $name = { AA BB CC }
    const hexStringRegex = /(\$\w+)\s*=\s*\{\s*([^}]*)\s*\}/g;
    while ((match = hexStringRegex.exec(stringsContent)) !== null) {
      result.strings.push({
        name: match[1],
        type: 'hex',
        value: match[2].replace(/\s+/g, ''),
        modifiers: [],
      });
    }
  }

  // Extract condition
  const conditionMatch = yaraRule.match(/condition\s*:\s*([\s\S]*?)(?:\}|$)/i);
  if (conditionMatch) {
    result.condition = conditionMatch[1].trim().replace(/\s+/g, ' ');
  }

  return result;
}

// Convert hex string to ASCII (best effort)
function hexToAscii(hex: string): string | null {
  try {
    // Remove wildcards and spaces
    const cleanHex = hex.replace(/[\s\?\[\]]/g, '');
    if (cleanHex.length % 2 !== 0) return null;
    
    let ascii = '';
    for (let i = 0; i < cleanHex.length; i += 2) {
      const byte = parseInt(cleanHex.substr(i, 2), 16);
      if (byte >= 32 && byte <= 126) {
        ascii += String.fromCharCode(byte);
      } else {
        // Non-printable character
        return null;
      }
    }
    return ascii;
  } catch {
    return null;
  }
}

// Map YARA strings to Sigma detection selection
function mapStringsToSigma(
  strings: YARAString[],
  targetField: string
): { selection: Record<string, unknown>; notes: string[] } {
  const selection: Record<string, unknown> = {};
  const notes: string[] = [];
  
  const containsValues: string[] = [];
  const regexValues: string[] = [];
  
  for (const str of strings) {
    switch (str.type) {
      case 'text': {
        let value = str.value;
        // Handle escape sequences
        value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t');
        containsValues.push(value);
        break;
      }
      
      case 'regex': {
        regexValues.push(str.value);
        notes.push(`Regex pattern "${str.name}" mapped to |re modifier - verify compatibility`);
        break;
      }
      
      case 'hex': {
        const ascii = hexToAscii(str.value);
        if (ascii) {
          containsValues.push(ascii);
          notes.push(`Hex string "${str.name}" decoded to ASCII: "${ascii}"`);
        } else {
          notes.push(`Hex string "${str.name}" could not be converted - contains non-printable chars or wildcards`);
          // Add as comment
          containsValues.push(`[HEX:${str.value}]`);
        }
        break;
      }
    }
  }
  
  if (containsValues.length > 0) {
    selection[`${targetField}|contains`] = containsValues.length === 1 ? containsValues[0] : containsValues;
  }
  
  if (regexValues.length > 0) {
    selection[`${targetField}|re`] = regexValues.length === 1 ? regexValues[0] : regexValues;
  }
  
  return { selection, notes };
}

// Determine Sigma condition from YARA condition
function mapCondition(yaraCondition: string, stringCount: number): { condition: string; notes: string[] } {
  const notes: string[] = [];
  let condition = 'selection';
  
  const condLower = yaraCondition.toLowerCase();
  
  if (condLower.includes('all of them') || condLower.includes('all of ($')) {
    condition = 'all of selection*';
    notes.push('YARA "all of" mapped to Sigma "all of selection*"');
  } else if (condLower.includes('any of them') || condLower.includes('any of ($')) {
    condition = 'selection';
    notes.push('YARA "any of" mapped to standard selection (OR logic)');
  } else if (condLower.match(/(\d+)\s+of\s+them/)) {
    const match = condLower.match(/(\d+)\s+of\s+them/);
    if (match) {
      const count = parseInt(match[1]);
      condition = `${count} of selection*`;
      notes.push(`YARA "${count} of them" mapped to Sigma "${count} of selection*"`);
    }
  } else if (condLower.includes('filesize')) {
    notes.push('YARA filesize condition cannot be mapped to Sigma log-based detection');
  } else if (condLower.includes('uint') || condLower.includes('int')) {
    notes.push('YARA integer/byte conditions cannot be directly mapped to Sigma');
  }
  
  return { condition, notes };
}

// Guess MITRE tags from content
function guessMitreTags(parsed: ParsedYARA): string[] {
  const tags: string[] = [];
  
  // Check meta tags first
  if (parsed.meta.tags) {
    for (const tag of parsed.meta.tags) {
      if (tag.match(/T\d{4}/)) {
        tags.push(`attack.${tag.toLowerCase()}`);
      }
    }
  }
  
  // Keyword-based guessing
  const content = `${parsed.meta.description || ''} ${parsed.strings.map(s => s.value).join(' ')}`.toLowerCase();
  
  if (content.includes('powershell') || content.includes('pwsh')) {
    tags.push('attack.execution');
    tags.push('attack.t1059.001');
  }
  if (content.includes('mimikatz') || content.includes('credential') || content.includes('lsass')) {
    tags.push('attack.credential_access');
    tags.push('attack.t1003');
  }
  if (content.includes('persistence') || content.includes('autorun') || content.includes('startup')) {
    tags.push('attack.persistence');
  }
  if (content.includes('inject') || content.includes('hollowing')) {
    tags.push('attack.defense_evasion');
    tags.push('attack.t1055');
  }
  if (content.includes('ransomware') || content.includes('encrypt')) {
    tags.push('attack.impact');
    tags.push('attack.t1486');
  }
  if (content.includes('c2') || content.includes('beacon') || content.includes('cobalt')) {
    tags.push('attack.command_and_control');
  }
  
  // Default if nothing found
  if (tags.length === 0) {
    tags.push('attack.execution');
    tags.push('attack.defense_evasion');
  }
  
  return [...new Set(tags)];
}

// Main conversion function
export function convertYARAToSigma(
  yaraRule: string,
  options: {
    logsource_category?: string;
    product?: string;
    title_override?: string;
  } = {}
): ConversionResult {
  const {
    logsource_category = 'process_creation',
    product = 'windows',
    title_override,
  } = options;
  
  const warnings: string[] = [
    '⚠️ IMPORTANT: This is an APPROXIMATE conversion only!',
    '⚠️ YARA rules scan file content; Sigma rules analyze log events.',
    '⚠️ Manual review and testing is MANDATORY before production use.',
    '⚠️ String patterns may not appear in logs the same way as in files.',
  ];
  
  const notes: string[] = [];
  
  // Parse the YARA rule
  const parsed = parseYARARule(yaraRule);
  
  if (parsed.strings.length === 0) {
    warnings.push('⚠️ No strings found in YARA rule - generated Sigma may be incomplete');
  }
  
  // Determine target field based on logsource
  let targetField = 'CommandLine';
  if (logsource_category === 'file_event') {
    targetField = 'TargetFilename';
  } else if (logsource_category === 'network_connection') {
    targetField = 'DestinationHostname';
  } else if (logsource_category === 'registry_event') {
    targetField = 'TargetObject';
  }
  
  // Map strings to Sigma selection
  const { selection, notes: stringNotes } = mapStringsToSigma(parsed.strings, targetField);
  notes.push(...stringNotes);
  
  // Map condition
  const { condition, notes: conditionNotes } = mapCondition(parsed.condition, parsed.strings.length);
  notes.push(...conditionNotes);
  
  // Guess MITRE tags
  const mitreTags = guessMitreTags(parsed);
  
  // Build title
  const title = title_override || 
    parsed.meta.description || 
    `Converted YARA Rule: ${parsed.ruleName}`;
  
  // Build Sigma rule
  const sigmaRule = `title: '${title.replace(/'/g, "''")}'
id: ${generateUUID()}
status: experimental
description: |
  Auto-converted from YARA rule: ${parsed.ruleName}
  ${parsed.meta.description ? `Original description: ${parsed.meta.description}` : ''}
  WARNING: This is an approximate conversion. Manual review required.
references:
${parsed.meta.reference ? `  - ${parsed.meta.reference}` : '  - https://github.com/Neo23x0/signature-base'}
author: MCP Converter (original: ${parsed.meta.author || 'Unknown'})
date: ${new Date().toISOString().split('T')[0]}
modified: ${new Date().toISOString().split('T')[0]}
tags:
${mitreTags.map(t => `  - ${t}`).join('\n')}
logsource:
  category: ${logsource_category}
  product: ${product}
detection:
  selection:
${Object.entries(selection).map(([key, value]) => {
  if (Array.isArray(value)) {
    return `    ${key}:\n${value.map(v => `      - '${String(v).replace(/'/g, "''")}'`).join('\n')}`;
  } else {
    return `    ${key}: '${String(value).replace(/'/g, "''")}'`;
  }
}).join('\n')}
  condition: ${condition}
falsepositives:
  - Unknown - manual tuning required
  - Legitimate software using similar patterns
  - This rule was auto-converted from a file-based YARA rule
level: high
# Original YARA condition: ${parsed.condition}
# Original YARA strings count: ${parsed.strings.length}`;

  return {
    sigma_rule: sigmaRule,
    notes,
    warnings,
  };
}

// Tool definition and handler
export const yaraToSigmaTool = {
  name: 'convert_yara_to_sigma',
  description: 'Convert a YARA rule to an approximate Sigma rule. Best-effort conversion focused on string/hex conditions mapped to process_creation logs (CommandLine). Always include a warning that manual review is required.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      yara_rule: { 
        type: 'string', 
        description: 'The full YARA rule text to convert' 
      },
      logsource_category: { 
        type: 'string', 
        description: 'Sigma logsource category (default: process_creation). Options: process_creation, file_event, network_connection, registry_event' 
      },
      product: { 
        type: 'string', 
        description: 'Target product (default: windows)' 
      },
      title_override: { 
        type: 'string', 
        description: 'Custom title for the generated Sigma rule' 
      },
    },
    required: ['yara_rule'],
  },
};

export function handleYARAToSigma(args: {
  yara_rule: string;
  logsource_category?: string;
  product?: string;
  title_override?: string;
}): string {
  const result = convertYARAToSigma(args.yara_rule, {
    logsource_category: args.logsource_category,
    product: args.product,
    title_override: args.title_override,
  });
  
  let output = '## Conversion Result\n\n';
  
  // Warnings first
  output += '### ⚠️ Warnings\n';
  for (const warning of result.warnings) {
    output += `${warning}\n`;
  }
  output += '\n';
  
  // Notes
  if (result.notes.length > 0) {
    output += '### Conversion Notes\n';
    for (const note of result.notes) {
      output += `- ${note}\n`;
    }
    output += '\n';
  }
  
  // Sigma rule
  output += '### Generated Sigma Rule\n';
  output += '```yaml\n';
  output += result.sigma_rule;
  output += '\n```\n';
  
  return output;
}
