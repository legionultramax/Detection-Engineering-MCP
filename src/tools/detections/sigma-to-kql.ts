// Sigma to KQL Converter Tool
// Converts Sigma detection rules to Kibana Query Language (KQL) for Elastic Stack

import { parse as parseYAML } from 'yaml';

interface ParsedSigma {
  title: string;
  id: string;
  status?: string;
  description: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    [key: string]: unknown;
  };
  level: string;
  tags: string[];
  falsepositives?: string[];
  author?: string;
  date?: string;
}

interface ConversionResult {
  kql_query: string;
  metadata: {
    title: string;
    severity: string;
    mitre_tags: string[];
    data_sources: string[];
  };
  notes: string[];
  warnings: string[];
}

interface FieldMapping {
  kqlField: string;
  category?: string;
}

// Field mapping tables for different log sources (using Elastic Common Schema - ECS)
const FIELD_MAPPINGS: Record<string, Record<string, string>> = {
  // Process Creation (Sysmon Event ID 1) - ECS fields
  process_creation: {
    'Image': 'process.executable',
    'CommandLine': 'process.command_line',
    'ParentImage': 'process.parent.executable',
    'ParentCommandLine': 'process.parent.command_line',
    'User': 'user.name',
    'LogonId': 'user.id',
    'IntegrityLevel': 'process.integrity_level',
    'CurrentDirectory': 'process.working_directory',
    'OriginalFileName': 'file.name',
    'Company': 'file.code_signature.subject_name',
    'Product': 'process.name',
    'FileVersion': 'file.version',
    'Description': 'file.description',
    'Hashes': 'file.hash.sha256',
    'md5': 'file.hash.md5',
    'sha256': 'file.hash.sha256',
    'sha1': 'file.hash.sha1',
  },

  // Registry Events (Sysmon Event ID 12, 13, 14)
  registry_event: {
    'TargetObject': 'registry.path',
    'Details': 'registry.data.strings',
    'EventType': 'event.action',
    'Image': 'process.executable',
  },

  // Network Connection (Sysmon Event ID 3)
  network_connection: {
    'DestinationIp': 'destination.ip',
    'DestinationPort': 'destination.port',
    'SourceIp': 'source.ip',
    'SourcePort': 'source.port',
    'Image': 'process.executable',
    'Protocol': 'network.protocol',
    'User': 'user.name',
    'DestinationHostname': 'destination.domain',
  },

  // File Event (Sysmon Event ID 11)
  file_event: {
    'TargetFilename': 'file.path',
    'TargetObject': 'file.path',
    'Image': 'process.executable',
    'CreationUtcTime': 'file.created',
  },

  // DNS Query (Sysmon Event ID 22)
  dns_query: {
    'QueryName': 'dns.question.name',
    'Image': 'process.executable',
    'query': 'dns.question.name',
  },

  // Windows Security Events
  security_event: {
    'EventID': 'event.code',
    'SubjectUserName': 'user.name',
    'TargetUserName': 'user.target.name',
    'WorkstationName': 'host.name',
    'IpAddress': 'source.ip',
    'LogonType': 'winlog.logon.type',
  },
};

// Generate UUID for reference
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Escape KQL special characters
function escapeKQLValue(value: string): string {
  // In Kibana KQL, we need to escape special characters: \():<>"*
  // But wildcards (*) should be preserved if they're intentional
  let escaped = value;

  // Escape backslashes first
  escaped = escaped.replace(/\\/g, '\\\\');

  // Escape other special characters (but not wildcards in the value itself)
  escaped = escaped.replace(/:/g, '\\:');
  escaped = escaped.replace(/\(/g, '\\(');
  escaped = escaped.replace(/\)/g, '\\)');
  escaped = escaped.replace(/"/g, '\\"');
  escaped = escaped.replace(/</g, '\\<');
  escaped = escaped.replace(/>/g, '\\>');

  return escaped;
}

// Check if value needs quotes
function needsQuotes(value: string): boolean {
  // Need quotes if value contains spaces or special characters
  return /[\s\(\)\[\]\{\}:"]/.test(value) || value.includes('*');
}

// Format value for KQL
function formatValue(value: string, preserveWildcards: boolean = false): string {
  let formatted = preserveWildcards ? value : escapeKQLValue(value);

  // Add quotes if needed
  if (needsQuotes(formatted)) {
    return `"${formatted.replace(/"/g, '\\"')}"`;
  }

  return formatted;
}

// Parse Sigma YAML rule
function parseSigmaRule(yamlContent: string): ParsedSigma {
  try {
    const parsed = parseYAML(yamlContent) as ParsedSigma;

    // Validate required fields
    if (!parsed.title) parsed.title = 'Untitled Detection';
    if (!parsed.description) parsed.description = '';
    if (!parsed.logsource) parsed.logsource = {};
    if (!parsed.detection) throw new Error('Detection section is required');
    if (!parsed.level) parsed.level = 'medium';
    if (!parsed.tags) parsed.tags = [];
    if (!parsed.id) parsed.id = generateUUID();

    return parsed;
  } catch (error) {
    throw new Error(`Failed to parse Sigma rule: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Map Sigma field to ECS field
function mapSigmaFieldToKQL(
  sigmaField: string,
  logsource: ParsedSigma['logsource']
): FieldMapping | null {
  const category = logsource.category?.toLowerCase() || 'process_creation';

  // Check category-specific mapping
  if (FIELD_MAPPINGS[category]?.[sigmaField]) {
    return {
      kqlField: FIELD_MAPPINGS[category][sigmaField],
      category,
    };
  }

  // Fallback to process_creation mapping
  if (FIELD_MAPPINGS.process_creation[sigmaField]) {
    return {
      kqlField: FIELD_MAPPINGS.process_creation[sigmaField],
      category: 'process_creation',
    };
  }

  // Return null if no mapping found
  return null;
}

// Apply Sigma modifier to create KQL condition
function applyModifier(
  kqlField: string,
  modifier: string | undefined,
  values: string | string[],
  notes: string[],
  warnings: string[]
): string {
  const valueArray = Array.isArray(values) ? values : [values];

  switch (modifier) {
    case 'contains': {
      // Kibana KQL: field:*value* for contains
      if (valueArray.length === 1) {
        const val = String(valueArray[0]);
        return `${kqlField}:*${escapeKQLValue(val)}*`;
      }
      // Multiple values - OR them
      return `(${valueArray.map(v => `${kqlField}:*${escapeKQLValue(String(v))}*`).join(' OR ')})`;
    }

    case 'startswith': {
      // Kibana KQL: field:value* for startswith
      if (valueArray.length === 1) {
        const val = String(valueArray[0]);
        return `${kqlField}:${escapeKQLValue(val)}*`;
      }
      return `(${valueArray.map(v => `${kqlField}:${escapeKQLValue(String(v))}*`).join(' OR ')})`;
    }

    case 'endswith': {
      // Kibana KQL: field:*value for endswith
      if (valueArray.length === 1) {
        const val = String(valueArray[0]);
        return `${kqlField}:*${escapeKQLValue(val)}`;
      }
      return `(${valueArray.map(v => `${kqlField}:*${escapeKQLValue(String(v))}`).join(' OR ')})`;
    }

    case 're': {
      // Regex - KQL doesn't support regex natively, convert to wildcard if possible
      warnings.push(`Regex modifier detected - converting to wildcard pattern (may not be exact)`);
      if (valueArray.length === 1) {
        const pattern = String(valueArray[0])
          .replace(/\.\*/g, '*')
          .replace(/\./g, '?');
        return `${kqlField}:${formatValue(pattern, true)}`;
      }
      return `(${valueArray.map(v => {
        const pattern = String(v).replace(/\.\*/g, '*').replace(/\./g, '?');
        return `${kqlField}:${formatValue(pattern, true)}`;
      }).join(' OR ')})`;
    }

    case 'base64': {
      // Base64 encoded - decode and search
      warnings.push(`Base64 modifier detected - using decoded value`);
      const decoded = valueArray.map(v => {
        try {
          return Buffer.from(String(v), 'base64').toString('utf-8');
        } catch {
          return String(v);
        }
      });
      if (decoded.length === 1) {
        return `${kqlField}:*${escapeKQLValue(decoded[0])}*`;
      }
      return `(${decoded.map(v => `${kqlField}:*${escapeKQLValue(v)}*`).join(' OR ')})`;
    }

    case 'base64offset': {
      warnings.push(`Base64offset modifier is not supported in KQL - using approximate conversion`);
      return `${kqlField}:*${escapeKQLValue(String(valueArray[0]))}*`;
    }

    case 'lt': {
      // Less than - KQL uses < operator
      return `${kqlField} < ${valueArray[0]}`;
    }

    case 'lte': {
      return `${kqlField} <= ${valueArray[0]}`;
    }

    case 'gt': {
      return `${kqlField} > ${valueArray[0]}`;
    }

    case 'gte': {
      return `${kqlField} >= ${valueArray[0]}`;
    }

    case 'all': {
      // All values must be present - AND them
      return valueArray.map(v => `${kqlField}:*${escapeKQLValue(String(v))}*`).join(' AND ');
    }

    case 'cidr': {
      // CIDR notation - KQL doesn't support CIDR natively
      warnings.push(`CIDR modifier not natively supported in KQL - consider using IP range or specific IPs`);
      if (valueArray.length === 1) {
        return `${kqlField}:${formatValue(String(valueArray[0]))}`;
      }
      return `(${valueArray.map(v => `${kqlField}:${formatValue(String(v))}`).join(' OR ')})`;
    }

    default: {
      // No modifier = exact match (or wildcard if value contains *)
      if (valueArray.length === 1) {
        const val = String(valueArray[0]);
        // Check if it's a wildcard pattern
        if (val.includes('*') || val.includes('?')) {
          return `${kqlField}:${formatValue(val, true)}`;
        }
        return `${kqlField}:${formatValue(val)}`;
      }
      // Multiple values - OR them
      return `(${valueArray.map(v => {
        const val = String(v);
        if (val.includes('*') || val.includes('?')) {
          return `${kqlField}:${formatValue(val, true)}`;
        }
        return `${kqlField}:${formatValue(val)}`;
      }).join(' OR ')})`;
    }
  }
}

// Process a single selection block
function processSelectionBlock(
  selectionName: string,
  selectionContent: Record<string, unknown>,
  logsource: ParsedSigma['logsource']
): { condition: string; notes: string[]; warnings: string[] } {
  const conditions: string[] = [];
  const notes: string[] = [];
  const warnings: string[] = [];

  for (const [field, value] of Object.entries(selectionContent)) {
    // Parse field and modifier
    const [sigmaField, ...modifierParts] = field.split('|');
    const modifier = modifierParts.join('|') || undefined;

    // Map to ECS field
    const mapping = mapSigmaFieldToKQL(sigmaField, logsource);

    if (!mapping) {
      warnings.push(`Field "${sigmaField}" could not be mapped to ECS - using original name`);
      const condition = applyModifier(sigmaField, modifier, value as string | string[], notes, warnings);
      conditions.push(condition);
      continue;
    }

    // Generate condition
    const condition = applyModifier(mapping.kqlField, modifier, value as string | string[], notes, warnings);
    conditions.push(condition);

    notes.push(`Mapped "${sigmaField}" → "${mapping.kqlField}" (ECS)`);
  }

  if (conditions.length === 0) {
    warnings.push(`Selection "${selectionName}" produced no conditions`);
    return { condition: '*', notes, warnings };
  }

  // Combine conditions with AND (fields in same selection are ANDed in Sigma)
  const finalCondition = conditions.length > 1
    ? `(${conditions.join(' AND ')})`
    : conditions[0];

  return { condition: finalCondition, notes, warnings };
}

// Translate Sigma condition to KQL
function translateCondition(
  conditionString: string,
  selectionMap: Map<string, string>,
  warnings: string[]
): string {
  let condition = conditionString.trim();

  // Handle "1 of selection_*" or "all of selection_*" patterns
  const ofPatternMatch = condition.match(/(\d+|all)\s+of\s+(\w+\*|\w+)/i);
  if (ofPatternMatch) {
    const [, countOrAll, pattern] = ofPatternMatch;
    const isWildcard = pattern.includes('*');
    const prefix = isWildcard ? pattern.replace('*', '') : '';

    // Find matching selections
    const matchingSelections = Array.from(selectionMap.entries())
      .filter(([key]) => isWildcard ? key.startsWith(prefix) : key === pattern)
      .map(([, value]) => value);

    if (matchingSelections.length === 0) {
      warnings.push(`No selections found matching pattern "${pattern}"`);
      return '*';
    }

    if (countOrAll === 'all') {
      return `(${matchingSelections.join(' AND ')})`;
    } else {
      const count = parseInt(countOrAll);
      if (count === 1) {
        return `(${matchingSelections.join(' OR ')})`;
      } else {
        warnings.push(`"${count} of" pattern requires manual review - using OR logic`);
        return `(${matchingSelections.join(' OR ')})`;
      }
    }
  }

  // Replace selection identifiers with their conditions
  for (const [key, value] of selectionMap.entries()) {
    const regex = new RegExp(`\\b${key}\\b`, 'g');
    condition = condition.replace(regex, value);
  }

  // Translate boolean operators to KQL syntax (uppercase)
  condition = condition
    .replace(/\band\b/gi, ' AND ')
    .replace(/\bor\b/gi, ' OR ')
    .replace(/\bnot\b/gi, ' NOT ');

  return condition;
}

// Extract MITRE tags from Sigma tags
function extractMITRETags(tags: string[]): string[] {
  const mitreTags: string[] = [];

  for (const tag of tags) {
    const lowerTag = tag.toLowerCase();
    // Match attack.* tags
    if (lowerTag.startsWith('attack.')) {
      const technique = lowerTag.replace('attack.', '');
      // Check if it's a technique ID (T####)
      if (technique.match(/^t\d{4}/)) {
        mitreTags.push(technique.toUpperCase());
      }
    }
  }

  return mitreTags;
}

// Determine index pattern based on log source
function determineIndexPattern(logsource: ParsedSigma['logsource']): string {
  const category = logsource.category?.toLowerCase() || '';
  const product = logsource.product?.toLowerCase() || '';

  // Common Elastic index patterns
  if (category.includes('process')) return 'winlogbeat-*, logs-endpoint.events.process-*';
  if (category.includes('network')) return 'winlogbeat-*, logs-endpoint.events.network-*';
  if (category.includes('registry')) return 'winlogbeat-*, logs-endpoint.events.registry-*';
  if (category.includes('file')) return 'winlogbeat-*, logs-endpoint.events.file-*';
  if (category.includes('dns')) return 'winlogbeat-*, logs-endpoint.events.dns-*';
  if (product.includes('windows')) return 'winlogbeat-*';
  if (product.includes('linux')) return 'filebeat-*';

  return 'logs-*';
}

// Main conversion function
export function convertSigmaToKQL(
  sigmaRule: string,
  options: {
    timeframe?: string;
    target_platform?: string;
    include_comments?: boolean;
  } = {}
): ConversionResult {
  const {
    timeframe = '24h',
    include_comments = true,
  } = options;

  const notes: string[] = [];
  const warnings: string[] = [];

  // Parse Sigma rule
  const parsed = parseSigmaRule(sigmaRule);

  // Determine index pattern
  const indexPattern = determineIndexPattern(parsed.logsource);
  notes.push(`Suggested index pattern: ${indexPattern}`);

  // Process detection section
  const detection = parsed.detection;
  const selectionMap = new Map<string, string>();

  // Extract condition string
  const conditionString = detection.condition as string;
  if (!conditionString) {
    throw new Error('Detection condition is required');
  }

  // Process each selection/filter block
  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;

    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const result = processSelectionBlock(key, value as Record<string, unknown>, parsed.logsource);
      selectionMap.set(key, result.condition);
      notes.push(...result.notes);
      warnings.push(...result.warnings);
    }
  }

  // Translate condition
  const kql_query = translateCondition(conditionString, selectionMap, warnings);

  // Extract metadata
  const mitre_tags = extractMITRETags(parsed.tags);

  return {
    kql_query,
    metadata: {
      title: parsed.title,
      severity: parsed.level,
      mitre_tags,
      data_sources: [indexPattern],
    },
    notes,
    warnings,
  };
}

// Tool handler - formats output for MCP
export function handleSigmaToKQL(args: {
  sigma_rule: string;
  timeframe?: string;
  target_platform?: string;
  include_comments?: boolean;
}): string {
  try {
    const result = convertSigmaToKQL(args.sigma_rule, {
      timeframe: args.timeframe || '24h',
      target_platform: args.target_platform || 'elastic',
      include_comments: args.include_comments ?? true,
    });

    let output = '## Sigma to Kibana Query Language (KQL) Conversion\n\n';

    // Metadata
    output += '### Detection Metadata\n';
    output += `**Title:** ${result.metadata.title}\n`;
    output += `**Severity:** ${result.metadata.severity}\n`;
    if (result.metadata.mitre_tags.length > 0) {
      output += `**MITRE ATT&CK:** ${result.metadata.mitre_tags.join(', ')}\n`;
    }
    output += `**Recommended Index Pattern:** ${result.metadata.data_sources.join(', ')}\n\n`;

    // Warnings
    if (result.warnings.length > 0) {
      output += '### ⚠️ Conversion Warnings\n';
      for (const warning of result.warnings) {
        output += `- ${warning}\n`;
      }
      output += '\n';
    }

    // KQL Query
    output += '### Kibana Query Language (KQL)\n';
    output += '```\n';
    output += result.kql_query;
    output += '\n```\n\n';

    output += '**Usage:** Paste this query into the Kibana search bar in Discover, Security, or when creating detection rules.\n\n';

    // Notes
    if (result.notes.length > 0) {
      output += '### Conversion Notes\n';
      for (const note of result.notes) {
        output += `- ${note}\n`;
      }
      output += '\n';
    }

    output += '---\n';
    output += '*Note: Always validate and test KQL queries in your Kibana environment. Field mappings use Elastic Common Schema (ECS) and may need adjustment for custom field mappings.*\n';

    return output;
  } catch (error) {
    return `## Conversion Error\n\n**Error:** ${error instanceof Error ? error.message : 'Unknown error'}\n\nPlease verify that the input is a valid Sigma rule in YAML format.`;
  }
}
