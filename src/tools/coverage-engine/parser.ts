// Log Parser for Coverage Engine
// Extracts event source, event ID, and field names from raw log samples.
// Supports: Windows Event XML, Sysmon, JSON (EDR/Cloud), key=value (auditd), CSV

export interface ParsedLog {
  event_source: string;
  event_id: string;
  fields: string[];
  raw: string;
  format_detected: string;
}

// ────────────────────────────────────────────────────────────────────────────
// Main parser entry point
// ────────────────────────────────────────────────────────────────────────────

export function parseLog(rawLog: string): ParsedLog {
  const trimmed = rawLog.trim();

  // Try each parser in order of specificity
  const parsers = [
    tryParseWindowsXml,
    tryParseSysmonXml,
    tryParseJson,
    tryParseKeyValue,
    tryParseCef,
  ];

  for (const parser of parsers) {
    const result = parser(trimmed);
    if (result) return result;
  }

  // Fallback: generic field extraction
  return {
    event_source: 'unknown',
    event_id: 'unknown',
    fields: extractGenericFields(trimmed),
    raw: trimmed,
    format_detected: 'unknown',
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Windows Security/System Event Log XML
// ────────────────────────────────────────────────────────────────────────────

function tryParseWindowsXml(log: string): ParsedLog | null {
  // Match <Event> or <EventData> XML patterns
  if (!log.includes('<Event') && !log.includes('<EventID>')) return null;

  const eventIdMatch = log.match(/<EventID[^>]*>(\d+)<\/EventID>/i);
  if (!eventIdMatch) return null;

  const eventId = eventIdMatch[1];

  // Determine source from Provider or Channel
  let eventSource = 'windows_security';
  const providerMatch = log.match(/Provider\s+Name=['"]([^'"]+)['"]/i);
  const channelMatch = log.match(/<Channel>([^<]+)<\/Channel>/i);

  const provider = providerMatch?.[1]?.toLowerCase() || '';
  const channel = channelMatch?.[1]?.toLowerCase() || '';

  if (provider.includes('sysmon') || channel.includes('sysmon')) {
    eventSource = 'sysmon';
  } else if (
    channel.includes('microsoft-windows-powershell/operational') ||
    (provider.includes('powershell') && channel.includes('operational'))
  ) {
    eventSource = 'windows_powershell_operational';
  } else if (provider.includes('powershell') || channel.includes('powershell')) {
    eventSource = 'windows_powershell';
  } else if (
    provider.includes('terminalservices-localsessionmanager') ||
    channel.includes('terminalservices-localsessionmanager')
  ) {
    eventSource = 'windows_rdp_local';
  } else if (
    provider.includes('terminalservices-remoteconnectionmanager') ||
    channel.includes('terminalservices-remoteconnectionmanager')
  ) {
    eventSource = 'windows_rdp_remote';
  } else if (
    provider.includes('terminalservices-gateway') ||
    channel.includes('terminalservices-gateway')
  ) {
    eventSource = 'windows_rdp_gateway';
  } else if (
    provider.includes('windows defender') ||
    provider.includes('microsoft antimalware') ||
    channel.includes('windows defender')
  ) {
    eventSource = 'windows_defender';
  } else if (
    provider.includes('windows firewall with advanced security') ||
    provider.includes('microsoft-windows-windows firewall') ||
    channel.includes('firewall')
  ) {
    eventSource = 'windows_firewall';
  } else if (
    provider.includes('taskscheduler') ||
    provider.includes('microsoft-windows-taskscheduler') ||
    channel.includes('taskscheduler')
  ) {
    eventSource = 'windows_taskscheduler';
  } else if (
    provider.includes('bits-client') ||
    provider.includes('microsoft-windows-bits-client') ||
    channel.includes('bits')
  ) {
    eventSource = 'windows_bits';
  } else if (
    provider.includes('wmi-activity') ||
    provider.includes('microsoft-windows-wmi-activity') ||
    channel.includes('wmi-activity')
  ) {
    eventSource = 'windows_wmi';
  } else if (channel === 'application' || channel.includes('application')) {
    eventSource = 'windows_application';
  } else if (channel.includes('system') || provider.includes('service control manager')) {
    eventSource = 'windows_system';
  }

  // Extract field names from <Data Name="FieldName"> or <EventData> children
  const fields: string[] = [];
  const dataRegex = /<Data\s+Name=['"]([^'"]+)['"]/gi;
  let match;
  while ((match = dataRegex.exec(log)) !== null) {
    fields.push(match[1]);
  }

  // Also extract from named XML elements within EventData
  if (fields.length === 0) {
    const elemRegex = /<(\w+)>[^<]+<\/\1>/g;
    while ((match = elemRegex.exec(log)) !== null) {
      const tag = match[1];
      if (!['Event', 'System', 'EventData', 'EventID', 'Provider', 'Channel', 'TimeCreated', 'Computer', 'Correlation', 'Execution', 'Security'].includes(tag)) {
        fields.push(tag);
      }
    }
  }

  return {
    event_source: eventSource,
    event_id: eventId,
    fields: [...new Set(fields)],
    raw: log,
    format_detected: 'windows_xml',
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Sysmon-specific XML (superset of Windows XML)
// ────────────────────────────────────────────────────────────────────────────

function tryParseSysmonXml(log: string): ParsedLog | null {
  if (!log.toLowerCase().includes('sysmon')) return null;
  // Delegate to windows XML parser — it handles sysmon via provider detection
  return tryParseWindowsXml(log);
}

// ────────────────────────────────────────────────────────────────────────────
// JSON logs (EDR, Cloud, Elastic, Splunk)
// ────────────────────────────────────────────────────────────────────────────

function tryParseJson(log: string): ParsedLog | null {
  if (!log.startsWith('{') && !log.startsWith('[')) return null;

  let obj: Record<string, unknown>;
  try {
    const parsed = JSON.parse(log);
    obj = Array.isArray(parsed) ? parsed[0] : parsed;
    if (typeof obj !== 'object' || obj === null) return null;
  } catch {
    return null;
  }

  const fields = extractJsonFieldNames(obj);
  const { eventSource, eventId } = classifyJsonLog(obj);

  return {
    event_source: eventSource,
    event_id: eventId,
    fields,
    raw: log,
    format_detected: 'json',
  };
}

function extractJsonFieldNames(obj: Record<string, unknown>, prefix = ''): string[] {
  const fields: string[] = [];
  for (const [key, val] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    fields.push(fullKey);
    if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
      fields.push(...extractJsonFieldNames(val as Record<string, unknown>, fullKey));
    }
  }
  return fields;
}

function classifyJsonLog(obj: Record<string, unknown>): { eventSource: string; eventId: string } {
  // CrowdStrike
  if (obj.event_simpleName || obj.ExternalApiType) {
    return {
      eventSource: 'crowdstrike',
      eventId: (obj.event_simpleName as string) || (obj.ExternalApiType as string) || 'unknown',
    };
  }

  // Microsoft Defender for Endpoint (MDE / Advanced Hunting)
  if (obj.ActionType && (obj.DeviceName || obj.DeviceId)) {
    // Determine table from available fields
    let table = 'DeviceEvents';
    if (obj.ProcessCommandLine !== undefined || obj.FileName !== undefined) {
      if (obj.FolderPath !== undefined && obj.ProcessCommandLine !== undefined) table = 'DeviceProcessEvents';
      else if (obj.RegistryKey !== undefined) table = 'DeviceRegistryEvents';
      else if (obj.RemoteIP !== undefined) table = 'DeviceNetworkEvents';
      else if (obj.ImageLoaded !== undefined || (obj.FileName !== undefined && obj.SHA256 !== undefined)) table = 'DeviceImageLoadEvents';
    }
    if (obj.LogonType !== undefined) table = 'DeviceLogonEvents';
    return { eventSource: 'mde', eventId: table };
  }

  // AWS CloudTrail
  if (obj.eventSource && obj.eventName && obj.awsRegion) {
    return {
      eventSource: 'aws_cloudtrail',
      eventId: obj.eventName as string,
    };
  }

  // Azure AD / Entra ID
  if (obj.operationName && (obj.tenantId || obj.callerIpAddress)) {
    return { eventSource: 'azure_ad', eventId: obj.operationName as string };
  }
  if (obj.UserPrincipalName && obj.AppDisplayName && obj.ResultType !== undefined) {
    return { eventSource: 'azure_ad', eventId: 'SignInLogs' };
  }

  // Elastic ECS
  if (obj.event && typeof obj.event === 'object') {
    const ev = obj.event as Record<string, unknown>;
    if (ev.module && ev.action) {
      return {
        eventSource: (ev.module as string).toLowerCase(),
        eventId: ev.action as string,
      };
    }
  }

  // Generic: look for common event ID fields
  const idFields = ['EventID', 'event_id', 'eventId', 'event.id', 'EventRecordID'];
  for (const f of idFields) {
    if (obj[f] !== undefined) {
      return { eventSource: 'unknown_json', eventId: String(obj[f]) };
    }
  }

  return { eventSource: 'unknown_json', eventId: 'unknown' };
}

// ────────────────────────────────────────────────────────────────────────────
// Key-Value format (Linux auditd, syslog, etc.)
// ────────────────────────────────────────────────────────────────────────────

function tryParseKeyValue(log: string): ParsedLog | null {
  // auditd format: type=EXECVE msg=audit(1234:5678): argc=3 a0="ls" a1="-la"
  const auditTypeMatch = log.match(/type=(\w+)\s+msg=audit/);
  if (auditTypeMatch) {
    const eventId = auditTypeMatch[1];
    const fields: string[] = [];
    const kvRegex = /(\w+)=(?:"[^"]*"|[^\s]+)/g;
    let match;
    while ((match = kvRegex.exec(log)) !== null) {
      fields.push(match[1]);
    }
    return {
      event_source: 'linux_auditd',
      event_id: eventId,
      fields: [...new Set(fields)],
      raw: log,
      format_detected: 'auditd_kv',
    };
  }

  // Generic key=value (at least 3 k=v pairs)
  const kvPairs = log.match(/(\w+)=(?:"[^"]*"|[^\s]+)/g);
  if (kvPairs && kvPairs.length >= 3) {
    const fields = kvPairs.map(p => p.split('=')[0]);
    return {
      event_source: 'unknown_kv',
      event_id: 'unknown',
      fields: [...new Set(fields)],
      raw: log,
      format_detected: 'key_value',
    };
  }

  return null;
}

// ────────────────────────────────────────────────────────────────────────────
// CEF (Common Event Format)
// ────────────────────────────────────────────────────────────────────────────

function tryParseCef(log: string): ParsedLog | null {
  // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
  const cefMatch = log.match(/^CEF:\d+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/);
  if (!cefMatch) return null;

  const vendor = cefMatch[1];
  const product = cefMatch[2];
  const signatureId = cefMatch[4];
  const extension = cefMatch[7];

  // Extract fields from extension (key=value pairs)
  const fields: string[] = [];
  const kvRegex = /(\w+)=(?:[^\s]+)/g;
  let match;
  while ((match = kvRegex.exec(extension)) !== null) {
    fields.push(match[1]);
  }

  return {
    event_source: `${vendor}_${product}`.toLowerCase().replace(/\s+/g, '_'),
    event_id: signatureId,
    fields: [...new Set(fields)],
    raw: log,
    format_detected: 'cef',
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Generic field extraction fallback
// ────────────────────────────────────────────────────────────────────────────

function extractGenericFields(log: string): string[] {
  const fields: string[] = [];

  // Try XML-style attributes/elements
  const xmlAttr = log.match(/(\w+)=['"][^'"]*['"]/g);
  if (xmlAttr) {
    for (const attr of xmlAttr) {
      fields.push(attr.split('=')[0]);
    }
  }

  // Try k=v style
  const kvPairs = log.match(/(\w+)=(?:"[^"]*"|[^\s]+)/g);
  if (kvPairs) {
    for (const p of kvPairs) {
      fields.push(p.split('=')[0]);
    }
  }

  return [...new Set(fields)];
}

// ────────────────────────────────────────────────────────────────────────────
// Parse from structured input (event_source + event_id + fields directly)
// ────────────────────────────────────────────────────────────────────────────

export function parseStructuredInput(
  eventSource: string,
  eventId: string,
  fields?: string[]
): ParsedLog {
  return {
    event_source: eventSource.toLowerCase().replace(/\s+/g, '_'),
    event_id: eventId,
    fields: fields || [],
    raw: '',
    format_detected: 'structured_input',
  };
}
