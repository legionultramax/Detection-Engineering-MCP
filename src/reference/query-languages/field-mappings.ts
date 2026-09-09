// Sigma taxonomy field names mapped to each target language, keyed by logsource
// category.
//
// This table is authored — there is no corpus to derive a *mapping* from, only
// corpora to derive each side's vocabulary from. So it is written here and then
// every target is checked against the derived catalog at request time. A target
// the catalog corroborates is reported confirmed; one it does not is reported
// unconfirmed, with that fact attached to the mapping rather than left implicit.
//
// The consequence worth stating: this file being wrong produces a query that
// parses, runs and returns zero rows. That is the worst failure mode in the
// system, which is why nothing here is presented as fact without the catalog
// agreeing.

/** Target field for one Sigma field, per language. null = no equivalent. */
export interface FieldTargets {
  kql: string | null;
  spl: string | null;
  cql: string | null;
  /** Why a mapping is awkward, where it is. */
  note?: string;
}

/**
 * The table the mapping assumes, per category and language. Needed because KQL
 * field names only mean anything relative to a table, and SPL fields are
 * model-qualified.
 *
 * null means the language has no equivalent source for this telemetry, which is
 * a real answer and not a gap to be papered over. Splunk's CIM has no data model
 * for image loads, script blocks, process access or driver loads — detections
 * for those read raw Sysmon or PowerShell events instead. Naming a plausible
 * model there would produce a query that runs against the wrong data.
 */
export const CATEGORY_SOURCES: Record<string, { kql: string | null; spl: string | null; cql: string | null }> = {
  process_creation: {
    kql: 'DeviceProcessEvents',
    spl: 'Endpoint.Processes',
    cql: 'ProcessRollup2',
  },
  network_connection: {
    kql: 'DeviceNetworkEvents',
    spl: 'Network_Traffic.All_Traffic',
    cql: 'NetworkConnectIP4',
  },
  dns_query: {
    kql: 'DeviceEvents',
    spl: 'Network_Resolution.DNS',
    cql: 'DnsRequest',
  },
  file_event: {
    kql: 'DeviceFileEvents',
    spl: 'Endpoint.Filesystem',
    cql: 'NewExecutableWritten',
  },
  registry_event: {
    kql: 'DeviceRegistryEvents',
    spl: 'Endpoint.Registry',
    cql: 'RegSystemConfigValueUpdate',
  },
  registry_set: {
    kql: 'DeviceRegistryEvents',
    spl: 'Endpoint.Registry',
    cql: 'RegSystemConfigValueUpdate',
  },
  // registry_add and registry_delete alias registry_event's field table below.
  // They were aliased there and omitted here, so rules in those categories
  // mapped their fields and had nowhere to write them — 0% target assignment,
  // found by the coverage run rather than by reading the code.
  registry_add: {
    kql: 'DeviceRegistryEvents',
    spl: 'Endpoint.Registry',
    cql: 'RegGenericValueUpdate',
  },
  registry_delete: {
    kql: 'DeviceRegistryEvents',
    spl: 'Endpoint.Registry',
    // Falcon has no RegKeyDeleted or RegValueDeleted event — checked against the
    // vendored dictionary rather than assumed. Deletions surface through the
    // generic value-update event, so the query must filter on the operation.
    cql: 'RegGenericValueUpdate',
  },
  image_load: {
    kql: 'DeviceImageLoadEvents',
    spl: null,
    cql: 'ClassifiedModuleLoad',
  },
  ps_script: {
    kql: 'DeviceEvents',
    spl: null,
    cql: 'ScriptControlScanTelemetry',
  },
  process_access: {
    kql: 'DeviceEvents',
    spl: null,
    cql: 'SuspiciousCredentialModuleLoad',
  },
  driver_load: {
    kql: 'DeviceEvents',
    spl: null,
    cql: 'DriverLoad',
  },
  authentication: {
    kql: 'SigninLogs',
    spl: 'Authentication.Authentication',
    cql: 'UserLogon',
  },
};

export const FIELD_MAPPINGS: Record<string, Record<string, FieldTargets>> = {
  process_creation: {
    Image: { kql: 'FolderPath', spl: 'Processes.process_path', cql: 'ImageFileName' },
    OriginalFileName: { kql: 'ProcessVersionInfoOriginalFileName', spl: 'Processes.original_file_name', cql: 'OriginalFilename' },
    CommandLine: { kql: 'ProcessCommandLine', spl: 'Processes.process', cql: 'CommandLine' },
    ParentImage: { kql: 'InitiatingProcessFolderPath', spl: 'Processes.parent_process_path', cql: 'ParentBaseFileName' },
    ParentCommandLine: { kql: 'InitiatingProcessCommandLine', spl: 'Processes.parent_process', cql: null,
      note: 'Falcon ProcessRollup2 carries the parent image name, not the parent command line. Join on ParentProcessId if the full parent command line is needed.' },
    User: { kql: 'AccountName', spl: 'Processes.user', cql: 'UserName' },
    IntegrityLevel: { kql: 'ProcessIntegrityLevel', spl: null, cql: 'IntegrityLevel',
      note: 'CIM has no integrity level field; the concept does not exist in the Processes data model.' },
    CurrentDirectory: { kql: 'InitiatingProcessCurrentWorkingDirectory', spl: null, cql: null },
    Hashes: { kql: 'SHA256', spl: 'Processes.process_hash', cql: 'SHA256HashData' },
    md5: { kql: 'MD5', spl: 'Processes.process_hash', cql: 'MD5HashData' },
    sha256: { kql: 'SHA256', spl: 'Processes.process_hash', cql: 'SHA256HashData' },
    Company: { kql: 'ProcessVersionInfoCompanyName', spl: null, cql: null },
    Product: { kql: 'ProcessVersionInfoProductName', spl: null, cql: null },
    Description: { kql: 'ProcessVersionInfoFileDescription', spl: null, cql: null },
    LogonId: { kql: 'LogonId', spl: null, cql: 'LogonId' },
  },

  network_connection: {
    DestinationIp: { kql: 'RemoteIP', spl: 'All_Traffic.dest', cql: 'RemoteAddressIP4' },
    DestinationPort: { kql: 'RemotePort', spl: 'All_Traffic.dest_port', cql: 'RemotePort' },
    DestinationHostname: { kql: 'RemoteUrl', spl: 'All_Traffic.dest_name', cql: null },
    SourceIp: { kql: 'LocalIP', spl: 'All_Traffic.src', cql: 'LocalAddressIP4' },
    SourcePort: { kql: 'LocalPort', spl: 'All_Traffic.src_port', cql: 'LocalPort' },
    Image: { kql: 'InitiatingProcessFolderPath', spl: 'All_Traffic.app', cql: 'ContextBaseFileName' },
    Protocol: { kql: 'Protocol', spl: 'All_Traffic.transport', cql: 'Protocol' },
    User: { kql: 'InitiatingProcessAccountName', spl: 'All_Traffic.user', cql: 'UserName' },
    Initiated: { kql: null, spl: 'All_Traffic.direction', cql: null,
      note: 'Sigma Initiated is a boolean; CIM expresses direction as inbound/outbound. Falcon splits it across NetworkConnectIP4 and NetworkReceiveAcceptIP4.' },
  },

  dns_query: {
    QueryName: { kql: 'AdditionalFields', spl: 'DNS.query', cql: 'DomainName',
      note: 'Defender surfaces DNS via DeviceEvents with ActionType DnsQueryResponse and the name inside AdditionalFields, so a JSON extraction is needed rather than a direct column.' },
    query: { kql: 'AdditionalFields', spl: 'DNS.query', cql: 'DomainName' },
    Image: { kql: 'InitiatingProcessFolderPath', spl: null, cql: 'ContextBaseFileName' },
    QueryStatus: { kql: null, spl: 'DNS.reply_code_id', cql: null },
    answer: { kql: null, spl: 'DNS.answer', cql: 'IP4Records' },
  },

  file_event: {
    TargetFilename: { kql: 'FolderPath', spl: 'Filesystem.file_path', cql: 'TargetFileName' },
    Image: { kql: 'InitiatingProcessFolderPath', spl: 'Filesystem.process_path', cql: 'ContextBaseFileName' },
    User: { kql: 'InitiatingProcessAccountName', spl: 'Filesystem.user', cql: 'UserName' },
    CreationUtcTime: { kql: 'Timestamp', spl: 'Filesystem.file_create_time', cql: 'ContextTimeStamp' },
    Hashes: { kql: 'SHA256', spl: 'Filesystem.file_hash', cql: 'SHA256HashData' },
  },

  registry_event: {
    TargetObject: { kql: 'RegistryKey', spl: 'Registry.registry_path', cql: 'RegObjectName' },
    Details: { kql: 'RegistryValueData', spl: 'Registry.registry_value_data', cql: 'RegStringValue' },
    EventType: { kql: 'ActionType', spl: 'Registry.action', cql: null },
    Image: { kql: 'InitiatingProcessFolderPath', spl: 'Registry.process_path', cql: 'ContextBaseFileName' },
    NewName: { kql: 'RegistryValueName', spl: 'Registry.registry_value_name', cql: 'RegValueName' },
  },

  authentication: {
    TargetUserName: { kql: 'UserPrincipalName', spl: 'Authentication.user', cql: 'UserName' },
    SubjectUserName: { kql: 'UserPrincipalName', spl: 'Authentication.src_user', cql: 'UserName' },
    IpAddress: { kql: 'IPAddress', spl: 'Authentication.src', cql: 'RemoteAddressIP4' },
    WorkstationName: { kql: 'DeviceDetail', spl: 'Authentication.dest', cql: 'ComputerName' },
    LogonType: { kql: null, spl: 'Authentication.authentication_method', cql: 'LogonType' },
    Status: { kql: 'ResultType', spl: 'Authentication.action', cql: 'Status' },
    EventID: { kql: null, spl: 'EventCode', cql: null,
      note: 'Windows event IDs do not survive into Entra ID sign-in logs; SigninLogs uses ResultType instead.' },
  },
};

/** Registry-set is the same shape as registry_event in the Sigma taxonomy. */
FIELD_MAPPINGS.registry_set = FIELD_MAPPINGS.registry_event;
FIELD_MAPPINGS.registry_add = FIELD_MAPPINGS.registry_event;
FIELD_MAPPINGS.registry_delete = FIELD_MAPPINGS.registry_event;

// The four categories below cover 393 further Sigma rules — image_load 135,
// ps_script 191, process_access 35, driver_load 32 — measured from the corpus.
// None has a Splunk CIM data model, so SPL targets are null throughout: ESCU
// detections for this telemetry read raw Sysmon or PowerShell events, and
// naming a plausible-looking model would send the query at the wrong data.
// Falcon event names were checked against the vendored dictionary.

/** Sysmon event 7. Defender exposes this as its own table. */
FIELD_MAPPINGS.image_load = {
  ImageLoaded: { kql: 'FolderPath', spl: null, cql: null,
    note: 'On DeviceImageLoadEvents, FolderPath is the module being loaded, not the loader.' },
  Image: { kql: 'InitiatingProcessFolderPath', spl: null, cql: 'ContextBaseFileName' },
  Hashes: { kql: 'SHA256', spl: null, cql: 'SHA256HashData' },
  sha256: { kql: 'SHA256', spl: null, cql: 'SHA256HashData' },
  md5: { kql: 'MD5', spl: null, cql: 'MD5HashData' },
  OriginalFileName: { kql: null, spl: null, cql: null },
  Signed: { kql: null, spl: null, cql: null,
    note: 'Defender does not expose signature state on image-load rows; pivot to DeviceFileCertificateInfo.' },
  Signature: { kql: null, spl: null, cql: null },
  SignatureStatus: { kql: null, spl: null, cql: null },
  User: { kql: 'InitiatingProcessAccountName', spl: null, cql: 'UserName' },
};

/** PowerShell script block logging, event 4104. */
FIELD_MAPPINGS.ps_script = {
  ScriptBlockText: { kql: 'AdditionalFields', spl: 'ScriptBlockText', cql: null,
    note: 'Defender carries the block inside AdditionalFields on DeviceEvents where ' +
      'ActionType is PowerShellCommand, so it needs a JSON extraction rather than a column. ' +
      'Splunk reads EventCode 4104 directly, where ScriptBlockText is a real field.' },
  Path: { kql: null, spl: 'Path', cql: null },
  ScriptBlockId: { kql: null, spl: 'ScriptBlockId', cql: null },
  Image: { kql: 'InitiatingProcessFolderPath', spl: null, cql: 'ContextBaseFileName' },
  User: { kql: 'InitiatingProcessAccountName', spl: 'user', cql: 'UserName' },
};

/** Sysmon event 10 — the LSASS-handle shape most credential-theft rules use. */
FIELD_MAPPINGS.process_access = {
  SourceImage: { kql: 'InitiatingProcessFolderPath', spl: null, cql: 'ContextBaseFileName' },
  TargetImage: { kql: 'FolderPath', spl: null, cql: 'TargetFileName' },
  GrantedAccess: { kql: 'AdditionalFields', spl: null, cql: null,
    note: 'Defender does not surface the access mask as a column; it appears in ' +
      'AdditionalFields on OpenProcessApiCall rows when present at all.' },
  CallTrace: { kql: null, spl: null, cql: null },
  SourceUser: { kql: 'InitiatingProcessAccountName', spl: null, cql: 'UserName' },
  TargetUser: { kql: 'AccountName', spl: null, cql: null },
};

/** Sysmon event 6 — the LOLDrivers shape. */
FIELD_MAPPINGS.driver_load = {
  ImageLoaded: { kql: 'FolderPath', spl: null, cql: null },
  Hashes: { kql: 'SHA256', spl: null, cql: 'SHA256HashData' },
  sha256: { kql: 'SHA256', spl: null, cql: 'SHA256HashData' },
  md5: { kql: 'MD5', spl: null, cql: 'MD5HashData' },
  Signature: { kql: null, spl: null, cql: null },
  Signed: { kql: null, spl: null, cql: null },
  SignatureStatus: { kql: null, spl: null, cql: null },
};

// Fields that appear across categories rather than only in their home shape.
// The coverage run surfaced these as referenced-but-unmapped in real rules: a
// network_connection rule filtering on CommandLine, for instance, is common and
// was previously reported as having no mapping at all.
for (const cat of ['network_connection', 'dns_query', 'file_event', 'registry_event',
                   'image_load', 'process_access', 'driver_load'] as const) {
  const table = FIELD_MAPPINGS[cat];
  if (table && !table.CommandLine) {
    table.CommandLine = {
      kql: 'InitiatingProcessCommandLine', spl: null, cql: 'CommandLine',
      note: 'The initiating process\'s command line, not the event\'s own subject.',
    };
  }
  if (table && !table.IntegrityLevel) {
    table.IntegrityLevel = { kql: 'ProcessIntegrityLevel', spl: null, cql: 'IntegrityLevel' };
  }
}
FIELD_MAPPINGS.network_connection.DestinationIsIpv6 = {
  kql: null, spl: null, cql: null,
  note: 'No direct equivalent. Infer from the address family of the destination field, or in ' +
    'Falcon by selecting NetworkConnectIP6 instead of NetworkConnectIP4.',
};

// PE version-info fields, which rules use to identify a binary by its metadata
// rather than its path. The coverage run found these referenced in image_load
// and driver_load rules with no mapping entry.
const VERSION_INFO: Record<string, FieldTargets> = {
  Description: { kql: 'ProcessVersionInfoFileDescription', spl: null, cql: null },
  Company: { kql: 'ProcessVersionInfoCompanyName', spl: null, cql: null },
  Product: { kql: 'ProcessVersionInfoProductName', spl: null, cql: null },
  FileVersion: { kql: 'ProcessVersionInfoProductVersion', spl: null, cql: null },
  OriginalFileName: { kql: 'ProcessVersionInfoOriginalFileName', spl: null, cql: 'OriginalFilename' },
};
for (const cat of ['image_load', 'driver_load'] as const) {
  for (const [field, targets] of Object.entries(VERSION_INFO)) {
    FIELD_MAPPINGS[cat][field] ??= targets;
  }
}

// ImagePath was the single largest gap in the work queue — 24 references across
// the sample. Service and driver rules use it for the on-disk path of the
// image being registered, which is a different thing from the loading process.
for (const cat of ['driver_load', 'image_load', 'registry_event'] as const) {
  FIELD_MAPPINGS[cat].ImagePath ??= {
    kql: 'FolderPath', spl: null, cql: null,
    note: 'The path of the image being registered or loaded, not the process performing it. ' +
      'In a registry rule this is the value data of a service ImagePath, so read it from the ' +
      'registry value rather than a file column.',
  };
}
FIELD_MAPPINGS.registry_event.ImagePath = {
  kql: 'RegistryValueData', spl: 'Registry.registry_value_data', cql: 'RegStringValue',
  note: 'Service ImagePath is registry value data, not a file path column.',
};

FIELD_MAPPINGS.process_access.SourceCommandLine = {
  kql: 'InitiatingProcessCommandLine', spl: null, cql: 'CommandLine',
  note: 'The command line of the process requesting access, not the target.',
};

FIELD_MAPPINGS.ps_script.Provider_Name = {
  kql: null, spl: 'Provider_Name', cql: null,
  note: 'Windows event provider name. Defender does not carry it; in Splunk it distinguishes ' +
    'PowerShell operational logging from other providers on the same event code.',
};

/**
 * Sigma value modifiers, and how each is expressed in the target.
 *
 * Getting a modifier wrong is a quieter error than a wrong field name but has
 * the same effect: `|endswith` rendered as equality matches nothing.
 */
export const MODIFIER_TRANSLATION: Record<string, { kql: string; spl: string; cql: string }> = {
  contains: { kql: 'has (term) or contains (substring)', spl: '="*value*"', cql: '=/value/ or =*value*' },
  startswith: { kql: 'startswith', spl: '="value*"', cql: '=/^value/' },
  endswith: { kql: 'endswith', spl: '="*value"', cql: '=/value$/' },
  all: { kql: 'has_all, or chained and', spl: 'AND between predicates', cql: 'separate | stages' },
  re: { kql: 'matches regex', spl: '| regex field="pattern"', cql: '=/pattern/' },
  base64: { kql: 'base64_decode_tostring, then match', spl: '| eval d=base64decode(f)', cql: 'base64Decode()' },
  base64offset: { kql: 'match all three offset encodings', spl: 'match all three offset encodings', cql: 'match all three offset encodings' },
  cidr: { kql: 'ipv4_is_in_range', spl: 'CIDR match via where cidrmatch()', cql: 'cidr(field, subnet=…)' },
  windash: { kql: 'has_any over - / – / — variants', spl: 'OR over dash variants', cql: 'regex alternation over dash variants' },
  lt: { kql: '<', spl: '<', cql: '<' },
  lte: { kql: '<=', spl: '<=', cql: '<=' },
  gt: { kql: '>', spl: '>', cql: '>' },
  gte: { kql: '>=', spl: '>=', cql: '>=' },
};

export function categoriesWithMappings(): string[] {
  return Object.keys(FIELD_MAPPINGS);
}
