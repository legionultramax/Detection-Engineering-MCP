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

/**
 * Target field for one Sigma field, per language. null = no equivalent.
 *
 * `aql` is optional rather than required, and the difference is deliberate.
 * QRadar normalises only the network and identity envelope; every process,
 * file, registry and command-line field is a Custom Event Property whose name
 * is chosen per deployment. Where a normalised property exists the target is
 * given bare and lower-case (`destinationport`). Where it does not, the target
 * is given **with its double quotes** (`'"Process CommandLine"'`) — which is
 * both the syntax Ariel requires and the signal that this is a per-deployment
 * guess rather than a fact. An absent `aql` key means no mapping was authored
 * for that field at all, which the brief reports as unmapped.
 */
export interface FieldTargets {
  kql: string | null;
  spl: string | null;
  cql: string | null;
  aql?: string | null;
  /** Why a mapping is awkward, where it is. */
  note?: string;
}

/**
 * True when an AQL target names a Custom Event Property rather than a
 * normalised Ariel property.
 *
 * The test is the quoting, because in Ariel the quoting *is* the distinction —
 * a bare identifier is resolved against QRadar's normalised schema and a quoted
 * one against the deployment's custom property list.
 */
export function isAqlCustomProperty(target: string | null | undefined): boolean {
  return typeof target === 'string' && target.trim().startsWith('"');
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
export const CATEGORY_SOURCES: Record<string, {
  kql: string | null; spl: string | null; cql: string | null; aql?: string | null;
}> = {
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

// ── Remaining corpus categories ────────────────────────────────────────────
//
// The 24 categories left uncovered held 381 rules. 292 of them are mapped
// below; the rest are deliberately left alone and the reasons are recorded at
// the bottom, because "we chose not to" and "we forgot" look identical in a
// coverage report otherwise.
//
// Field names here were read out of the rules themselves rather than recalled,
// and every Falcon event was checked against the vendored dictionary — which is
// how NamedPipeCreated and CreateRemoteThread were caught as non-existent. The
// real events are NamedPipe and InjectedThread.

/** IIS and web server logs. W3C field names, not the Sigma endpoint taxonomy. */
CATEGORY_SOURCES.webserver = { kql: 'W3CIISLog', spl: 'Web.Web', cql: null };
FIELD_MAPPINGS.webserver = {
  'cs-uri-query': { kql: 'csUriQuery', spl: 'Web.uri_query', cql: null },
  'cs-uri-stem': { kql: 'csUriStem', spl: 'Web.uri_path', cql: null },
  'cs-uri': { kql: 'csUriStem', spl: 'Web.url', cql: null },
  'cs-method': { kql: 'csMethod', spl: 'Web.http_method', cql: null },
  'sc-status': { kql: 'scStatus', spl: 'Web.status', cql: null },
  'cs-user-agent': { kql: 'csUserAgent', spl: 'Web.http_user_agent', cql: null },
  'cs-referer': { kql: 'csReferer', spl: 'Web.http_referrer', cql: null },
  'cs-username': { kql: 'csUserName', spl: 'Web.user', cql: null },
  'c-ip': { kql: 'cIP', spl: 'Web.src', cql: null },
  'cs-host': { kql: 'csHost', spl: 'Web.site', cql: null },
};

/** Proxy logs. Overlapping but distinct field naming from webserver. */
CATEGORY_SOURCES.proxy = { kql: 'CommonSecurityLog', spl: 'Web.Web', cql: null };
FIELD_MAPPINGS.proxy = {
  'c-uri': { kql: 'RequestURL', spl: 'Web.url', cql: null },
  'cs-uri': { kql: 'RequestURL', spl: 'Web.url', cql: null },
  'c-uri-query': { kql: 'RequestURL', spl: 'Web.uri_query', cql: null },
  'c-useragent': { kql: 'RequestClientApplication', spl: 'Web.http_user_agent', cql: null },
  'cs-method': { kql: 'RequestMethod', spl: 'Web.http_method', cql: null },
  'cs-host': { kql: 'DestinationHostName', spl: 'Web.dest', cql: null },
  'sc-status': { kql: 'EventOutcome', spl: 'Web.status', cql: null },
  'src_ip': { kql: 'SourceIP', spl: 'Web.src', cql: null },
  'dst_ip': { kql: 'DestinationIP', spl: 'Web.dest_ip', cql: null },
  'cs-bytes': { kql: 'SentBytes', spl: 'Web.bytes_out', cql: null },
};

/** Network-level DNS logs — distinct from dns_query, which is Sysmon 22. */
CATEGORY_SOURCES.dns = { kql: 'DnsEvents', spl: 'Network_Resolution.DNS', cql: 'DnsRequest' };
FIELD_MAPPINGS.dns = {
  query: { kql: 'Name', spl: 'DNS.query', cql: 'DomainName' },
  record_type: { kql: 'QueryType', spl: 'DNS.record_type', cql: 'RequestType' },
  answer: { kql: 'IPAddresses', spl: 'DNS.answer', cql: 'IP4Records' },
  parent_domain: { kql: null, spl: null, cql: null,
    note: 'Sigma expresses this as a computed parent of the queried name. Derive it in the ' +
      'target query rather than expecting a column.' },
};

/** PowerShell module logging, event 4103. */
CATEGORY_SOURCES.ps_module = { kql: 'DeviceEvents', spl: null, cql: 'ScriptControlScanTelemetry' };
FIELD_MAPPINGS.ps_module = {
  Payload: { kql: 'AdditionalFields', spl: 'Payload', cql: null,
    note: 'Event 4103 payload. Defender carries it inside AdditionalFields; Splunk reads the ' +
      'field directly off the event.' },
  ContextInfo: { kql: 'AdditionalFields', spl: 'ContextInfo', cql: null },
  Image: { kql: 'InitiatingProcessFolderPath', spl: null, cql: 'ContextBaseFileName' },
  User: { kql: 'InitiatingProcessAccountName', spl: 'user', cql: 'UserName' },
};

/** Classic PowerShell engine start, event 400. */
CATEGORY_SOURCES.ps_classic_start = { kql: 'DeviceEvents', spl: null, cql: null };
FIELD_MAPPINGS.ps_classic_start = {
  Data: { kql: 'AdditionalFields', spl: 'Data', cql: null,
    note: 'Event 400 carries HostApplication and engine version inside an unstructured Data ' +
      'blob. Both targets need a text extraction rather than a field comparison.' },
};

/** Sysmon 17/18. */
CATEGORY_SOURCES.pipe_created = { kql: 'DeviceEvents', spl: null, cql: 'NamedPipe' };
FIELD_MAPPINGS.pipe_created = {
  PipeName: { kql: 'AdditionalFields', spl: null, cql: 'NamedPipeName',
    note: 'Defender surfaces named pipes on DeviceEvents where ActionType is NamedPipeEvent, ' +
      'with the pipe name inside AdditionalFields.' },
  Image: { kql: 'InitiatingProcessFolderPath', spl: null, cql: 'ContextBaseFileName' },
};

/** Sysmon 8 — the injection shape. */
CATEGORY_SOURCES.create_remote_thread = { kql: 'DeviceEvents', spl: null, cql: 'InjectedThread' };
FIELD_MAPPINGS.create_remote_thread = {
  SourceImage: { kql: 'InitiatingProcessFolderPath', spl: null, cql: 'ContextBaseFileName' },
  TargetImage: { kql: 'FolderPath', spl: null, cql: 'TargetFileName' },
  SourceParentImage: { kql: 'InitiatingProcessParentFileName', spl: null, cql: null },
  SourceCommandLine: { kql: 'InitiatingProcessCommandLine', spl: null, cql: 'CommandLine' },
  StartFunction: { kql: 'AdditionalFields', spl: null, cql: null },
  StartModule: { kql: 'AdditionalFields', spl: null, cql: null },
  StartAddress: { kql: null, spl: null, cql: null },
};

/** File-event variants. Same telemetry, different Sysmon event, different Falcon event. */
CATEGORY_SOURCES.file_delete = { kql: 'DeviceFileEvents', spl: 'Endpoint.Filesystem', cql: 'FileDeleted' };
CATEGORY_SOURCES.file_access = { kql: 'DeviceFileEvents', spl: 'Endpoint.Filesystem', cql: 'FileOpenInfo' };
CATEGORY_SOURCES.file_rename = { kql: 'DeviceFileEvents', spl: 'Endpoint.Filesystem', cql: 'FileRenameInfo' };
CATEGORY_SOURCES.file_change = { kql: 'DeviceFileEvents', spl: 'Endpoint.Filesystem', cql: null };
CATEGORY_SOURCES.file_executable_detected =
  { kql: 'DeviceFileEvents', spl: 'Endpoint.Filesystem', cql: 'NewExecutableWritten' };
CATEGORY_SOURCES.create_stream_hash =
  { kql: 'DeviceFileEvents', spl: 'Endpoint.Filesystem', cql: 'MotwWritten' };

for (const cat of ['file_delete', 'file_access', 'file_rename', 'file_change',
                   'file_executable_detected', 'create_stream_hash'] as const) {
  FIELD_MAPPINGS[cat] = { ...FIELD_MAPPINGS.file_event };
}
FIELD_MAPPINGS.file_access.FileName = { kql: 'FileName', spl: 'Filesystem.file_name', cql: 'TargetFileName' };
FIELD_MAPPINGS.file_rename.SourceFilename = { kql: 'PreviousFileName', spl: null, cql: 'SourceFileName' };
FIELD_MAPPINGS.file_change.PreviousCreationUtcTime = { kql: null, spl: null, cql: null,
  note: 'Timestomping evidence. Neither target exposes the prior creation time as a column; ' +
    'detecting it requires comparing against a baseline.' };
FIELD_MAPPINGS.create_stream_hash.Contents = { kql: null, spl: null, cql: null,
  note: 'Alternate data stream contents. Sysmon captures a prefix; neither Defender nor Falcon ' +
    'exposes stream contents, so match on the stream name and path instead.' };
FIELD_MAPPINGS.create_stream_hash.Hash = { kql: 'SHA256', spl: 'Filesystem.file_hash', cql: 'SHA256HashData' };

// The last few stragglers the coverage run surfaced. Each appeared three times,
// which is small but free to close.
for (const cat of ['file_event', 'file_delete', 'file_access', 'file_rename', 'file_change',
                   'file_executable_detected', 'create_stream_hash', 'image_load'] as const) {
  FIELD_MAPPINGS[cat].ParentImage ??= {
    kql: 'InitiatingProcessParentFileName', spl: null, cql: 'ParentBaseFileName',
    note: 'The parent of the process touching the file, two hops from the file itself.',
  };
}
FIELD_MAPPINGS.create_remote_thread.TargetParentProcessId = {
  kql: null, spl: null, cql: 'TargetProcessId',
  note: 'Sigma means the parent of the injected-into process. Defender does not expose it on ' +
    'the injection row; pivot via DeviceProcessEvents on the target process.',
};
for (const cat of ['ps_module', 'ps_classic_start'] as const) {
  FIELD_MAPPINGS[cat].Provider_Name ??= FIELD_MAPPINGS.ps_script.Provider_Name;
}

// ── QRadar / Ariel ─────────────────────────────────────────────────────────
//
// Added last and kept in one block, because AQL's mapping story is structurally
// different from the other three and mixing it in above would hide that.
//
// There is exactly one Ariel table for log telemetry, `events`, so there is no
// per-category source selection to make — the discriminating work that
// DeviceProcessEvents does in KQL is done in AQL by a predicate on logsourceid,
// category or qid. `flows` exists but holds QRadar's own network flow records,
// not forwarded logs, so no Sigma category maps to it.
//
// The split that matters is per *field*, not per category. QRadar normalises the
// network and identity envelope, and those targets are given bare and lower
// case. Everything else is a Custom Event Property, given quoted, and the quotes
// mean "this name is a convention in most deployments and a guess in yours".
// Nothing here is corroborated: there are zero AQL rules in the corpus.
for (const cat of Object.keys(CATEGORY_SOURCES)) {
  CATEGORY_SOURCES[cat].aql = 'events';
}

/**
 * Normalised properties that map cleanly, wherever the category uses them.
 *
 * These are the mappings worth trusting. `username`, `sourceip` and
 * `destinationport` are populated by QRadar's own normalisation rather than by
 * a customer's property extraction, so unlike a CEP they are the same in every
 * deployment.
 */
const AQL_NORMALISED: Record<string, string> = {
  User: 'username',
  TargetUserName: 'username',
  SourceIp: 'sourceip',
  DestinationIp: 'destinationip',
  SourcePort: 'sourceport',
  DestinationPort: 'destinationport',
  src_ip: 'sourceip',
  dst_ip: 'destinationip',
  'c-ip': 'sourceip',
  'cs-username': 'username',
};

const AQL_TARGETS: Record<string, Record<string, string | null>> = {
  process_creation: {
    Image: '"Process Path"',
    CommandLine: '"Process CommandLine"',
    ParentImage: '"Parent Process Path"',
    ParentCommandLine: '"Parent Process CommandLine"',
    Hashes: '"File Hash"',
    sha256: '"SHA256 Hash"',
    md5: '"MD5 Hash"',
    OriginalFileName: null,
    IntegrityLevel: null,
    CurrentDirectory: null,
    Company: null,
    Product: null,
    Description: null,
    LogonId: null,
  },
  network_connection: {
    Image: '"Process Path"',
    DestinationHostname: '"Destination Hostname"',
    Protocol: 'protocolid',
    Initiated: 'eventdirection',
    DestinationIsIpv6: null,
  },
  dns_query: {
    QueryName: '"DNS Query Name"',
    query: '"DNS Query Name"',
    answer: '"DNS Answer"',
    Image: '"Process Path"',
    QueryStatus: null,
  },
  dns: {
    query: '"DNS Query Name"',
    answer: '"DNS Answer"',
    record_type: '"DNS Record Type"',
    parent_domain: null,
  },
  file_event: {
    TargetFilename: '"File Path"',
    Image: '"Process Path"',
    CreationUtcTime: 'devicetime',
    Hashes: '"File Hash"',
  },
  registry_event: {
    TargetObject: '"Registry Key Path"',
    Details: '"Registry Value Data"',
    NewName: '"Registry Value Name"',
    Image: '"Process Path"',
    EventType: null,
    ImagePath: '"Registry Value Data"',
  },
  authentication: {
    SubjectUserName: '"Source User"',
    IpAddress: 'sourceip',
    WorkstationName: 'identityhostname',
    LogonType: '"Logon Type"',
    Status: 'qid',
    EventID: 'qid',
  },
  // QRadar's strongest ground. Proxy, web and firewall logs are what it was
  // built to ingest, so these arrive through a vendor DSM rather than a
  // hand-rolled property extraction and the names are more stable than the
  // endpoint CEPs above.
  webserver: {
    'cs-uri-query': '"URL"',
    'cs-uri-stem': '"URL Path"',
    'cs-uri': '"URL"',
    'cs-method': '"HTTP Method"',
    'sc-status': '"HTTP Response Code"',
    'cs-user-agent': '"User Agent"',
    'cs-referer': '"HTTP Referrer"',
    'cs-host': '"HTTP Host"',
  },
  proxy: {
    'c-uri': '"URL"',
    'cs-uri': '"URL"',
    'c-uri-query': '"URL"',
    'c-useragent': '"User Agent"',
    'cs-method': '"HTTP Method"',
    'cs-host': '"HTTP Host"',
    'sc-status': '"HTTP Response Code"',
    'cs-bytes': 'sourcebytes',
  },
};

/** Notes attached where the mapping is lossy in a way that changes the query. */
const AQL_NOTES: Record<string, string> = {
  ParentCommandLine:
    'Rarely extracted as a property. Most Windows DSMs surface the parent image but not the ' +
    'parent command line; if it is needed, confirm the CEP exists before relying on it.',
  Protocol:
    'Sigma names the protocol (tcp/udp); Ariel stores protocolid as a number. Compare against ' +
    'the numeric IANA value, or render it with a lookup for display only.',
  Initiated:
    'Sigma Initiated is a boolean. Ariel expresses direction as eventdirection, whose values ' +
    'depend on how the log source is configured — confirm rather than assuming L2R/R2L.',
  Status:
    'Authentication success and failure are not a field in QRadar; they are encoded in the QID ' +
    'and its category. Filter on category or qid rather than looking for a status property.',
  EventID:
    'Windows event IDs do not survive normalisation as a queryable property. QRadar maps each ' +
    'to a QID, and that mapping belongs to the installed DSM — so a qid filter is correct only ' +
    'for the deployment it was written against.',
  WorkstationName:
    'identityhostname is populated only when asset identity resolution is enabled and has seen ' +
    'the host. It is empty rather than wrong when it is not.',
  CreationUtcTime:
    'devicetime is the timestamp the device reported, not a file creation time. The closest ' +
    'available property, and not the same thing — say so if the rule depends on file times.',
  'cs-bytes':
    'sourcebytes is a flow property. On an event it is populated only if the DSM maps it, so ' +
    'confirm before filtering on volume.',
};

for (const [cat, targets] of Object.entries(AQL_TARGETS)) {
  const table = FIELD_MAPPINGS[cat];
  if (!table) continue;
  for (const [field, target] of Object.entries(targets)) {
    if (!table[field]) continue;
    table[field].aql = target;
    if (AQL_NOTES[field] && !table[field].note) table[field].note = AQL_NOTES[field];
  }
}

// The normalised set applies across every category that references the field,
// and is applied after the per-category table so it wins. These are the only
// AQL targets in this file that do not depend on a deployment's property
// configuration.
for (const table of Object.values(FIELD_MAPPINGS)) {
  for (const [field, target] of Object.entries(AQL_NORMALISED)) {
    if (table[field]) table[field].aql = target;
  }
  // CommandLine appears across categories via the cross-category loop above.
  if (table.CommandLine && table.CommandLine.aql === undefined) {
    table.CommandLine.aql = '"Process CommandLine"';
  }
}

/**
 * Categories deliberately left unmapped, and why.
 *
 * Recorded so a future coverage report distinguishes a decision from an
 * oversight. Together these are 89 rules.
 */
export const UNMAPPED_CATEGORIES: Record<string, string> = {
  application: 'Product-specific by definition — the corpus rules target opencanary and ' +
    'rpc_firewall, whose fields (InterfaceUuid, OpNum) exist only in those products. A generic ' +
    'mapping would be wrong for every product it did not have in mind.',
  antivirus: 'Signature names are vendor-specific strings. There is no portable target for ' +
    '"the AV called it Trojan.GenericKD".',
  firewall: 'Six rules, and the field names differ per vendor appliance.',
  wmi_event: 'Three rules. Defender has no WMI-subscription table; the telemetry arrives as ' +
    'DeviceEvents with a WmiEvent ActionType and needs per-rule handling.',
  raw_access_thread: 'One rule.',
  process_tampering: 'One rule.',
  sysmon_status: 'Sysmon service health, not adversary behaviour.',
  sysmon_error: 'Sysmon service health, not adversary behaviour.',
  ps_classic_provider_start: 'One rule, and it overlaps ps_classic_start.',
  database: 'One rule.',
  appliance: 'One rule, vendor-specific (Palo Alto).',
};

/**
 * Sigma value modifiers, and how each is expressed in the target.
 *
 * Getting a modifier wrong is a quieter error than a wrong field name but has
 * the same effect: `|endswith` rendered as equality matches nothing.
 */
export const MODIFIER_TRANSLATION: Record<string, { kql: string; spl: string; cql: string; aql: string }> = {
  contains: { kql: 'has (term) or contains (substring)', spl: '="*value*"', cql: '=/value/ or =*value*',
    aql: "ILIKE '%value%' — or TEXT SEARCH 'value' against the raw payload, which is indexed" },
  startswith: { kql: 'startswith', spl: '="value*"', cql: '=/^value/', aql: "ILIKE 'value%'" },
  endswith: { kql: 'endswith', spl: '="*value"', cql: '=/value$/', aql: "ILIKE '%value'" },
  all: { kql: 'has_all, or chained and', spl: 'AND between predicates', cql: 'separate | stages',
    aql: 'AND between predicates' },
  re: { kql: 'matches regex', spl: '| regex field="pattern"', cql: '=/pattern/',
    aql: "MATCHES 'pattern', or IMATCHES for case-insensitive. Not REGEXP or ~" },
  base64: { kql: 'base64_decode_tostring, then match', spl: '| eval d=base64decode(f)', cql: 'base64Decode()',
    aql: 'No decode function in Ariel. Match the encoded string itself, or decode downstream — ' +
      'and say which, because they detect different things' },
  base64offset: { kql: 'match all three offset encodings', spl: 'match all three offset encodings', cql: 'match all three offset encodings',
    aql: 'Match all three offset encodings as literal strings; Ariel cannot decode' },
  cidr: { kql: 'ipv4_is_in_range', spl: 'CIDR match via where cidrmatch()', cql: 'cidr(field, subnet=…)',
    aql: "INCIDR('10.0.0.0/8', sourceip) — subnet first, then the property" },
  windash: { kql: 'has_any over - / – / — variants', spl: 'OR over dash variants', cql: 'regex alternation over dash variants',
    aql: 'OR over the dash variants with ILIKE' },
  lt: { kql: '<', spl: '<', cql: '<', aql: '<' },
  lte: { kql: '<=', spl: '<=', cql: '<=', aql: '<=' },
  gt: { kql: '>', spl: '>', cql: '>', aql: '>' },
  gte: { kql: '>=', spl: '>=', cql: '>=', aql: '>=' },
};

export function categoriesWithMappings(): string[] {
  return Object.keys(FIELD_MAPPINGS);
}
