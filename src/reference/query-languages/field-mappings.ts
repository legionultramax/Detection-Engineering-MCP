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
 */
export const CATEGORY_SOURCES: Record<string, { kql: string; spl: string; cql: string }> = {
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
  image_load: {
    kql: 'DeviceImageLoadEvents',
    spl: 'Endpoint.Processes',
    cql: 'ImageHash',
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
