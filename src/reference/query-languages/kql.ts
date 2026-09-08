// Kusto Query Language — Microsoft Sentinel and Defender Advanced Hunting.
//
// The operator index-backing facts and several anti-patterns follow the
// analysis in .claude/skills/spl-optimizer/SKILL.md (Apache-2.0, Michael Haag),
// which is vendored in this repository. Content here is written independently;
// that skill is cited as prior art. See .claude/skills/NOTICE.md.

import type { LanguageSpec } from './types.js';

export const KQL_SPEC: LanguageSpec = {
  id: 'kql',
  name: 'Kusto Query Language',
  engine: 'Azure Data Explorer (Kusto), via Microsoft Sentinel / Defender Advanced Hunting',
  confidence: 'confirmed',
  authority: 'https://learn.microsoft.com/azure/data-explorer/kusto/query/',

  dataModel:
    'Tabular. A query names a table, then pipes it through operators: ' +
    'TableName | where ... | project ... | summarize ... . The table name must come first. ' +
    'Kusto has its own optimiser (predicate pushdown, column pruning), but the physical plan ' +
    'still follows what you write, so ordering matters. Field names are case-sensitive; ' +
    'string comparison is case-sensitive unless the operator ends in ~ (== vs =~). ' +
    'Tables differ between Sentinel workspaces and Defender: Defender uses Device* tables ' +
    '(DeviceProcessEvents, DeviceNetworkEvents), Sentinel adds SecurityEvent, CommonSecurityLog, ' +
    'SigninLogs and whatever solutions are installed.',

  operators: [
    { operator: 'has', indexed: 'yes', use: 'Whole-term match. The default choice for a word.' },
    { operator: 'has_any', indexed: 'yes', use: 'Any of several terms.' },
    { operator: 'has_all', indexed: 'yes', use: 'All terms present, in any order.' },
    { operator: '==', indexed: 'yes', use: 'Exact, case-sensitive equality.' },
    { operator: '=~', indexed: 'yes', use: 'Exact, case-insensitive equality.' },
    { operator: 'in / in~', indexed: 'yes', use: 'Membership in a set. Prefer over chained or.' },
    { operator: 'startswith', indexed: 'partial', use: 'Prefix match.' },
    { operator: 'endswith', indexed: 'partial', use: 'Suffix match — common for image paths.' },
    { operator: 'contains', indexed: 'no', use: 'Substring scan. Only when the match crosses a term boundary.' },
    { operator: 'matches regex', indexed: 'no', use: 'Slowest. Only when no simpler operator expresses it.' },
  ],

  cost: [
    { cost: 'cheap', construct: 'where on a time column, then an indexed operator' },
    { cost: 'cheap', construct: 'project / project-away to drop columns early' },
    { cost: 'medium', construct: 'summarize with low-cardinality grouping keys' },
    { cost: 'expensive', construct: 'contains or startswith over a long free-text column' },
    { cost: 'expensive', construct: 'join', note: 'put the smaller result set on the left' },
    { cost: 'very expensive', construct: 'matches regex over a whole table' },
    { cost: 'very expensive', construct: 'mv-expand before filtering', note: 'multiplies rows, then filters' },
  ],

  prohibitions: [
    {
      id: 'kql.no-time-bound',
      severity: 'blocking',
      title: 'No time bound',
      reason:
        'Without a time predicate the query scans the full retention window. In Sentinel that ' +
        'is billable and may never return; in Advanced Hunting it hits the 10-minute cap.',
      fix: 'Add | where TimeGenerated > ago(1h) — or Timestamp for Defender tables — as the first filter.',
      pattern: '\\b(ago\\s*\\(|between\\s*\\(|>\\s*datetime\\(|startofday|TimeGenerated\\s*[><]|Timestamp\\s*[><])',
      invert: true,
    },
    {
      id: 'kql.unbounded-search',
      severity: 'blocking',
      title: 'Unbounded cross-table search',
      reason: 'search * scans every table in the workspace.',
      fix: 'Name the table the detection actually needs.',
      pattern: '^\\s*search\\s+\\*',
      flags: 'm',
    },
    {
      id: 'kql.contains-for-term',
      severity: 'warning',
      title: 'contains used for a whole term',
      reason:
        'contains is a substring scan and cannot use the term index. For a whole word, has is ' +
        'orders of magnitude cheaper over a large table.',
      fix: 'Replace contains with has where the match is a whole term.',
      pattern: '\\bcontains\\s+"[A-Za-z0-9_.-]+"',
    },
    {
      id: 'kql.regex-for-simple',
      severity: 'warning',
      title: 'Regex where a simpler operator would do',
      reason: 'matches regex gets no index acceleration and is the slowest string operation.',
      fix: 'Use has, startswith or endswith when the pattern has no alternation or quantifiers.',
      pattern: 'matches\\s+regex\\s+@?"[A-Za-z0-9_\\\\ .-]+"',
    },
    {
      id: 'kql.project-star',
      severity: 'warning',
      title: 'project *',
      reason: 'Carries every column through the pipeline, increasing data moved between nodes.',
      fix: 'Project only the columns the detection needs.',
      pattern: '\\bproject\\s+\\*',
    },
    {
      id: 'kql.mv-expand-before-filter',
      severity: 'warning',
      title: 'mv-expand before filtering',
      reason: 'Expanding an array multiplies rows, and any filter after it runs over the larger set.',
      fix: 'Filter first, expand second.',
      pattern: '\\bmv-expand\\b(?![\\s\\S]{0,80}\\bwhere\\b)',
    },
  ],

  examples: [
    {
      shape: 'process_creation',
      title: 'Encoded PowerShell execution',
      query:
        'DeviceProcessEvents\n' +
        '| where Timestamp > ago(1h)\n' +
        '| where FileName in~ ("powershell.exe", "pwsh.exe")\n' +
        '| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ")\n' +
        '| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
      notes: 'Time first, then indexed set membership, then indexed term match, then project.',
    },
    {
      shape: 'process_creation',
      title: 'LOLBAS download via certutil',
      query:
        'DeviceProcessEvents\n' +
        '| where Timestamp > ago(24h)\n' +
        '| where FileName =~ "certutil.exe"\n' +
        '| where ProcessCommandLine has_any ("urlcache", "verifyctl", "-decode")\n' +
        '| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
    },
    {
      shape: 'network_connection',
      title: 'Rare outbound port from a scripting host',
      query:
        'DeviceNetworkEvents\n' +
        '| where Timestamp > ago(24h)\n' +
        '| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe", "mshta.exe")\n' +
        '| summarize Connections = count(), Ports = make_set(RemotePort, 20)\n' +
        '    by DeviceName, InitiatingProcessFileName\n' +
        '| where Connections < 5',
      notes: 'Aggregate after filtering, and keep the grouping keys low-cardinality.',
    },
    {
      shape: 'authentication',
      title: 'Failed sign-ins across many accounts from one address',
      query:
        'SigninLogs\n' +
        '| where TimeGenerated > ago(1h)\n' +
        '| where ResultType != 0\n' +
        '| summarize Accounts = dcount(UserPrincipalName), Attempts = count()\n' +
        '    by IPAddress, bin(TimeGenerated, 10m)\n' +
        '| where Accounts > 10',
    },
    {
      shape: 'file_event',
      title: 'Executable written to a user-writable path',
      query:
        'DeviceFileEvents\n' +
        '| where Timestamp > ago(24h)\n' +
        '| where FileName endswith ".exe"\n' +
        '| where FolderPath has_any (@"\\Users\\Public\\", @"\\AppData\\Local\\Temp\\")\n' +
        '| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName',
    },
    {
      shape: 'registry_event',
      title: 'Run key persistence',
      query:
        'DeviceRegistryEvents\n' +
        '| where Timestamp > ago(24h)\n' +
        '| where ActionType == "RegistryValueSet"\n' +
        '| where RegistryKey has @"\\CurrentVersion\\Run"\n' +
        '| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData',
    },
  ],

  notes: [
    'Defender Advanced Hunting uses Timestamp; Sentinel workspace tables use TimeGenerated. ' +
      'Using the wrong one is a blocking error, not a style preference — the column does not exist.',
    'Tables ending in _CL are custom logs and exist only where that solution is installed. ' +
      'A query against one runs fine in the workspace that has it and returns nothing everywhere else.',
    'Case sensitivity bites: == is case-sensitive, =~ is not. File and process names in ' +
      'telemetry vary in case, so prefer =~ and in~ for them.',
    'let statements are materialised when referenced. Use them to avoid repeating a dataset, ' +
      'not to name an intermediate you only read once.',
  ],
};
