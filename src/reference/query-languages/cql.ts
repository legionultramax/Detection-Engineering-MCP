// CrowdStrike Query Language — Falcon LogScale (formerly Humio).
//
// Confidence is deliberately 'community', not 'confirmed'. Event names come
// from a community extraction of CrowdStrike's auth-gated documentation,
// vendored at data/third-party/crowdstrike-events/sensor_events.csv: 998
// events, 337 of them with no description at all, and at least two with
// platform lists that contradict their own text. It is far better than writing
// event names from memory and it is not ground truth. Every output built on it
// must cite the official sensor map.

import type { LanguageSpec } from './types.js';

export const CQL_SPEC: LanguageSpec = {
  id: 'cql',
  name: 'CrowdStrike Query Language',
  engine: 'Falcon LogScale (formerly Humio)',
  confidence: 'community',
  authority: 'https://docs.crowdstrike.com/r/en-US/sensormap.ftmap',

  dataModel:
    'Pipeline, not SQL. A query is a filter expression followed by | separated stages: ' +
    '#repo=falcon event_simpleName=ProcessRollup2 | groupBy([ComputerName]) .\n\n' +
    'Tag filters come first and are the cheapest selector — #repo and #type are indexed tags, ' +
    'and putting them at the head of the query lets LogScale skip whole segments. ' +
    'event_simpleName is the discriminator that decides which fields exist on an event: ' +
    'ProcessRollup2 carries CommandLine and ParentBaseFileName, DnsRequest carries DomainName, ' +
    'NetworkConnectIP4 carries RemoteAddressIP4 and RemotePort. Selecting the wrong event name ' +
    'produces a syntactically valid query over the wrong rows.\n\n' +
    'Time is normally supplied by the search interface or the API call rather than written into ' +
    'the query, which is why an explicit time bound is advisory here rather than required.',

  operators: [
    { operator: '#repo= / #type=', indexed: 'yes', use: 'Tag filters. Put them first; they prune segments.' },
    { operator: 'field=value', indexed: 'yes', use: 'Exact match.' },
    { operator: 'field=*value*', indexed: 'partial', use: 'Glob. Leading wildcard costs more.' },
    { operator: 'field=/regex/', indexed: 'no', use: 'Regex. Add i for case-insensitive: /enc/i' },
    { operator: 'field=/(?<name>…)/', indexed: 'no', use: 'Named capture, extracting a new field inline.' },
    { operator: 'in(field, values=[…])', indexed: 'yes', use: 'Set membership.' },
    { operator: 'bare term', indexed: 'yes', use: 'Free-text search across the event.' },
    { operator: '| groupBy([f], function=…)', indexed: 'no', use: 'Aggregation stage.' },
  ],

  cost: [
    { cost: 'cheap', construct: '#repo / #type tag filters at the head of the query' },
    { cost: 'cheap', construct: 'event_simpleName equality' },
    { cost: 'medium', construct: 'groupBy over a low-cardinality key' },
    { cost: 'expensive', construct: 'regex over a high-volume field such as CommandLine' },
    { cost: 'expensive', construct: 'leading-wildcard glob' },
    { cost: 'very expensive', construct: 'groupBy over a high-cardinality key such as CommandLine' },
  ],

  prohibitions: [
    {
      id: 'cql.sql-syntax',
      severity: 'blocking',
      title: 'SQL syntax',
      reason: 'CQL is a pipeline language. SELECT / FROM / WHERE are not valid.',
      fix: 'Write filters as bare predicates, then pipe into stages: field=value | groupBy([…])',
      pattern: '\\b(SELECT\\s+[\\w*]|FROM\\s+\\w+\\s+WHERE|INNER\\s+JOIN)\\b',
      flags: 'i',
    },
    {
      id: 'cql.no-event-selector',
      severity: 'blocking',
      title: 'No event_simpleName or tag filter',
      reason:
        'Without an event selector the query matches every event type in the repository. Since ' +
        'the available fields depend on the event, an unselected query is also unpredictable.',
      fix: 'Add event_simpleName=… , and lead with #repo= where you know the repository.',
      pattern: '(event_simpleName\\s*=|#repo\\s*=|#type\\s*=)',
      invert: true,
    },
    {
      id: 'cql.unquoted-regex',
      severity: 'warning',
      title: 'Regex without slash delimiters',
      reason: 'CQL regex literals are delimited with /…/. A bare string is treated as a glob.',
      fix: 'Wrap the pattern: CommandLine=/-enc/i',
      pattern: '\\b(?:matches|regex)\\s*\\(',
    },
    {
      id: 'cql.tag-filter-not-first',
      severity: 'warning',
      title: 'Tag filter is not at the head of the query',
      reason:
        'Tag filters prune whole segments before anything else runs. Placed after another ' +
        'predicate they still work, but the pruning benefit is reduced.',
      fix: 'Move #repo= / #type= to the front.',
      pattern: '^\\s*(?!#)[^|\\n]*?#(repo|type)\\s*=',
      flags: 'm',
    },
    {
      id: 'cql.groupby-high-cardinality',
      severity: 'warning',
      title: 'groupBy over a high-cardinality field',
      reason:
        'Grouping by CommandLine or a full path produces close to one group per event and can ' +
        'exhaust the aggregation limit, silently truncating results.',
      fix: 'Group by host, user or file name, and carry the command line with collect() or as a sample.',
      pattern: 'groupBy\\s*\\(\\s*\\[?[^\\])]*\\b(CommandLine|ImageFileName|TargetFileName)\\b',
    },
  ],

  examples: [
    {
      shape: 'process_creation',
      title: 'Encoded PowerShell execution',
      query:
        '#repo=falcon event_simpleName=ProcessRollup2\n' +
        '| in(FileName, values=["powershell.exe", "pwsh.exe"])\n' +
        '| CommandLine=/-enc(odedcommand)?\\s/i\n' +
        '| groupBy([ComputerName, UserName, FileName], function=collect([CommandLine]))',
      notes:
        'ProcessRollup2 is Windows-only in the vendored dictionary. For Linux or macOS the ' +
        'cross-platform equivalent is SyntheticProcessRollup2.',
    },
    {
      shape: 'process_creation',
      title: 'Cross-platform process execution',
      query:
        '#repo=falcon event_simpleName=SyntheticProcessRollup2\n' +
        '| in(FileName, values=["curl", "wget"])\n' +
        '| groupBy([ComputerName, UserName, FileName, CommandLine], function=count())',
      notes:
        'SyntheticProcessRollup2 covers Windows, Linux, macOS and Falcon Container, where ' +
        'ProcessRollup2 does not.',
    },
    {
      shape: 'dns_query',
      title: 'DNS lookups to a suspicious TLD',
      query:
        '#repo=falcon event_simpleName=DnsRequest\n' +
        '| DomainName=/\\.(top|xyz|zip|mov)$/i\n' +
        '| groupBy([ComputerName, DomainName], function=count())\n' +
        '| sort(_count, order=desc, limit=50)',
    },
    {
      shape: 'network_connection',
      title: 'Outbound connection from a scripting host',
      query:
        '#repo=falcon event_simpleName=NetworkConnectIP4\n' +
        '| in(ContextBaseFileName, values=["wscript.exe", "cscript.exe", "mshta.exe"])\n' +
        '| groupBy([ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort], function=count())',
    },
    {
      shape: 'credential_access',
      title: 'LSASS handle access indicators',
      query:
        '#repo=falcon event_simpleName=SuspiciousCredentialModuleLoad\n' +
        '| groupBy([ComputerName, ImageFileName, TargetFileName], function=count())',
      notes:
        'Falcon ships detection-derived events as well as raw telemetry. Prefer them where they ' +
        'exist — they encode CrowdStrike\'s own logic rather than reimplementing it.',
    },
    {
      shape: 'file_event',
      title: 'Executable written to a user-writable path',
      query:
        '#repo=falcon event_simpleName=NewExecutableWritten\n' +
        '| TargetFileName=/\\\\(Users\\\\Public|AppData\\\\Local\\\\Temp)\\\\/i\n' +
        '| groupBy([ComputerName, TargetFileName], function=count())',
    },
  ],

  notes: [
    'Event names are case-sensitive PascalCase: ProcessRollup2, not process_rollup2.',
    'Which fields exist depends entirely on event_simpleName. Verify the event before ' +
      'assuming a field, and verify the event itself against the official sensor map — the ' +
      'vendored dictionary is an unofficial extraction.',
    'ProcessRollup2 is listed Windows-only. A Linux process rule written against it returns ' +
      'nothing; use SyntheticProcessRollup2 for cross-platform coverage.',
    '337 of the 998 events in the vendored dictionary have no description. An event being ' +
      'listed is not evidence that it does what its name suggests.',
    'Falcon emits both raw telemetry and detection-derived events. Where a purpose-built event ' +
      'exists, using it beats reimplementing the same logic over raw telemetry.',
  ],
};
