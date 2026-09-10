// Ariel Query Language — IBM QRadar.
//
// Confidence is 'unconfirmed', the weakest tier, and that is not pessimism:
//
//   1. There are zero AQL rules in the local corpus. Every other language in
//      this directory is graded against thousands of real rules — KQL against
//      5,509, SPL against 2,185. AQL has nothing to check against, so no field
//      name here can be corroborated the way a KQL column can.
//   2. More fundamentally, most of what a detection needs is not normalised by
//      QRadar at all. Ariel normalises the network and identity envelope —
//      sourceip, destinationport, username, qid — and everything else arrives
//      as a **Custom Event Property**, a per-deployment regex or JSON extraction
//      defined by whoever onboarded the log source. One customer's
//      "Process CommandLine" is another's "CommandLine" and another's
//      "cmdline", and a third may not extract it at all.
//
// So the useful thing this spec can do is not to assert field names. It is to
// separate the properties that are the same in every QRadar from the ones that
// are a local convention, and to say which is which every time.
//
// CEP targets are written **with their double quotes included** — '"Process
// Name"' rather than 'Process Name'. That is both the syntax AQL requires and
// the marker the validator and the translation brief use to grade a mapping as
// unverifiable. The quoting is load-bearing in both directions.

import type { LanguageSpec } from './types.js';

/**
 * Ariel properties that exist in every QRadar deployment.
 *
 * These come from QRadar's own normalisation, not from a customer's DSM
 * configuration, which is what makes them the one part of an AQL query that can
 * be checked. Anything not in this set is either a Custom Event Property, a
 * function alias, or a mistake — and the validator's job is to say which.
 *
 * Lower-cased because Ariel property names are case-insensitive, unlike the
 * quoted CEP names, which are not.
 */
export const AQL_EVENT_PROPERTIES: ReadonlySet<string> = new Set([
  // identity and network envelope
  'sourceip', 'destinationip', 'sourceport', 'destinationport',
  'sourcemac', 'destinationmac', 'prenatsourceip', 'postnatsourceip',
  'sourceaddress', 'destinationaddress',
  'username', 'identityip', 'identityhostname', 'identityusername',
  'identitymac', 'identitynetbiosname', 'hasidentity',
  // event classification
  'qid', 'category', 'highlevelcategory', 'eventdirection',
  'logsourceid', 'logsourcegroupid', 'logsourcetypeid',
  'magnitude', 'severity', 'credibility', 'relevance',
  'eventcount', 'protocolid', 'creeventlist',
  // time
  'starttime', 'endtime', 'devicetime', 'processortime',
  // content
  'payload', 'utf8_payload', 'message',
  // geography and topology
  'sourcegeographiclocation', 'destinationgeographiclocation',
  'sourcenetwork', 'destinationnetwork',
  // multi-tenancy — injected by the hunt backend, never written by hand
  'domainid',
  // flows table
  'sourcebytes', 'destinationbytes', 'sourcepackets', 'destinationpackets',
  'firstpackettime', 'lastpackettime', 'flowtype', 'flowsource',
  'flowinterface', 'applicationid', 'icmptype', 'icmpcode', 'tcpflags',
]);

/** Ariel tables. There are only two, and they cannot be joined. */
export const AQL_TABLES: readonly string[] = ['events', 'flows'];

/**
 * Scalar and aggregate functions Ariel provides.
 *
 * Needed so the extractor does not report `COUNT` or `QIDNAME` as an unknown
 * property. The aggregate subset is listed separately because its presence is
 * what triggers the chunking warning below.
 */
export const AQL_FUNCTIONS: ReadonlySet<string> = new Set([
  'lower', 'upper', 'str', 'long', 'double', 'concat', 'substring', 'strlen',
  'dateformat', 'now', 'parsedatetime', 'incidr', 'utf8', 'base64',
  'qidname', 'qiddescription', 'categoryname', 'logsourcename',
  'networkname', 'rulename', 'assethostname', 'assetuser',
  'referencetable', 'referencemap', 'referencesetcontains',
  'count', 'sum', 'avg', 'min', 'max', 'uniquecount', 'first', 'last',
  'stddev', 'median', 'coalesce', 'isnull', 'cast',
]);

export const AQL_AGGREGATE_FUNCTIONS: readonly string[] = [
  'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'UNIQUECOUNT', 'FIRST', 'LAST',
  'STDDEV', 'MEDIAN',
];

export const AQL_SPEC: LanguageSpec = {
  id: 'aql',
  name: 'Ariel Query Language',
  engine: 'IBM QRadar (Ariel)',
  confidence: 'unconfirmed',
  authority: 'https://www.ibm.com/docs/en/qsip',

  dataModel:
    'SQL-shaped, and only SQL-shaped on the surface. A query is ' +
    'SELECT <properties> FROM events WHERE <predicates> [GROUP BY …] ' +
    '[ORDER BY …] [LIMIT n] [time bound].\n\n' +
    'There are exactly two tables, `events` and `flows`, and **they cannot be joined** — ' +
    'Ariel has no JOIN of any kind, no UNION, and no subquery in FROM. Any correlation across ' +
    'two event shapes has to be done outside the query, or collapsed into one pass with ' +
    'conditional aggregation over a shared key.\n\n' +
    'The property model is the part that catches people. QRadar normalises the network and ' +
    'identity envelope — sourceip, destinationip, destinationport, username, qid, logsourceid, ' +
    'category, magnitude, starttime — and these are identical in every deployment. Everything ' +
    'else, including every process, file, registry and command-line field a detection actually ' +
    'needs, is a **Custom Event Property**: a regex or JSON extraction configured per log source ' +
    'by whoever onboarded it. CEP names are double-quoted and case-sensitive — "Process ' +
    'CommandLine" — and they differ between customers. A CEP that is not configured is not an ' +
    'error; the property is simply null, and the query returns nothing.\n\n' +
    'A QID identifies an event type. Mapping a Windows event ID to a QID is a property of the ' +
    'installed DSM, so filtering on `qid` is portable only within one deployment; ' +
    'QIDNAME(qid) is readable but is a function call, so it cannot use the index.\n\n' +
    'Time is supplied as `LAST n HOURS` or `START <epoch_ms> STOP <epoch_ms>`. **In the hunt ' +
    'pipeline you must not write either** — the Phase 2 backend appends its own START/STOP ' +
    'from the request\'s date range, and a query that already carries one conflicts with it.',

  operators: [
    { operator: '=  !=  <  <=  >  >=', indexed: 'yes', use: 'Comparison on a normalised property.' },
    { operator: 'IN (…)', indexed: 'yes', use: 'Set membership. Cheaper than chained OR.' },
    { operator: "LIKE '%v%'", indexed: 'partial', use: 'Wildcard match. A leading % prevents index use.' },
    { operator: "ILIKE '%v%'", indexed: 'partial', use: 'Case-insensitive LIKE. Prefer over LOWER(f) LIKE …' },
    { operator: "MATCHES 'regex'", indexed: 'no', use: 'Regex. IMATCHES for case-insensitive.' },
    { operator: "TEXT SEARCH 'term'", indexed: 'yes', use: 'Full-text over the payload, via the Lucene index. The fast way to search raw log text.' },
    { operator: "INCIDR('10.0.0.0/8', ip)", indexed: 'yes', use: 'CIDR containment. Note the argument order: subnet first.' },
    { operator: 'BETWEEN a AND b', indexed: 'yes', use: 'Inclusive range.' },
    { operator: 'IS NULL / IS NOT NULL', indexed: 'partial', use: 'Essential for CEPs — an unconfigured CEP is null, not absent.' },
    { operator: '"Custom Property"', indexed: 'no', use: 'CEP reference. Double-quoted, case-sensitive, deployment-specific.' },
    { operator: 'GROUP BY … HAVING …', indexed: 'no', use: 'Aggregation. See the chunking prohibition before using it.' },
  ],

  cost: [
    { cost: 'cheap', construct: 'equality or IN on an indexed normalised property (sourceip, destinationport, qid)' },
    { cost: 'cheap', construct: "TEXT SEARCH 'term' — Lucene-indexed payload search" },
    { cost: 'medium', construct: "LIKE 'prefix%' — anchored, so partially index-assisted" },
    { cost: 'expensive', construct: "LIKE '%substring%' on a CEP — leading wildcard, no index, full scan" },
    { cost: 'expensive', construct: 'MATCHES / IMATCHES regex over any property' },
    { cost: 'expensive', construct: 'a function wrapping the filtered property, e.g. LOWER(f) = … or QIDNAME(qid) ILIKE …' },
    { cost: 'very expensive', construct: "UTF8(payload) LIKE '%…%' — decodes and scans every payload; use TEXT SEARCH instead" },
    { cost: 'very expensive', construct: 'GROUP BY over a high-cardinality property such as a command line' },
  ],

  prohibitions: [
    {
      id: 'aql.no-join',
      severity: 'blocking',
      title: 'JOIN, UNION or a subquery in FROM',
      reason:
        'Ariel has no JOIN, no UNION and no subquery in FROM. This is the single hardest limit ' +
        'in the language, and it is why a multi-stage kill chain cannot be expressed as one AQL ' +
        'query the way it can in KQL or SPL.',
      fix:
        'Emit one query per phase and state the correlation logic as a written spec, or collapse ' +
        'the phases into a single pass with conditional aggregation over a shared key ' +
        '(GROUP BY sourceip with SUM(CASE …) per phase) — subject to the chunking rule below.',
      pattern: '\\b(INNER\\s+JOIN|LEFT\\s+JOIN|RIGHT\\s+JOIN|OUTER\\s+JOIN|FULL\\s+JOIN|JOIN|UNION(\\s+ALL)?)\\b|FROM\\s*\\(',
      flags: 'i',
    },
    {
      id: 'aql.time-bound-in-query',
      severity: 'blocking',
      title: 'Time bound written into the query',
      reason:
        'The hunt backend appends its own START/STOP from the request date range before ' +
        'submitting. A query that already carries LAST n HOURS or START/STOP ends up with two ' +
        'time clauses — either a parse failure, or a range that silently contradicts the one the ' +
        'analyst asked for.',
      fix:
        'Remove the time clause and let the pipeline supply it. If you are writing AQL to paste ' +
        'straight into the QRadar console instead, add the bound yourself and re-validate with ' +
        'submission_context="standalone".',
      pattern: '\\b(LAST\\s+\\d+\\s+(MINUTE|HOUR|DAY|WEEK|MONTH)S?|START\\s+(\\d{10,}|\'|")|STOP\\s+(\\d{10,}|\'|"))',
      flags: 'i',
    },
    {
      id: 'aql.domain-id-in-query',
      severity: 'blocking',
      title: 'domainId written into the query',
      reason:
        'The hunt backend injects domainId for tenant isolation. A hand-written domainId ' +
        'predicate is ANDed with the injected one, so if the two disagree the query returns zero ' +
        'rows — which is indistinguishable from "no malicious activity found".',
      fix: 'Remove it. Tenant scoping is not the query author\'s job in this pipeline.',
      pattern: '\\bdomainid\\s*(=|IN|!=)',
      flags: 'i',
    },
    {
      id: 'aql.aggregation-with-chunking',
      severity: 'warning',
      title: 'Aggregation, which the pipeline may compute per chunk',
      reason:
        'The hunt backend splits a range longer than 7 days into one query per day and ' +
        'concatenates the result sets. Each chunk therefore aggregates only its own day, and ' +
        'what comes back is a stack of daily partial aggregates rather than one total. A COUNT ' +
        'of 400 over a month can arrive as thirty rows of ~13 that nothing re-adds. There is no ' +
        'error and no warning in the output — the CSV simply means something other than what it ' +
        'appears to.',
      fix:
        'Keep the hunt range at 7 days or less so the query runs as a single chunk, or return ' +
        'raw events and aggregate downstream. If you keep the aggregation, say plainly in the ' +
        'hypothesis that the result is per-day and must be summed.',
      pattern: '\\b(GROUP\\s+BY|COUNT\\s*\\(|SUM\\s*\\(|AVG\\s*\\(|UNIQUECOUNT\\s*\\(|STDDEV\\s*\\(|MEDIAN\\s*\\()',
      flags: 'i',
    },
    {
      id: 'aql.no-select',
      severity: 'blocking',
      title: 'No SELECT … FROM',
      reason:
        'Ariel requires an explicit SELECT and FROM. A bare filter expression, or a pipeline ' +
        'written in KQL or SPL style, is not AQL.',
      fix: 'Write SELECT <properties> FROM events WHERE <predicates>.',
      pattern: '\\bSELECT\\b[\\s\\S]*\\bFROM\\s+(events|flows)\\b',
      flags: 'i',
      invert: true,
    },
    {
      id: 'aql.pipeline-syntax',
      severity: 'blocking',
      title: 'Pipeline syntax from another language',
      reason:
        'A leading pipe, or | stats / | where / | project / | summarize / | table, is SPL or ' +
        'KQL. Ariel has no pipeline operator.',
      fix: 'Express the filter in WHERE and the aggregation in GROUP BY.',
      pattern: '\\|\\s*(stats|where|eval|table|project|summarize|extend|search|rename|sort|dedup|groupBy)\\b',
      flags: 'i',
    },
    {
      id: 'aql.select-star',
      severity: 'warning',
      title: 'SELECT *',
      reason:
        'SELECT * returns every normalised property plus the full payload for every matching ' +
        'row. In the hunt pipeline that goes straight into a CSV, so a broad query produces a ' +
        'file that is large, slow to transfer and awkward to read.',
      fix: 'Name the properties the hypothesis actually needs.',
      pattern: 'SELECT\\s+\\*',
      flags: 'i',
    },
    {
      id: 'aql.payload-like',
      severity: 'warning',
      title: 'LIKE over the decoded payload',
      reason:
        'UTF8(payload) LIKE \'%…%\' decodes and scans every payload in range. TEXT SEARCH uses ' +
        'the Lucene index and answers the same question far more cheaply.',
      fix: "Use TEXT SEARCH 'term'. Keep UTF8(payload) in the SELECT list if you want to see it.",
      pattern: 'UTF8\\s*\\(\\s*payload\\s*\\)\\s+I?LIKE',
      flags: 'i',
    },
    {
      id: 'aql.wrong-regex-operator',
      severity: 'blocking',
      title: 'Non-Ariel regex operator',
      reason: 'Ariel spells regex matching MATCHES (or IMATCHES). REGEXP, RLIKE and ~ are not valid.',
      fix: "Use field MATCHES 'pattern', or IMATCHES for case-insensitive.",
      pattern: '\\b(REGEXP|RLIKE)\\b|[^!<>]~\\s*[\'"]',
      flags: 'i',
    },
    {
      id: 'aql.lower-on-filtered-property',
      severity: 'warning',
      title: 'LOWER() around the property being filtered',
      reason:
        'Wrapping the property in a function prevents index use, so the predicate becomes a ' +
        'full scan. ILIKE does the same job and stays index-assisted.',
      fix: "Replace LOWER(f) LIKE '%v%' with f ILIKE '%v%'.",
      pattern: 'LOWER\\s*\\([^)]+\\)\\s*(=|LIKE|IN)',
      flags: 'i',
    },
    {
      id: 'aql.no-limit',
      severity: 'warning',
      title: 'No LIMIT',
      reason:
        'An unbounded hunt query can return millions of rows into a CSV. The pipeline will not ' +
        'stop it.',
      fix: 'Add LIMIT with a number the hypothesis can actually be assessed from.',
      pattern: '\\bLIMIT\\s+\\d+',
      flags: 'i',
      invert: true,
    },
  ],

  examples: [
    {
      shape: 'process_creation',
      title: 'Encoded PowerShell execution',
      query:
        'SELECT starttime, sourceip, username,\n' +
        '       "Process Name", "Process CommandLine", "Parent Process Name"\n' +
        'FROM events\n' +
        'WHERE "Process Name" ILIKE \'%powershell.exe\'\n' +
        '  AND ("Process CommandLine" ILIKE \'%-enc %\'\n' +
        '    OR "Process CommandLine" ILIKE \'%-encodedcommand%\')\n' +
        'ORDER BY starttime DESC\n' +
        'LIMIT 1000',
      notes:
        'No time clause: the pipeline supplies START/STOP. The three quoted names are Custom ' +
        'Event Properties and are the part of this query most likely to be wrong — confirm them ' +
        'against the target deployment\'s property list before trusting a zero-row result.',
    },
    {
      shape: 'process_creation',
      title: 'Parent-child anomaly, aggregated — read the caveat',
      query:
        'SELECT sourceip, username, "Parent Process Name", "Process Name",\n' +
        '       COUNT(*) AS executions\n' +
        'FROM events\n' +
        'WHERE "Parent Process Name" ILIKE \'%winword.exe\'\n' +
        '  AND "Process Name" ILIKE \'%cmd.exe\'\n' +
        'GROUP BY sourceip, username, "Parent Process Name", "Process Name"\n' +
        'ORDER BY executions DESC\n' +
        'LIMIT 200',
      notes:
        'Correct only for a hunt range of 7 days or less. Beyond that the backend chunks daily ' +
        'and `executions` becomes a per-day count, with one row per day per host and nothing ' +
        'summing them.',
    },
    {
      shape: 'network_connection',
      title: 'Outbound connection to a non-internal address on an odd port',
      query:
        'SELECT starttime, sourceip, destinationip, destinationport, username, "Process Name"\n' +
        'FROM events\n' +
        'WHERE destinationport IN (4444, 5555, 8443)\n' +
        "  AND NOT INCIDR('10.0.0.0/8', destinationip)\n" +
        "  AND NOT INCIDR('192.168.0.0/16', destinationip)\n" +
        'ORDER BY starttime DESC\n' +
        'LIMIT 1000',
      notes:
        'destinationip and destinationport are normalised, so this is the rare endpoint-adjacent ' +
        'query that is portable across deployments. Note INCIDR takes the subnet first.',
    },
    {
      shape: 'dns_query',
      title: 'DNS lookups to low-reputation TLDs',
      query:
        'SELECT starttime, sourceip, username, "DNS Query Name"\n' +
        'FROM events\n' +
        'WHERE "DNS Query Name" IMATCHES \'.*\\.(top|xyz|zip|mov|click)$\'\n' +
        'ORDER BY starttime DESC\n' +
        'LIMIT 1000',
      notes:
        'IMATCHES is a full scan. If the DNS log source is high volume, narrow it first with a ' +
        'logsourceid or category predicate, which is indexed.',
    },
    {
      shape: 'file_event',
      title: 'Executable written to a user-writable path',
      query:
        'SELECT starttime, sourceip, username, "File Path", "Process Name"\n' +
        'FROM events\n' +
        'WHERE ("File Path" ILIKE \'%\\\\Users\\\\Public\\\\%\'\n' +
        '    OR "File Path" ILIKE \'%\\\\AppData\\\\Local\\\\Temp\\\\%\')\n' +
        '  AND "File Path" ILIKE \'%.exe\'\n' +
        'ORDER BY starttime DESC\n' +
        'LIMIT 1000',
    },
    {
      shape: 'authentication',
      title: 'Failed logons across many accounts from one source',
      query:
        'SELECT sourceip, QIDNAME(qid) AS event_name,\n' +
        '       UNIQUECOUNT(username) AS accounts_tried, COUNT(*) AS attempts\n' +
        'FROM events\n' +
        'WHERE category = 3117\n' +
        '  AND username IS NOT NULL\n' +
        'GROUP BY sourceip, event_name\n' +
        'HAVING accounts_tried > 10\n' +
        'ORDER BY accounts_tried DESC\n' +
        'LIMIT 100',
      notes:
        'category is a normalised QRadar classification, so it survives across deployments where ' +
        'a raw Windows event ID would not — but confirm the number against the target ' +
        'installation rather than trusting it here. Aggregated, so the 7-day chunking caveat ' +
        'applies.',
    },
    {
      shape: 'registry_event',
      title: 'Run-key persistence',
      query:
        'SELECT starttime, sourceip, username,\n' +
        '       "Registry Key Path", "Registry Value Name", "Registry Value Data", "Process Name"\n' +
        'FROM events\n' +
        'WHERE "Registry Key Path" ILIKE \'%\\\\CurrentVersion\\\\Run%\'\n' +
        'ORDER BY starttime DESC\n' +
        'LIMIT 1000',
    },
    {
      shape: 'process_creation',
      title: 'Payload search when no CEP is configured',
      query:
        'SELECT starttime, sourceip, username, LOGSOURCENAME(logsourceid) AS log_source,\n' +
        '       UTF8(payload) AS raw_event\n' +
        'FROM events\n' +
        "WHERE TEXT SEARCH 'vssadmin'\n" +
        'ORDER BY starttime DESC\n' +
        'LIMIT 500',
      notes:
        'The fallback worth knowing. When a deployment has not extracted the property you need, ' +
        'TEXT SEARCH over the raw payload is index-backed and finds the events anyway — you just ' +
        'cannot filter or group on the value. Far better than a CEP guess that returns nothing.',
    },
  ],

  notes: [
    'No JOIN, no UNION, no subquery in FROM. Correlation across event shapes happens outside ' +
      'the query or through conditional aggregation in one pass.',
    'Custom Event Properties are double-quoted and case-sensitive, and their names are chosen ' +
      'per deployment. Every quoted name in a generated query is an assumption about the target ' +
      'installation, not a fact about QRadar.',
    'An unconfigured CEP is null rather than an error, so the wrong property name yields zero ' +
      'rows and no diagnostic. Treat a zero-row AQL result as unproven, not as clean.',
    'Do not write a time bound or a domainId in the hunt pipeline — the backend injects both.',
    'Aggregation is only correct for hunt ranges of 7 days or less, because longer ranges are ' +
      'chunked daily and the result sets are concatenated rather than re-aggregated.',
    'Ariel has no documented comment syntax. Explanation belongs in the hypothesis text ' +
      'alongside the query, not inside it.',
    'TEXT SEARCH is index-backed and is the right tool for raw log text. UTF8(payload) LIKE is ' +
      'the same question asked in the most expensive way available.',
    'QIDs are assigned by the installed DSM, so a qid filter is portable only within one ' +
      'deployment. The normalised `category` is the more portable classification.',
  ],
};
