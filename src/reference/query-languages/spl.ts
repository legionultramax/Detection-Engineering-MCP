// Search Processing Language — Splunk.
//
// Pipeline structure, the command cost model and several anti-patterns follow
// the analysis in .claude/skills/spl-optimizer/SKILL.md (Apache-2.0, Michael
// Haag), vendored in this repository. Content here is written independently;
// that skill is cited as prior art. See .claude/skills/NOTICE.md.

import type { LanguageSpec } from './types.js';

export const SPL_SPEC: LanguageSpec = {
  id: 'spl',
  name: 'Search Processing Language',
  engine: 'Splunk Enterprise / Splunk Cloud',
  confidence: 'confirmed',
  authority: 'https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/',

  dataModel:
    'Three phases. Input selects data by index, sourcetype or accelerated data model — terms ' +
    'placed before the first pipe hit the index and are effectively free. Search (map) filters ' +
    'and transforms per event. Reporting (reduce) aggregates. Everything before the first pipe ' +
    'is the cheapest filter available, so put selective terms there.\n\n' +
    'Detections in the Splunk ESCU corpus are written against CIM data models and queried with ' +
    'tstats over accelerated summaries. Fields are model-qualified: Processes.process_name, ' +
    'Registry.registry_path, Filesystem.file_path. The dominant shape is ' +
    '| tstats ... from datamodel=Endpoint.Processes where ... by ... .',

  operators: [
    { operator: 'field=value (before first pipe)', indexed: 'yes', use: 'Index-time term match. Cheapest filter available.' },
    { operator: 'field=value*', indexed: 'yes', use: 'Trailing wildcard still uses the index.' },
    { operator: 'field=*value', indexed: 'no', use: 'Leading wildcard defeats bloom filters. Avoid.' },
    { operator: 'IN (a, b, c)', indexed: 'yes', use: 'Set membership; clearer than chained OR.' },
    { operator: 'where field="x"', indexed: 'no', use: 'Search-time, post-index. Use for computed comparisons.' },
    { operator: 'rex', indexed: 'no', use: 'Regex field extraction. Expensive; extract only what you use.' },
    { operator: 'like()', indexed: 'no', use: 'SQL-style pattern inside where.' },
  ],

  cost: [
    { cost: 'cheap', construct: 'tstats over an accelerated data model' },
    { cost: 'cheap', construct: 'inline terms before the first pipe (index, sourcetype, field=value)' },
    { cost: 'cheap', construct: 'where, fields, rename, eval — streaming, per event' },
    { cost: 'medium', construct: 'stats, chart, timechart', note: 'aggregation, but parallelisable' },
    { cost: 'expensive', construct: 'join, append, transaction', note: 'memory-heavy and serialised' },
    { cost: 'expensive', construct: 'rex over a high-volume sourcetype' },
    { cost: 'very expensive', construct: 'map, nested subsearches', note: 'sequential execution' },
    { cost: 'very expensive', construct: 'leading-wildcard match', note: 'defeats the index entirely' },
  ],

  prohibitions: [
    {
      id: 'spl.external-macro',
      severity: 'blocking',
      title: 'Macro that ships outside the rules repository',
      reason:
        'drop_dm_object_name, globedistance and get_asset live in Splunk_SA_CIM or Enterprise ' +
        'Security, not in the detection content. On a Splunk without those apps the search fails ' +
        'at the backtick. drop_dm_object_name is not cosmetic — it strips the data-model prefix ' +
        'from field names, so removing it also changes every downstream field reference.',
      fix:
        'Either confirm the target Splunk has Splunk_SA_CIM installed, or rename the fields ' +
        'explicitly with | rename "Processes.process_name" as process_name.',
      pattern: '`\\s*(drop_dm_object_name|globedistance|get_asset)\\s*\\(?',
    },
    {
      id: 'spl.no-source-anchor',
      severity: 'blocking',
      title: 'No index, sourcetype or data model',
      reason:
        'Without an anchor the search runs against every index the user can read, which is the ' +
        'most expensive thing a Splunk search can do.',
      fix: 'Add index=..., sourcetype=..., or query a data model with tstats.',
      pattern: '\\b(index\\s*=|sourcetype\\s*=|source\\s*=|from\\s+datamodel|datamodel\\s*=|eventtype\\s*=)',
      invert: true,
    },
    {
      id: 'spl.unresolved-macro',
      severity: 'warning',
      title: 'ESCU macro reference',
      reason:
        'ESCU searches average roughly four macros each. Datasource macros such as `sysmon` and ' +
        '`wineventlog_security` are defined per environment, and _filter macros are per-detection ' +
        'whitelist hooks that are empty by default. A macro that is not defined in the target ' +
        'Splunk stops the search.',
      fix:
        'Expand the macro inline for portability, or confirm the target has the ESCU app and the ' +
        'macro defined for its own indexes.',
      pattern: '`[a-zA-Z0-9_]+(\\([^)]*\\))?`',
    },
    {
      id: 'spl.leading-wildcard',
      severity: 'warning',
      title: 'Leading wildcard',
      reason: 'A leading * defeats bloom filters and forces a scan.',
      fix: 'Anchor the term, use a trailing wildcard, or match on a raw substring with where.',
      pattern: '=\\s*"?\\*[A-Za-z0-9_]',
    },
    {
      id: 'spl.transaction',
      severity: 'warning',
      title: 'transaction used for grouping',
      reason: 'transaction is memory-bound and does not distribute. stats does the same job cheaply.',
      fix: 'Use stats ... by <correlation field>, with earliest/latest for timing.',
      pattern: '\\|\\s*transaction\\b',
    },
    {
      id: 'spl.eval-before-where',
      severity: 'warning',
      title: 'eval before where',
      reason: 'Computing a field for every event and then discarding most of them inverts the cheap order.',
      fix: 'Filter first, compute second.',
      pattern: '\\|\\s*eval\\b[\\s\\S]{0,200}?\\|\\s*where\\b',
    },
  ],

  examples: [
    {
      shape: 'process_creation',
      title: 'Encoded PowerShell via the Endpoint data model',
      query:
        '| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime\n' +
        '    from datamodel=Endpoint.Processes\n' +
        '    where Processes.process_name IN ("powershell.exe", "pwsh.exe")\n' +
        '      AND Processes.process="*-enc*"\n' +
        '    by Processes.dest Processes.user Processes.process Processes.parent_process_name\n' +
        '| rename "Processes.*" as *',
      notes:
        'tstats over the accelerated model is the cheapest shape. The rename replaces ' +
        '`drop_dm_object_name` so the search does not depend on Splunk_SA_CIM.',
    },
    {
      shape: 'process_creation',
      title: 'LOLBAS download via certutil, raw events',
      query:
        'index=* sourcetype=WinEventLog:Security EventCode=4688\n' +
        '  (New_Process_Name="*\\\\certutil.exe" AND Process_Command_Line="*urlcache*")\n' +
        '| stats count min(_time) as firstTime max(_time) as lastTime\n' +
        '    by ComputerName, Account_Name, Process_Command_Line',
      notes: 'Terms before the first pipe are index-time and free; trailing wildcards keep the index.',
    },
    {
      shape: 'registry_event',
      title: 'Run key persistence',
      query:
        '| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime\n' +
        '    from datamodel=Endpoint.Registry\n' +
        '    where Registry.registry_path="*\\\\CurrentVersion\\\\Run*"\n' +
        '    by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data\n' +
        '| rename "Registry.*" as *',
    },
    {
      shape: 'network_connection',
      title: 'Scripting host making outbound connections',
      query:
        '| tstats summariesonly=true count\n' +
        '    from datamodel=Network_Traffic.All_Traffic\n' +
        '    where All_Traffic.app IN ("wscript.exe", "cscript.exe", "mshta.exe")\n' +
        '    by All_Traffic.src All_Traffic.dest All_Traffic.dest_port\n' +
        '| rename "All_Traffic.*" as *',
    },
    {
      shape: 'authentication',
      title: 'Failed logons across many accounts from one source',
      query:
        'index=* sourcetype=WinEventLog:Security EventCode=4625\n' +
        '| bin _time span=10m\n' +
        '| stats dc(Account_Name) as accounts, count as attempts by _time, Source_Network_Address\n' +
        '| where accounts > 10',
    },
    {
      shape: 'file_event',
      title: 'Executable written to a user-writable path',
      query:
        '| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime\n' +
        '    from datamodel=Endpoint.Filesystem\n' +
        '    where Filesystem.file_name="*.exe"\n' +
        '      AND (Filesystem.file_path="*\\\\Users\\\\Public\\\\*" OR Filesystem.file_path="*\\\\Temp\\\\*")\n' +
        '    by Filesystem.dest Filesystem.file_name Filesystem.file_path\n' +
        '| rename "Filesystem.*" as *',
    },
  ],

  notes: [
    'summariesonly=true queries only accelerated summaries. It is fast and it silently misses ' +
      'data outside the acceleration window — a correctness trade, not just a performance one.',
    'CIM field names are model-qualified until renamed. Processes.process is the full command ' +
      'line; Processes.process_name is the executable. Confusing the two is a common silent miss.',
    'ESCU searches end with a `<detection_name>_filter` macro. It is a whitelist hook, empty by ' +
      'default, and safe to omit when porting a search elsewhere.',
    'Prefer | rename "Model.*" as * over `drop_dm_object_name` when the target Splunk may not ' +
      'have Splunk_SA_CIM.',
  ],
};
