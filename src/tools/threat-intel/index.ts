// Threat Intelligence Tools
// Integration with MITRE ATT&CK, CVE/NVD, CISA KEV, LOLBAS, abuse.ch, OTX, and vendor blogs
import { defineTool, ToolDefinition } from '../registry.js';

// Vendor threat intelligence tools (Phase 2)
import { vendorTools } from './vendors/index.js';
// Government & CERT tools (Phase 3)
import { governmentTools } from './government/index.js';
// Specialized research tools (Phase 4)
import { researchTools } from './research/index.js';
// Correlation Engine (Phase 5)
import { correlationTools } from './correlation/index.js';
// Exploit Intelligence tools (Phase 6)
import { exploitTools } from './exploit/index.js';
// Community & Open Research tools (Phase 7)
import { communityTools } from './community/index.js';

// abuse.ch integrations
import {
  urlhausLookupURL,
  urlhausLookupHost,
  urlhausLookupTag,
  threatfoxSearchIOC,
  threatfoxSearchFamily,
  threatfoxSearchTag,
  threatfoxGetRecentIOCs,
  bazaarLookupHash,
  bazaarSearchFamily,
  bazaarSearchTag,
  bazaarGetRecentSamples,
  bazaarGetImphashSiblings,
} from './abusech.js';

// OTX integrations
import {
  otxPivotIP,
  otxPivotDomain,
  otxPivotHash,
  otxPivotURL,
  otxSearchActor,
  otxGetPulseIOCs,
  otxSubscribedPulsesFeed,
} from './otx.js';

// Unified pivot engine
import { pivotExpandIOCs } from './pivot.js';
import { 
  getMitreTechnique, searchMitreTechniques, cacheMitreTechnique,
  getCVE, cacheCVE, 
  getKEV, getAllKEV, isInKEV, cacheKEV,
  getLOLBAS, searchLOLBAS, cacheLOLBAS,
} from '../../db/threat-intel.js';
import { runQuery, runStatement } from '../../db/connection.js';

// Built-in MITRE ATT&CK data (subset of most common techniques)
const MITRE_TECHNIQUES: Record<string, { name: string; tactics: string[]; description: string }> = {
  'T1059': { name: 'Command and Scripting Interpreter', tactics: ['Execution'], description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.' },
  'T1059.001': { name: 'PowerShell', tactics: ['Execution'], description: 'Adversaries may abuse PowerShell commands and scripts for execution.' },
  'T1059.003': { name: 'Windows Command Shell', tactics: ['Execution'], description: 'Adversaries may abuse the Windows command shell (cmd) for execution.' },
  'T1055': { name: 'Process Injection', tactics: ['Defense Evasion', 'Privilege Escalation'], description: 'Adversaries may inject code into processes to evade detection and elevate privileges.' },
  'T1003': { name: 'OS Credential Dumping', tactics: ['Credential Access'], description: 'Adversaries may dump credentials to obtain account login and credential material.' },
  'T1003.001': { name: 'LSASS Memory', tactics: ['Credential Access'], description: 'Adversaries may attempt to access credential material stored in LSASS process memory.' },
  'T1547': { name: 'Boot or Logon Autostart Execution', tactics: ['Persistence', 'Privilege Escalation'], description: 'Adversaries may configure system settings to automatically execute programs during boot or logon.' },
  'T1547.001': { name: 'Registry Run Keys / Startup Folder', tactics: ['Persistence', 'Privilege Escalation'], description: 'Adversaries may achieve persistence by adding programs to the Registry Run keys or Startup folder.' },
  'T1566': { name: 'Phishing', tactics: ['Initial Access'], description: 'Adversaries may send phishing messages to gain access to victim systems.' },
  'T1566.001': { name: 'Spearphishing Attachment', tactics: ['Initial Access'], description: 'Adversaries may send spearphishing emails with a malicious attachment.' },
  'T1021': { name: 'Remote Services', tactics: ['Lateral Movement'], description: 'Adversaries may use valid accounts to log into a service for remote access.' },
  'T1021.001': { name: 'Remote Desktop Protocol', tactics: ['Lateral Movement'], description: 'Adversaries may use RDP to remotely access systems.' },
  'T1486': { name: 'Data Encrypted for Impact', tactics: ['Impact'], description: 'Adversaries may encrypt data on target systems to interrupt availability.' },
  'T1490': { name: 'Inhibit System Recovery', tactics: ['Impact'], description: 'Adversaries may delete or remove data that could be used to recover.' },
  'T1078': { name: 'Valid Accounts', tactics: ['Defense Evasion', 'Persistence', 'Privilege Escalation', 'Initial Access'], description: 'Adversaries may obtain and abuse credentials of existing accounts.' },
  'T1190': { name: 'Exploit Public-Facing Application', tactics: ['Initial Access'], description: 'Adversaries may exploit vulnerabilities in internet-facing software.' },
  'T1027': { name: 'Obfuscated Files or Information', tactics: ['Defense Evasion'], description: 'Adversaries may make payloads difficult to discover or analyze.' },
  'T1070': { name: 'Indicator Removal', tactics: ['Defense Evasion'], description: 'Adversaries may delete or modify artifacts to remove evidence.' },
  'T1053': { name: 'Scheduled Task/Job', tactics: ['Execution', 'Persistence', 'Privilege Escalation'], description: 'Adversaries may abuse task scheduling to execute malicious code.' },
  'T1218': { name: 'System Binary Proxy Execution', tactics: ['Defense Evasion'], description: 'Adversaries may bypass process and signature-based defenses by proxying execution.' },
};

// Built-in LOLBAS data
const LOLBAS_DATA: Record<string, { description: string; commands: string[]; detection: string; techniques: string[] }> = {
  'certutil.exe': {
    description: 'Certificate utility that can download files, encode/decode data, and more.',
    commands: ['certutil -urlcache -split -f [URL] [output]', 'certutil -encode [input] [output]', 'certutil -decode [input] [output]'],
    detection: 'Monitor for certutil.exe with network connections or encoding operations',
    techniques: ['T1140', 'T1105', 'T1027'],
  },
  'mshta.exe': {
    description: 'Microsoft HTML Application Host - executes HTA files.',
    commands: ['mshta.exe [URL]', 'mshta vbscript:Execute("code")'],
    detection: 'Monitor mshta.exe for unusual child processes or network connections',
    techniques: ['T1218.005'],
  },
  'regsvr32.exe': {
    description: 'Command-line utility to register/unregister OLE controls.',
    commands: ['regsvr32 /s /n /u /i:[URL] scrobj.dll'],
    detection: 'Monitor regsvr32.exe for script execution or network connections',
    techniques: ['T1218.010'],
  },
  'rundll32.exe': {
    description: 'Loads and runs DLLs.',
    commands: ['rundll32.exe [DLL],EntryPoint', 'rundll32.exe javascript:"code"'],
    detection: 'Monitor rundll32.exe for unusual DLL loads or command-line arguments',
    techniques: ['T1218.011'],
  },
  'powershell.exe': {
    description: 'Windows scripting shell with access to .NET framework.',
    commands: ['powershell -ep bypass -c [command]', 'powershell -encodedCommand [base64]'],
    detection: 'Monitor PowerShell script block logging and command-line arguments',
    techniques: ['T1059.001'],
  },
  'wmic.exe': {
    description: 'Windows Management Instrumentation command-line interface.',
    commands: ['wmic process call create [command]', 'wmic /node:[target] process call create [command]'],
    detection: 'Monitor wmic.exe for process creation and remote execution',
    techniques: ['T1047'],
  },
  'bitsadmin.exe': {
    description: 'Command-line tool for managing BITS jobs.',
    commands: ['bitsadmin /transfer [name] [URL] [output]'],
    detection: 'Monitor bitsadmin.exe for download operations',
    techniques: ['T1105', 'T1197'],
  },
  'cscript.exe': {
    description: 'Windows Script Host for running VBScript/JScript.',
    commands: ['cscript.exe [script.vbs]'],
    detection: 'Monitor cscript.exe for script execution and child processes',
    techniques: ['T1059.005'],
  },
};

// Lookup MITRE ATT&CK technique
const lookupMitreTechnique = defineTool({
  name: 'lookup_mitre_technique',
  description: 'Look up details about a MITRE ATT&CK technique by ID (e.g., T1059, T1059.001)',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: { type: 'string', description: 'MITRE technique ID (e.g., T1059)' },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const { technique_id } = args as { technique_id: string };
    const normalizedId = technique_id.toUpperCase();
    
    // Check cache first
    let technique = getMitreTechnique(normalizedId);
    
    if (!technique) {
      // Check built-in data
      const builtIn = MITRE_TECHNIQUES[normalizedId];
      if (builtIn) {
        technique = {
          id: normalizedId,
          name: builtIn.name,
          description: builtIn.description,
          tactic_names: builtIn.tactics,
          url: `https://attack.mitre.org/techniques/${normalizedId.replace('.', '/')}/`,
        };
        // Cache it
        cacheMitreTechnique(technique);
      }
    }
    
    if (!technique) {
      return {
        error: 'Technique not found',
        suggestion: `Try searching for techniques with search_mitre_techniques`,
        url: `https://attack.mitre.org/techniques/${normalizedId.replace('.', '/')}/`,
      };
    }
    
    return {
      id: technique.id,
      name: technique.name,
      description: technique.description,
      tactics: technique.tactic_names,
      url: technique.url,
      is_subtechnique: technique.is_subtechnique,
    };
  },
});

// Search MITRE techniques
const searchMitre = defineTool({
  name: 'search_mitre_techniques',
  description: 'Search MITRE ATT&CK techniques by keyword',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search keyword (e.g., "powershell", "credential")' },
    },
    required: ['query'],
  },
  handler: async (args) => {
    const { query } = args as { query: string };
    
    // Search built-in data
    const results = Object.entries(MITRE_TECHNIQUES)
      .filter(([id, data]) => 
        id.toLowerCase().includes(query.toLowerCase()) ||
        data.name.toLowerCase().includes(query.toLowerCase()) ||
        data.description.toLowerCase().includes(query.toLowerCase())
      )
      .map(([id, data]) => ({
        id,
        name: data.name,
        tactics: data.tactics,
      }));
    
    return {
      query,
      count: results.length,
      techniques: results,
    };
  },
});

// Lookup LOLBAS binary
const lookupLolbas = defineTool({
  name: 'lookup_lolbas',
  description: 'Look up a Living Off The Land Binary (LOLBAS) by name for abuse techniques',
  inputSchema: {
    type: 'object',
    properties: {
      binary: { type: 'string', description: 'Binary name (e.g., certutil.exe, mshta.exe)' },
    },
    required: ['binary'],
  },
  handler: async (args) => {
    const { binary } = args as { binary: string };
    const normalizedName = binary.toLowerCase();
    
    // Check cache first
    let entry = getLOLBAS(normalizedName);
    
    if (!entry) {
      // Check built-in data
      const builtIn = LOLBAS_DATA[normalizedName];
      if (builtIn) {
        entry = {
          name: normalizedName,
          description: builtIn.description,
          commands: builtIn.commands,
          detection: builtIn.detection,
          mitre_techniques: builtIn.techniques,
        };
        cacheLOLBAS(entry);
      }
    }
    
    if (!entry) {
      return {
        error: 'Binary not found in LOLBAS database',
        available: Object.keys(LOLBAS_DATA),
      };
    }
    
    return {
      binary: entry.name,
      description: entry.description,
      abuse_commands: entry.commands,
      detection_guidance: entry.detection,
      mitre_techniques: entry.mitre_techniques,
      reference: `https://lolbas-project.github.io/#/${entry.name.replace('.exe', '')}`,
    };
  },
});

// List all LOLBAS binaries
const listLolbas = defineTool({
  name: 'list_lolbas',
  description: 'List all known LOLBAS (Living Off The Land Binaries) with their primary abuse type',
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    return {
      count: Object.keys(LOLBAS_DATA).length,
      binaries: Object.entries(LOLBAS_DATA).map(([name, data]) => ({
        name,
        description: data.description.substring(0, 100),
        techniques: data.techniques,
      })),
      reference: 'https://lolbas-project.github.io/',
    };
  },
});

// Check CISA KEV (Known Exploited Vulnerabilities)
const checkCisaKev = defineTool({
  name: 'check_cisa_kev',
  description: 'Check if a CVE is in CISA Known Exploited Vulnerabilities catalog',
  inputSchema: {
    type: 'object',
    properties: {
      cve_id: { type: 'string', description: 'CVE ID (e.g., CVE-2021-44228)' },
    },
    required: ['cve_id'],
  },
  handler: async (args) => {
    const { cve_id } = args as { cve_id: string };
    const normalizedCve = cve_id.toUpperCase();
    
    const inKev = isInKEV(normalizedCve);
    const kevEntry = getKEV(normalizedCve);
    
    if (kevEntry) {
      return {
        cve: normalizedCve,
        in_kev: true,
        vendor: kevEntry.vendor_project,
        product: kevEntry.product,
        vulnerability: kevEntry.vulnerability_name,
        date_added: kevEntry.date_added,
        description: kevEntry.short_description,
        required_action: kevEntry.required_action,
        due_date: kevEntry.due_date,
        ransomware_use: kevEntry.known_ransomware_campaign,
      };
    }
    
    return {
      cve: normalizedCve,
      in_kev: false,
      note: 'CVE not found in CISA KEV. This does not mean it is not exploited, just not in the catalog.',
      kev_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    };
  },
});

// Get threat profile summary
const getThreatProfile = defineTool({
  name: 'get_threat_profile',
  description: 'Get a summary threat profile for common attack scenarios',
  inputSchema: {
    type: 'object',
    properties: {
      profile: { 
        type: 'string', 
        description: 'Profile type: ransomware, apt, insider, web-attack, supply-chain' 
      },
    },
    required: ['profile'],
  },
  handler: async (args) => {
    const { profile } = args as { profile: string };
    
    const profiles: Record<string, { 
      description: string; 
      techniques: string[]; 
      indicators: string[];
      defenses: string[];
    }> = {
      'ransomware': {
        description: 'Modern ransomware attack chain including initial access, lateral movement, and encryption',
        techniques: ['T1566', 'T1059', 'T1021', 'T1003', 'T1486', 'T1490', 'T1489'],
        indicators: ['Unusual process execution', 'Mass file modifications', 'Shadow copy deletion', 'Ransom notes'],
        defenses: ['Email filtering', 'Endpoint detection', 'Backup strategy', 'Network segmentation'],
      },
      'apt': {
        description: 'Advanced Persistent Threat with long-term access and data exfiltration goals',
        techniques: ['T1566.001', 'T1059.001', 'T1547.001', 'T1055', 'T1003', 'T1021', 'T1041'],
        indicators: ['Scheduled tasks persistence', 'Living-off-the-land', 'Encoded commands', 'C2 beaconing'],
        defenses: ['Zero trust architecture', 'DLP', 'Threat hunting', 'User awareness'],
      },
      'insider': {
        description: 'Malicious insider or compromised account abuse',
        techniques: ['T1078', 'T1005', 'T1530', 'T1567', 'T1070'],
        indicators: ['Off-hours access', 'Large data transfers', 'Privilege abuse', 'Policy violations'],
        defenses: ['UEBA', 'Access controls', 'DLP', 'Audit logging'],
      },
      'web-attack': {
        description: 'Web application attacks including injection and exploitation',
        techniques: ['T1190', 'T1505.003', 'T1059', 'T1105'],
        indicators: ['Web shell activity', 'Unusual web server processes', 'SQL injection patterns'],
        defenses: ['WAF', 'Input validation', 'Patch management', 'Web monitoring'],
      },
      'supply-chain': {
        description: 'Supply chain compromise targeting software or update mechanisms',
        techniques: ['T1195', 'T1195.002', 'T1059', 'T1547'],
        indicators: ['Unexpected software behavior', 'Unusual network connections', 'Code signing anomalies'],
        defenses: ['Vendor assessment', 'Software integrity', 'Network monitoring', 'Zero trust'],
      },
    };
    
    const p = profiles[profile.toLowerCase()];
    if (!p) {
      return {
        error: `Unknown profile: ${profile}`,
        available: Object.keys(profiles),
      };
    }
    
    return {
      profile,
      description: p.description,
      key_techniques: p.techniques,
      common_indicators: p.indicators,
      recommended_defenses: p.defenses,
    };
  },
});

// Analyze IOC type
const analyzeIoc = defineTool({
  name: 'analyze_ioc',
  description: 'Identify the type of an Indicator of Compromise and provide analysis guidance',
  inputSchema: {
    type: 'object',
    properties: {
      ioc: { type: 'string', description: 'The IOC value to analyze (hash, IP, domain, URL, etc.)' },
    },
    required: ['ioc'],
  },
  handler: async (args) => {
    const { ioc } = args as { ioc: string };
    
    let iocType = 'unknown';
    let analysis: Record<string, unknown> = {};
    
    // MD5
    if (/^[a-fA-F0-9]{32}$/.test(ioc)) {
      iocType = 'md5';
      analysis = {
        hash_type: 'MD5',
        lookup_sources: ['VirusTotal', 'MalwareBazaar', 'Hybrid Analysis'],
        note: 'MD5 is weak; check for SHA256 equivalent',
      };
    }
    // SHA1
    else if (/^[a-fA-F0-9]{40}$/.test(ioc)) {
      iocType = 'sha1';
      analysis = {
        hash_type: 'SHA1',
        lookup_sources: ['VirusTotal', 'MalwareBazaar'],
      };
    }
    // SHA256
    else if (/^[a-fA-F0-9]{64}$/.test(ioc)) {
      iocType = 'sha256';
      analysis = {
        hash_type: 'SHA256',
        lookup_sources: ['VirusTotal', 'MalwareBazaar', 'Hybrid Analysis', 'Any.Run'],
      };
    }
    // IPv4
    else if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) {
      iocType = 'ipv4';
      analysis = {
        ip_type: 'IPv4',
        lookup_sources: ['AbuseIPDB', 'Shodan', 'VirusTotal', 'GreyNoise'],
        checks: ['Geolocation', 'ASN', 'Reputation', 'Open ports'],
      };
    }
    // Domain
    else if (/^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(ioc)) {
      iocType = 'domain';
      analysis = {
        domain_type: 'FQDN',
        lookup_sources: ['VirusTotal', 'URLhaus', 'PhishTank', 'DomainTools'],
        checks: ['WHOIS', 'DNS records', 'Reputation', 'Historical data'],
      };
    }
    // URL
    else if (/^https?:\/\//.test(ioc)) {
      iocType = 'url';
      analysis = {
        url_type: 'URL',
        lookup_sources: ['VirusTotal', 'URLhaus', 'PhishTank', 'URLScan.io'],
        warning: 'Do not visit unknown URLs directly',
      };
    }
    // Email
    else if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ioc)) {
      iocType = 'email';
      analysis = {
        email_type: 'Email Address',
        lookup_sources: ['HaveIBeenPwned', 'EmailRep', 'Hunter.io'],
      };
    }
    
    return {
      ioc,
      type: iocType,
      analysis,
      common_actions: [
        'Search in SIEM for related activity',
        'Check threat intelligence platforms',
        'Add to blocklist if confirmed malicious',
        'Document findings',
      ],
    };
  },
});

// ---------------------------------------------------------------------------
// abuse.ch MCP tool definitions
// ---------------------------------------------------------------------------

const urlhausLookupURLTool = defineTool({
  name: 'urlhaus_lookup_url',
  description: 'Look up a URL in URLhaus to check if it distributes malware. Returns payload hashes, imphashes, and malware tags. Generates pivot suggestions for chained analysis.',
  inputSchema: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'Full URL to look up (e.g. http://evil.com/payload.exe)' },
    },
    required: ['url'],
  },
  handler: async (args) => {
    const { url } = args as { url: string };
    return urlhausLookupURL(url);
  },
});

const urlhausLookupHostTool = defineTool({
  name: 'urlhaus_lookup_host',
  description: 'Find all malicious URLs hosted on an IP address or domain in URLhaus.',
  inputSchema: {
    type: 'object',
    properties: {
      host: { type: 'string', description: 'IP address or domain name (e.g. 192.0.2.1 or evil.com)' },
    },
    required: ['host'],
  },
  handler: async (args) => {
    const { host } = args as { host: string };
    return urlhausLookupHost(host);
  },
});

const urlhausLookupTagTool = defineTool({
  name: 'urlhaus_lookup_tag',
  description: 'Search URLhaus for all malicious URLs associated with a malware tag (e.g. "Emotet", "qakbot", "cobalt-strike").',
  inputSchema: {
    type: 'object',
    properties: {
      tag: { type: 'string', description: 'Malware tag to search (e.g. "Emotet", "AgentTesla")' },
    },
    required: ['tag'],
  },
  handler: async (args) => {
    const { tag } = args as { tag: string };
    return urlhausLookupTag(tag);
  },
});

const threatfoxSearchIOCTool = defineTool({
  name: 'threatfox_search_ioc',
  description: 'Search ThreatFox for any IOC type (IP:port, domain, URL, MD5, SHA256). Returns confidence scores and malware family attribution.',
  inputSchema: {
    type: 'object',
    properties: {
      ioc: { type: 'string', description: 'IOC value to search (IP:port, domain, URL, hash)' },
    },
    required: ['ioc'],
  },
  handler: async (args) => {
    const { ioc } = args as { ioc: string };
    return threatfoxSearchIOC(ioc);
  },
});

const threatfoxSearchFamilyTool = defineTool({
  name: 'threatfox_search_family',
  description: 'Get all IOCs in ThreatFox for a specific malware family (e.g. "Cobalt Strike", "Sliver", "AgentTesla"). Returns C2 IPs, domains, and payload hashes.',
  inputSchema: {
    type: 'object',
    properties: {
      family: { type: 'string', description: 'Malware family name (e.g. "Cobalt Strike")' },
    },
    required: ['family'],
  },
  handler: async (args) => {
    const { family } = args as { family: string };
    return threatfoxSearchFamily(family);
  },
});

const threatfoxSearchTagTool = defineTool({
  name: 'threatfox_search_tag',
  description: 'Search ThreatFox IOCs by tag (e.g. "c2", "loader", "rat", "ransomware").',
  inputSchema: {
    type: 'object',
    properties: {
      tag: { type: 'string', description: 'ThreatFox tag to search' },
    },
    required: ['tag'],
  },
  handler: async (args) => {
    const { tag } = args as { tag: string };
    return threatfoxSearchTag(tag);
  },
});

const threatfoxRecentIOCsTool = defineTool({
  name: 'threatfox_get_recent_iocs',
  description: 'Retrieve the ThreatFox recent IOC feed for ambient threat intel sync. Returns all IOCs submitted in the last 1, 7, or 30 days.',
  inputSchema: {
    type: 'object',
    properties: {
      days: {
        type: 'number',
        enum: [1, 7, 30],
        description: 'Lookback window in days: 1, 7, or 30',
      },
    },
    required: ['days'],
  },
  handler: async (args) => {
    const { days } = args as { days: 1 | 7 | 30 };
    return threatfoxGetRecentIOCs(days);
  },
});

const bazaarLookupHashTool = defineTool({
  name: 'bazaar_lookup_hash',
  description: 'Look up a malware sample in MalwareBazaar by SHA256, MD5, or SHA1. Returns imphash, malware family, tags, and vendor detections.',
  inputSchema: {
    type: 'object',
    properties: {
      hash: { type: 'string', description: 'File hash (SHA256, MD5, or SHA1)' },
    },
    required: ['hash'],
  },
  handler: async (args) => {
    const { hash } = args as { hash: string };
    return bazaarLookupHash(hash);
  },
});

const bazaarSearchFamilyTool = defineTool({
  name: 'bazaar_search_family',
  description: 'Search MalwareBazaar for all samples belonging to a malware family. Returns hashes, imphashes, and file metadata.',
  inputSchema: {
    type: 'object',
    properties: {
      family: { type: 'string', description: 'Malware family / signature name (e.g. "Emotet")' },
      limit: { type: 'number', description: 'Max results (default 50, max 100)' },
    },
    required: ['family'],
  },
  handler: async (args) => {
    const { family, limit } = args as { family: string; limit?: number };
    return bazaarSearchFamily(family, limit);
  },
});

const bazaarSearchTagTool = defineTool({
  name: 'bazaar_search_tag',
  description: 'Search MalwareBazaar for malware samples by tag (e.g. "keylogger", "ransomware", "loader").',
  inputSchema: {
    type: 'object',
    properties: {
      tag: { type: 'string', description: 'MalwareBazaar tag to search' },
      limit: { type: 'number', description: 'Max results (default 50)' },
    },
    required: ['tag'],
  },
  handler: async (args) => {
    const { tag, limit } = args as { tag: string; limit?: number };
    return bazaarSearchTag(tag, limit);
  },
});

const bazaarRecentSamplesTool = defineTool({
  name: 'bazaar_get_recent_samples',
  description: 'Retrieve the most recently submitted samples from MalwareBazaar for ambient threat intel sync.',
  inputSchema: {
    type: 'object',
    properties: {
      limit: { type: 'number', description: 'Number of samples to retrieve (1–100, default 25)' },
    },
    required: ['limit'],
  },
  handler: async (args) => {
    const { limit } = args as { limit: number };
    return bazaarGetRecentSamples(limit);
  },
});

const bazaarImphashSiblingsTool = defineTool({
  name: 'bazaar_get_imphash_siblings',
  description: 'ELITE PIVOT: Find all MalwareBazaar samples sharing the same PE import hash (imphash). Reveals variants compiled from the same codebase — catches threat actors who forget to randomise their builds.',
  inputSchema: {
    type: 'object',
    properties: {
      imphash: { type: 'string', description: 'PE import hash (imphash) to pivot on' },
      limit: { type: 'number', description: 'Max results (default 50)' },
    },
    required: ['imphash'],
  },
  handler: async (args) => {
    const { imphash, limit } = args as { imphash: string; limit?: number };
    return bazaarGetImphashSiblings(imphash, limit);
  },
});

// ---------------------------------------------------------------------------
// OTX MCP tool definitions
// ---------------------------------------------------------------------------

const otxPivotIPTool = defineTool({
  name: 'otx_pivot_ip',
  description: 'Full OTX enrichment for an IP address. Returns pulse count, reputation, country, ASN, attributed actors, malware families, MITRE techniques, and pivot suggestions.',
  inputSchema: {
    type: 'object',
    properties: {
      ip: { type: 'string', description: 'IPv4 or IPv6 address to enrich' },
    },
    required: ['ip'],
  },
  handler: async (args) => {
    const { ip } = args as { ip: string };
    return otxPivotIP(ip);
  },
});

const otxPivotDomainTool = defineTool({
  name: 'otx_pivot_domain',
  description: 'OTX enrichment for a domain. Returns pulse context, passive DNS history (historical IPs), attributed actors, and malware families.',
  inputSchema: {
    type: 'object',
    properties: {
      domain: { type: 'string', description: 'Domain or hostname to enrich' },
    },
    required: ['domain'],
  },
  handler: async (args) => {
    const { domain } = args as { domain: string };
    return otxPivotDomain(domain);
  },
});

const otxPivotHashTool = defineTool({
  name: 'otx_pivot_hash',
  description: 'OTX enrichment for a file hash. Returns malware families, MITRE techniques, actor attribution, and imphash for sibling sample pivoting.',
  inputSchema: {
    type: 'object',
    properties: {
      hash: { type: 'string', description: 'File hash (SHA256, MD5, or SHA1)' },
    },
    required: ['hash'],
  },
  handler: async (args) => {
    const { hash } = args as { hash: string };
    return otxPivotHash(hash);
  },
});

const otxPivotURLTool = defineTool({
  name: 'otx_pivot_url',
  description: 'OTX enrichment for a URL. Returns pulse context, attributed actors, malware families, and suggests domain pivot.',
  inputSchema: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'URL to enrich (must start with http:// or https://)' },
    },
    required: ['url'],
  },
  handler: async (args) => {
    const { url } = args as { url: string };
    return otxPivotURL(url);
  },
});

const otxSearchActorTool = defineTool({
  name: 'otx_search_actor',
  description: 'ELITE: Search all OTX pulses attributed to a threat actor. Deduplicates IOCs across pulses and returns the actor\'s full infrastructure — C2 IPs, domains, hashes, MITRE techniques.',
  inputSchema: {
    type: 'object',
    properties: {
      actor_name: { type: 'string', description: 'Threat actor name (e.g. "APT29", "Lazarus Group", "Volt Typhoon")' },
    },
    required: ['actor_name'],
  },
  handler: async (args) => {
    const { actor_name } = args as { actor_name: string };
    return otxSearchActor(actor_name);
  },
});

const otxGetPulseIOCsTool = defineTool({
  name: 'otx_get_pulse_iocs',
  description: 'Fetch all indicators from a specific OTX pulse ID. Paginates automatically.',
  inputSchema: {
    type: 'object',
    properties: {
      pulse_id: { type: 'string', description: 'OTX pulse ID (24-character hex string)' },
    },
    required: ['pulse_id'],
  },
  handler: async (args) => {
    const { pulse_id } = args as { pulse_id: string };
    return otxGetPulseIOCs(pulse_id);
  },
});

const otxSubscribedFeedTool = defineTool({
  name: 'otx_subscribed_feed',
  description: 'Fetch OTX subscribed pulses modified since a given timestamp. Use for scheduled ambient threat intel sync.',
  inputSchema: {
    type: 'object',
    properties: {
      since_iso: {
        type: 'string',
        description: 'ISO-8601 timestamp (e.g. "2025-02-01T00:00:00Z"). Returns pulses modified after this time.',
      },
    },
    required: ['since_iso'],
  },
  handler: async (args) => {
    const { since_iso } = args as { since_iso: string };
    const since = new Date(since_iso);
    if (isNaN(since.getTime())) {
      return { error: true, message: `Invalid ISO timestamp: ${since_iso}` };
    }
    return otxSubscribedPulsesFeed(since);
  },
});

// ---------------------------------------------------------------------------
// Unified pivot MCP tool
// ---------------------------------------------------------------------------

const pivotExpandIOCsTool = defineTool({
  name: 'pivot_expand_iocs',
  description: 'ELITE: Unified IOC pivot engine. Takes IOCs from an advisory, fans out to abuse.ch + OTX in parallel, auto-follows imphash/actor/family pivots one level deep, deduplicates everything, and returns confidence-ranked discovered IOCs. Feed this the output of ingest_advisory.',
  inputSchema: {
    type: 'object',
    properties: {
      iocs: {
        type: 'array',
        description: 'Input IOCs to pivot on',
        items: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['ip', 'domain', 'hash', 'url'] },
            value: { type: 'string' },
          },
          required: ['type', 'value'],
        },
      },
      actor: { type: 'string', description: 'Optional: threat actor name to include in pivot' },
      malware_family: { type: 'string', description: 'Optional: malware family name to include in pivot' },
    },
    required: ['iocs'],
  },
  handler: async (args) => {
    const { iocs, actor, malware_family } = args as {
      iocs: Array<{ type: 'ip' | 'domain' | 'hash' | 'url'; value: string }>;
      actor?: string;
      malware_family?: string;
    };
    return pivotExpandIOCs({ iocs, actor, malware_family });
  },
});

// ---------------------------------------------------------------------------
// Export all tools
// ---------------------------------------------------------------------------

export const threatIntelTools: ToolDefinition[] = [
  // Existing tools
  lookupMitreTechnique,
  searchMitre,
  lookupLolbas,
  listLolbas,
  checkCisaKev,
  getThreatProfile,
  analyzeIoc,
  // URLhaus
  urlhausLookupURLTool,
  urlhausLookupHostTool,
  urlhausLookupTagTool,
  // ThreatFox
  threatfoxSearchIOCTool,
  threatfoxSearchFamilyTool,
  threatfoxSearchTagTool,
  threatfoxRecentIOCsTool,
  // MalwareBazaar
  bazaarLookupHashTool,
  bazaarSearchFamilyTool,
  bazaarSearchTagTool,
  bazaarRecentSamplesTool,
  bazaarImphashSiblingsTool,
  // OTX
  otxPivotIPTool,
  otxPivotDomainTool,
  otxPivotHashTool,
  otxPivotURLTool,
  otxSearchActorTool,
  otxGetPulseIOCsTool,
  otxSubscribedFeedTool,
  // Unified engine
  pivotExpandIOCsTool,
  // Vendor threat intelligence (Phase 2 — 12 tools: 2 per vendor × 6 vendors)
  ...vendorTools,
  // Government & CERT sources (Phase 3 — 10 tools)
  ...governmentTools,
  // Specialized research sources (Phase 4 — 20 tools: 2 per source × 10 sources)
  ...researchTools,
  // Correlation Engine (Phase 5 — 5 tools)
  ...correlationTools,
  // Exploit Intelligence (Phase 6 — 10 tools: 3 JSON API + 7 RSS blogs)
  ...exploitTools,
  // Community & Open Research (Phase 7 — 9 tools)
  ...communityTools,
];

export const threatIntelToolCount = threatIntelTools.length;
