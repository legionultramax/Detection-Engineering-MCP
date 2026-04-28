/**
 * Shared utilities for vendor threat intelligence tools.
 *
 * Exports:
 *   - VENDOR_ENDPOINTS       — config map for 18 vendors
 *   - parseRSS()             — RSS 2.0 + Atom feed parser (pure regex, no deps)
 *   - extractArticleBody()   — HTML article body extractor
 *   - extractIntelMarkers()  — MITRE T-IDs, CVEs, IOCs, actors, malware
 *   - scoreVendorConfidence()— confidence scorer
 *   - fetchWithRetry()       — HTTP client with 429 back-off
 *   - makeVendorErr()        — structured error helper
 *   - createVendorSearchTool()— factory: {vendor}_search_reports
 *   - createVendorFetchTool() — factory: {vendor}_fetch_report
 *
 * TTLs (exported for external use):
 *   VENDOR_BLOG_TTL = 14 400 s (4 h)
 *   GOVT_FEED_TTL   =  3 600 s (1 h)
 *   LIVE_FEED_TTL   =  1 800 s (30 min)
 *   CVE_FEED_TTL    =  7 200 s (2 h)
 */

import { defineTool, type ToolDefinition } from '../../registry.js';
import { getCached, setCached } from '../cache.js';
import type { PivotSuggestion } from '../types.js';
import type {
  VendorConfig,
  VendorIntelResult,
  RSSItem,
  IntelMarkers,
  VendorReport,
  VendorSearchResult,
  VendorReportAnalysis,
  ExtractedTechnique,
  ExtractedIOC,
  ConfidenceInput,
} from './types.js';

// ─── TTLs ────────────────────────────────────────────────────────────────────

export const VENDOR_BLOG_TTL = 14_400; // 4 hours
export const GOVT_FEED_TTL   =  3_600; // 1 hour
export const LIVE_FEED_TTL   =  1_800; // 30 minutes
export const CVE_FEED_TTL    =  7_200; // 2 hours

// ─── HTTP ────────────────────────────────────────────────────────────────────

const BASE_HEADERS: Record<string, string> = {
  'User-Agent': 'HarrisHawkEye-MCP/1.0 (ThreatIntel; +https://github.com/harris-hawkeye)',
  'Accept': 'application/rss+xml, application/atom+xml, text/xml, text/html, */*',
};

// ─── VENDOR ENDPOINTS (18 vendors) ───────────────────────────────────────────

export const VENDOR_ENDPOINTS: Record<string, VendorConfig> = {
  mandiant: {
    key: 'mandiant',
    name: 'Mandiant / Google Threat Intelligence',
    search: 'https://cloud.google.com/blog/topics/threat-intelligence/',
    rss: 'https://cloud.google.com/blog/topics/threat-intelligence/rss',
  },
  microsoft: {
    key: 'microsoft',
    name: 'Microsoft Threat Intelligence',
    search: 'https://www.microsoft.com/en-us/security/blog/',
    rss: 'https://www.microsoft.com/en-us/security/blog/feed/',
  },
  crowdstrike: {
    key: 'crowdstrike',
    name: 'CrowdStrike Intelligence',
    search: 'https://www.crowdstrike.com/en-us/blog/',
    rss: 'https://www.crowdstrike.com/en-us/blog/feed/',
  },
  unit42: {
    key: 'unit42',
    name: 'Palo Alto Unit 42',
    search: 'https://unit42.paloaltonetworks.com/',
    rss: 'https://unit42.paloaltonetworks.com/feed/',
  },
  talos: {
    key: 'talos',
    name: 'Cisco Talos',
    search: 'https://blog.talosintelligence.com/',
    rss: 'https://blog.talosintelligence.com/rss/',
  },
  kaspersky: {
    key: 'kaspersky',
    name: 'Kaspersky Securelist',
    search: 'https://securelist.com/',
    rss: 'https://securelist.com/feed/',
  },
  eset: {
    key: 'eset',
    name: 'ESET WeLiveSecurity',
    search: 'https://www.welivesecurity.com/',
    rss: 'https://www.welivesecurity.com/feed/',
  },
  trendmicro: {
    key: 'trendmicro',
    name: 'Trend Micro Research',
    search: 'https://www.trendmicro.com/en_us/research.html',
    rss: 'https://feeds.trendmicro.com/TrendMicroResearch',
  },
  sentinelone: {
    key: 'sentinelone',
    name: 'SentinelOne Labs',
    search: 'https://www.sentinelone.com/labs/',
    rss: 'https://www.sentinelone.com/labs/feed/',
  },
  symantec: {
    key: 'symantec',
    name: 'Symantec Threat Hunter',
    search: 'https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence',
    rss: 'https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/rss',
  },
  sophos: {
    key: 'sophos',
    name: 'Sophos X-Ops',
    search: 'https://news.sophos.com/en-us/category/threat-research/',
    rss: 'https://news.sophos.com/en-us/category/threat-research/feed/',
  },
  secureworks: {
    key: 'secureworks',
    name: 'Secureworks CTU',
    search: 'https://www.secureworks.com/research',
    rss: 'https://www.secureworks.com/rss?feed=research',
  },
  checkpoint: {
    key: 'checkpoint',
    name: 'Check Point Research',
    search: 'https://research.checkpoint.com/',
    rss: 'https://research.checkpoint.com/feed/',
  },
  proofpoint: {
    key: 'proofpoint',
    name: 'Proofpoint Threat Insight',
    search: 'https://www.proofpoint.com/us/blog/threat-insight',
    rss: 'https://www.proofpoint.com/us/rss.xml',
  },
  trellix: {
    key: 'trellix',
    name: 'Trellix Research',
    search: 'https://www.trellix.com/blogs/research/',
    rss: 'https://www.trellix.com/blogs/research/rss/',
  },
  fortinet: {
    key: 'fortinet',
    name: 'FortiGuard Labs',
    search: 'https://www.fortinet.com/blog/threat-research',
    rss: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml',
  },
  cybereason: {
    key: 'cybereason',
    name: 'Cybereason Nocturnus',
    search: 'https://www.cybereason.com/blog/research',
    rss: 'https://www.cybereason.com/blog/rss.xml',
  },
  elastic: {
    key: 'elastic',
    name: 'Elastic Security Labs',
    search: 'https://www.elastic.co/security-labs',
    rss: 'https://www.elastic.co/security-labs/rss/feed.xml',
  },
  // ── Community tier (fallback when priority vendors return empty) ────────────
  bleeping: {
    key: 'bleeping',
    name: 'BleepingComputer',
    search: 'https://www.bleepingcomputer.com/news/security/',
    rss: 'https://www.bleepingcomputer.com/feed/',
  },
  sans_isc: {
    key: 'sans_isc',
    name: 'SANS ISC',
    search: 'https://isc.sans.edu/',
    rss: 'https://isc.sans.edu/rssfeed.xml',
  },
  malwarebytes: {
    key: 'malwarebytes',
    name: 'Malwarebytes Labs',
    search: 'https://www.malwarebytes.com/blog/',
    rss: 'https://www.malwarebytes.com/blog/feed/',
  },
};

// ─── KNOWN INTEL SEEDS (static; populated from MITRE DB at runtime) ───────────

/** Well-known threat actor names and aliases for keyword matching */
const KNOWN_ACTORS: readonly string[] = [
  'APT28', 'Fancy Bear', 'Sofacy', 'Pawn Storm', 'Strontium', 'Forest Blizzard',
  'APT29', 'Cozy Bear', 'Midnight Blizzard', 'Nobelium', 'The Dukes', 'Yttrium',
  'APT38', 'Lazarus', 'Lazarus Group', 'Hidden Cobra', 'Guardians of Peace',
  'APT41', 'Double Dragon', 'Winnti', 'Barium', 'Wicked Panda',
  'APT10', 'Stone Panda', 'MenuPass', 'Cicada',
  'APT27', 'Emissary Panda', 'LuckyMouse', 'Iron Tiger',
  'APT33', 'Elfin', 'Magnallium', 'Refined Kitten',
  'APT34', 'OilRig', 'Cobalt Gypsy', 'Helix Kitten',
  'APT35', 'Charming Kitten', 'TA453', 'Phosphorus',
  'FIN7', 'Carbanak', 'Navigator Group',
  'FIN11', 'TA505',
  'MuddyWater', 'TA450', 'Mercury', 'Static Kitten',
  'Turla', 'Snake', 'Uroburos', 'Venomous Bear', 'Waterbug',
  'Sandworm', 'Voodoo Bear', 'TeleBots', 'Iridium',
  'Volt Typhoon', 'Bronze Silhouette', 'KV Botnet',
  'Salt Typhoon', 'Earth Estries', 'FamousSparrow',
  'Scattered Spider', 'UNC3944', 'Starfraud', 'Octo Tempest',
  'BlackCat', 'ALPHV', 'Noberus',
  'LockBit',
  'Cl0p', 'TA505',
  'Vice Society',
  'REvil', 'Sodinokibi', 'GandCrab',
  'DarkSide', 'BlackMatter',
  'Conti',
  'Hive',
  'Quantum',
  'Play', 'PlayCrypt',
  '8Base',
  'Akira',
  'Medusa',
  'Royal',
  'Black Basta', 'BASTA',
  'Cuba ransomware',
  'TA571', 'TA577', 'TA578', 'TA558',
  'Earth Preta', 'Mustang Panda', 'TA416', 'RedDelta',
  'BRONZE BUTLER', 'Tick', 'RedBaldKnight',
  'Kimsuky', 'Thallium', 'Velvet Chollima',
  'Andariel', 'Silent Chollima',
  'BlueNoroff', 'Stardust Chollima',
  'UNC2452', 'UNC2891', 'UNC3886',
  'Dragonfly', 'Energetic Bear', 'Crouching Yeti', 'Berserk Bear',
  'Gamaredon', 'Primitive Bear', 'UAC-0010',
];

/** Well-known malware families for keyword matching */
const KNOWN_MALWARE: readonly string[] = [
  'Cobalt Strike', 'Mimikatz', 'Emotet', 'QakBot', 'Qbot', 'Qakbot',
  'TrickBot', 'BazarLoader', 'BazarBackdoor',
  'IcedID', 'Bokbot',
  'BumbleBee', 'SystemBC',
  'Sliver', 'Brute Ratel', 'Metasploit', 'PowerShell Empire',
  'AgentTesla', 'RedLine', 'RedLineStealer',
  'Raccoon', 'Raccoon Stealer',
  'Vidar', 'Lumma', 'Lumma Stealer',
  'AsyncRAT', 'NjRAT', 'QuasarRAT', 'RemCOS', 'XWorm',
  'SUNBURST', 'SUNSPOT', 'Teardrop', 'Raindrop',
  'GootLoader', 'GootKit',
  'SocGholish', 'FakeUpdates',
  'WannaCry', 'NotPetya', 'Petya',
  'BlackCat ransomware', 'ALPHV ransomware',
  'LockBit ransomware',
  'Cl0p ransomware',
  'Ryuk', 'Dharma', 'Phobos',
  'Conti ransomware',
  'DarkSide ransomware',
  'Hive ransomware',
  'Royal ransomware',
  'Akira ransomware',
  'Black Basta ransomware',
  'Play ransomware',
  'PlugX', 'ShadowPad',
  'Havoc', 'Nighthawk', 'Meterpreter',
  'NetWire', 'DarkComet',
  'Formbook', 'Snake malware',
  'Stuxnet', 'Flame', 'Duqu',
  'Industroyer', 'CrashOverride',
  'Triton', 'TRISIS',
  'AcidRain',
  'Pipedream', 'INCONTROLLER',
];

/** Common offensive security tools */
const KNOWN_TOOLS: readonly string[] = [
  'BloodHound', 'SharpHound', 'ADExplorer',
  'Impacket', 'PsExec',
  'CrackMapExec', 'Evil-WinRM',
  'Rubeus', 'Kerbrute',
  'Responder', 'Inveigh',
  'Nmap', 'Masscan',
  'RClone', 'MEGASync',
];

/** Industry keywords for sector attribution */
const KNOWN_INDUSTRIES: readonly string[] = [
  'healthcare', 'hospital', 'medical', 'pharmaceutical', 'pharma', 'biotech',
  'finance', 'financial', 'banking', 'bank', 'fintech', 'insurance',
  'energy', 'oil', 'gas', 'power grid', 'utilities', 'electric grid',
  'manufacturing', 'industrial', 'automotive', 'aerospace',
  'government', 'federal', 'public sector', 'defense', 'military',
  'education', 'university', 'academic',
  'retail', 'e-commerce',
  'technology', 'telecom', 'telecommunications',
  'media', 'entertainment',
  'transportation', 'logistics', 'aviation', 'maritime',
  'legal', 'law firm',
  'critical infrastructure', 'scada',
];

/** Region keywords for geographic attribution */
const KNOWN_REGIONS: readonly string[] = [
  'united states', 'north america',
  'europe', 'european union',
  'russia', 'russian federation',
  'china', 'prc',
  'north korea', 'dprk',
  'iran', 'iranian',
  'ukraine',
  'middle east', 'uae', 'saudi arabia',
  'asia pacific', 'southeast asia',
  'india',
  'australia',
  'united kingdom',
  'germany',
];

// ─── IOC PATTERNS ────────────────────────────────────────────────────────────

const MITRE_PATTERN    = /\bT\d{4}(?:\.\d{3})?\b/g;
const CVE_PATTERN      = /CVE-\d{4}-\d{4,}/gi;
const IPV4_PATTERN     = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV4_DEFANG      = /\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b/g;
const DOMAIN_DEFANG    = /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\][a-zA-Z]{2,}\b/g;
const SHA256_PATTERN   = /\b([a-fA-F0-9]{64})\b/g;
const SHA1_PATTERN     = /\b([a-fA-F0-9]{40})\b/g;
const MD5_PATTERN      = /\b([a-fA-F0-9]{32})\b/g;
const URL_DEFANG       = /hxxps?:\/\/[^\s<>"{}|\\^`]+/g;
const URL_LIVE         = /https?:\/\/[^\s<>"{}|\\^`[\]]{10,}/g;
const EMAIL_PATTERN    = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

// ─── FALSE POSITIVE FILTERS ──────────────────────────────────────────────────

const FP_DOMAINS: ReadonlySet<string> = new Set([
  'google.com', 'googleapis.com', 'googletagmanager.com', 'gstatic.com',
  'microsoft.com', 'microsoftonline.com', 'office365.com', 'office.com',
  'live.com', 'outlook.com', 'sharepoint.com', 'azure.com', 'azurewebsites.net',
  'github.com', 'githubusercontent.com', 'github.io',
  'twitter.com', 'x.com', 'linkedin.com', 'facebook.com',
  'youtube.com', 'instagram.com', 'tiktok.com',
  'cloudflare.com', 'cloudfront.net', 'fastly.net', 'akamai.com',
  'amazonaws.com', 'awsstatic.com', 's3.amazonaws.com',
  'dropbox.com', 'onedrive.com', 'box.com', 'icloud.com',
  'apple.com',
  'virustotal.com', 'hybrid-analysis.com',
  'example.com', 'example.org', 'test.com',
  'jquery.com', 'jquery.org',
  'w3.org', 'schema.org', 'openssl.org',
  'wikipedia.org', 'wikimedia.org',
  'wordpress.com', 'wordpress.org', 'wp.com',
  'adobe.com', 'adobe.io',
  'digicert.com', 'verisign.com', 'sectigo.com',
]);

const PRIVATE_IP_TESTS: ReadonlyArray<RegExp> = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^0\./,
  /^255\./,
  /^192\.0\.2\./,
  /^198\.51\.100\./,
  /^203\.0\.113\./,
];

// Lighter filter for defanged IPs — deliberately excludes 192.168.x.x since
// threat intel reports regularly reference internal C2 listener addresses in
// that range (e.g., lateral movement, internal proxy pivots).
const DEFANGED_PRIVATE_IP_TESTS: ReadonlyArray<RegExp> = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^127\./,
  /^169\.254\./,
  /^0\./,
  /^255\./,
  /^192\.0\.2\./,
  /^198\.51\.100\./,
  /^203\.0\.113\./,
];

// ─── SMALL HELPERS ───────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

/** Strip HTML tags and decode common entities */
export function stripHtml(raw: string): string {
  return raw
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&hellip;/g, '...')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

function normalizeDate(raw: string): string {
  if (!raw) return new Date().toISOString();
  const d = new Date(raw.trim());
  return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

/** Extract a text field from XML, CDATA-aware */
function extractXmlField(xml: string, field: string): string {
  const cdataRx = new RegExp(
    `<${field}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${field}>`,
    'i',
  );
  const cdata = cdataRx.exec(xml);
  if (cdata) return cdata[1];

  const plainRx = new RegExp(`<${field}[^>]*>([\\s\\S]*?)</${field}>`, 'i');
  const plain = plainRx.exec(xml);
  return plain ? plain[1] : '';
}

function isPrivateIP(ip: string): boolean {
  return PRIVATE_IP_TESTS.some(rx => rx.test(ip));
}

function isDefangedPrivateIP(ip: string): boolean {
  return DEFANGED_PRIVATE_IP_TESTS.some(rx => rx.test(ip));
}

/** Convert defanged notation back to normal: [.] → .  hxxp → http */
function refang(value: string): string {
  return value
    .replace(/\[\.\]/g, '.')
    .replace(/hxxp/gi, 'http');
}

function makeCacheKey(service: string, subtype: string, value: string): string {
  return `vendor:${service}:${subtype}:${value.toLowerCase().trim()}`;
}

// ─── RSS / ATOM PARSER ───────────────────────────────────────────────────────

export function parseRSS(xml: string): RSSItem[] {
  const items: RSSItem[] = [];
  const isAtom = /<feed\b/.test(xml) && xml.includes('www.w3.org/2005/Atom');
  const itemRx  = isAtom
    ? /<entry>([\s\S]*?)<\/entry>/g
    : /<item>([\s\S]*?)<\/item>/g;

  let m: RegExpExecArray | null;
  while ((m = itemRx.exec(xml)) !== null) {
    const block = m[1];

    const title       = extractXmlField(block, 'title');
    const description = extractXmlField(block, isAtom ? 'summary' : 'description');
    const content     = extractXmlField(block, 'content:encoded')
                     || extractXmlField(block, 'content');
    const pubDate     = extractXmlField(block, isAtom ? 'updated' : 'pubDate')
                     || extractXmlField(block, 'dc:date')
                     || extractXmlField(block, 'published');

    // Atom uses <link href="..."/>, RSS uses <link>URL</link>
    let link = '';
    if (isAtom) {
      const lm = /<link[^>]*href=["']([^"']+)["']/.exec(block);
      link = lm ? lm[1] : '';
    } else {
      link = extractXmlField(block, 'link').trim();
      if (!link) {
        const lm = /<link>([^<]+)<\/link>/.exec(block);
        link = lm ? lm[1].trim() : '';
      }
    }

    const catMatches = [...block.matchAll(/<category[^>]*>([^<]+)<\/category>/g)];
    const categories = catMatches.map(c => stripHtml(c[1].trim()));

    items.push({
      title:       stripHtml(title),
      link:        link,
      pubDate:     normalizeDate(pubDate),
      description: stripHtml(description),
      categories,
      content:     stripHtml(content || description),
    });
  }

  return items;
}

// ─── HTML ARTICLE EXTRACTOR ──────────────────────────────────────────────────

export function extractArticleBody(html: string): string {
  // Remove noise blocks before pattern matching
  const cleaned = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<nav[\s\S]*?<\/nav>/gi, '')
    .replace(/<footer[\s\S]*?<\/footer>/gi, '')
    .replace(/<header[\s\S]*?<\/header>/gi, '');

  // Priority 1: semantic <article> tag
  const articleM = /<article[^>]*>([\s\S]*?)<\/article>/i.exec(cleaned);
  if (articleM) return stripHtml(articleM[1]).replace(/\s{3,}/g, '\n\n').trim();

  // Priority 2: <main> tag
  const mainM = /<main[^>]*>([\s\S]*?)<\/main>/i.exec(cleaned);
  if (mainM) return stripHtml(mainM[1]).replace(/\s{3,}/g, '\n\n').trim();

  // Priority 3: common content div id/class names
  const contentM = /<div[^>]+(?:id|class)=["'][^"']*(?:post-content|entry-content|article-body|blog-content|content-body|article-content)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i.exec(cleaned);
  if (contentM) return stripHtml(contentM[1]).replace(/\s{3,}/g, '\n\n').trim();

  // Fallback: strip all HTML (capped at 60k chars to stay sane)
  return stripHtml(cleaned).replace(/\s{3,}/g, '\n').trim().substring(0, 60_000);
}

// ─── INTEL MARKER EXTRACTOR ──────────────────────────────────────────────────

export function extractIntelMarkers(text: string): IntelMarkers {
  const lower = text.toLowerCase();

  // MITRE T-IDs
  const techniques = [...new Set(text.match(MITRE_PATTERN) ?? [])];

  // CVEs — uppercase them for consistency
  const cves = [...new Set((text.match(CVE_PATTERN) ?? []).map(c => c.toUpperCase()))];

  // IPs — fanged (public only)
  const ipsRaw      = [...new Set((text.match(IPV4_PATTERN) ?? []).filter(ip => !isPrivateIP(ip)))];
  // IPs — defanged (lighter private-IP filter: 192.168.x.x is kept since threat
  // intel reports legitimately reference internal C2 listener addresses there)
  const ipsDefanged = [...new Set(
    (text.match(IPV4_DEFANG) ?? []).map(refang).filter(ip => !isDefangedPrivateIP(ip)),
  )];
  const allIPs = [...new Set([...ipsRaw, ...ipsDefanged])];

  // Domains — defanged only (fanged domains produce too many FPs in prose text)
  const domainsDefanged = [...new Set(
    (text.match(DOMAIN_DEFANG) ?? []).map(refang).filter(d => !FP_DOMAINS.has(d.toLowerCase())),
  )];

  // URLs — defanged (high confidence) and live (filtered)
  // Trim trailing punctuation that may be captured when brackets are in the match
  const urlsDefanged = [...new Set(
    (text.match(URL_DEFANG) ?? []).map(raw => refang(raw).replace(/[)>\].,;]+$/, '')),
  )];
  const urlsLive: string[] = [];
  for (const u of (text.match(URL_LIVE) ?? [])) {
    const cleaned = u.replace(/[)>\].,;]+$/, '');
    try {
      if (!FP_DOMAINS.has(new URL(cleaned).hostname.toLowerCase())) {
        urlsLive.push(cleaned);
      }
    } catch {
      // malformed URL — skip
    }
  }
  const uniqueURLsLive = [...new Set(urlsLive)].slice(0, 10);

  // Hashes — longest first to avoid SHA-256 being re-matched as MD5 fragment
  const sha256s = [...new Set(text.match(SHA256_PATTERN) ?? [])];
  const sha1s   = [...new Set((text.match(SHA1_PATTERN) ?? []).filter(h => !sha256s.includes(h)))];
  const md5s    = [...new Set((text.match(MD5_PATTERN) ?? []).filter(h => !sha256s.includes(h) && !sha1s.includes(h)))];

  // Emails (filter out image filenames accidentally matched)
  const emails = [...new Set(
    (text.match(EMAIL_PATTERN) ?? []).filter(e => !/\.(png|jpg|gif|svg|ico|webp)$/i.test(e)),
  )];

  // Build unified IOC list
  const iocs: IntelMarkers['iocs'] = [
    ...allIPs.map(v => ({ type: 'ip' as const, value: v })),
    ...domainsDefanged.map(v => ({ type: 'domain' as const, value: v })),
    ...urlsDefanged.map(v => ({ type: 'url' as const, value: v })),
    ...uniqueURLsLive.map(v => ({ type: 'url' as const, value: v })),
    ...sha256s.map(v => ({ type: 'sha256' as const, value: v })),
    ...sha1s.map(v => ({ type: 'sha1' as const, value: v })),
    ...md5s.map(v => ({ type: 'md5' as const, value: v })),
    ...emails.map(v => ({ type: 'email' as const, value: v })),
  ];

  // Actors — word-boundary keyword scan
  const actors = [...new Set(KNOWN_ACTORS.filter(actor => {
    const rx = new RegExp(`\\b${actor.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    return rx.test(text);
  }))];

  // Malware families
  const malware = [...new Set(KNOWN_MALWARE.filter(fam => {
    const rx = new RegExp(`\\b${fam.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    return rx.test(text);
  }))];

  // Tools
  const tools = [...new Set(KNOWN_TOOLS.filter(tool => {
    const rx = new RegExp(`\\b${tool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    return rx.test(text);
  }))];

  // Industries and regions (substring scan on lowercased text — acceptable for these)
  const industries = [...new Set(KNOWN_INDUSTRIES.filter(ind => lower.includes(ind)))];
  const regions    = [...new Set(KNOWN_REGIONS.filter(reg => lower.includes(reg)))];

  return { techniques, cves, actors, malware, tools, iocs, industries, regions };
}

// ─── CONFIDENCE SCORER ───────────────────────────────────────────────────────

export function scoreVendorConfidence(input: ConfidenceInput): 'high' | 'medium' | 'low' {
  let score = 0;
  if ((input.sources_consulted?.length ?? 0) >= 3) score += 3;
  if (input.mitre_confirmed)               score += 2;
  if ((input.vendor_count ?? 0) >= 2)      score += 2;
  if ((input.ioc_count ?? 0) > 0)          score += 1;
  if (input.cve_confirmed)                 score += 1;
  if (score >= 6) return 'high';
  if (score >= 3) return 'medium';
  return 'low';
}

// ─── ERROR HELPER ────────────────────────────────────────────────────────────

export function makeVendorErr(source: string, error: string): VendorIntelResult<never> {
  return {
    source,
    success: false,
    data: null,
    error,
    queried_at: new Date().toISOString(),
    pivot_suggestions: [],
  };
}

// ─── HTTP CLIENT WITH RETRY + 429 BACK-OFF ───────────────────────────────────

export async function fetchWithRetry(url: string, retries = 2): Promise<string> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, {
        headers: BASE_HEADERS,
        signal: AbortSignal.timeout(12_000),
      });
    } catch (err) {
      if (attempt < retries) {
        await sleep(1_500 * (attempt + 1));
        continue;
      }
      throw err;
    }

    if (res.status === 429) {
      const retryAfterHeader = res.headers.get('retry-after');
      const waitMs = retryAfterHeader ? Number(retryAfterHeader) * 1_000 : 3_000;
      if (attempt < retries) {
        await sleep(Math.max(waitMs, 2_000));
        continue;
      }
      throw new Error(`Rate-limited by ${url} after ${retries} retries`);
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} from ${url}`);
    }

    return res.text();
  }
  throw new Error(`Exhausted retries for ${url}`);
}

// ─── PIVOT SUGGESTION BUILDERS ───────────────────────────────────────────────

function buildSearchPivots(reports: VendorReport[], tool: string): PivotSuggestion[] {
  const suggestions: PivotSuggestion[] = [];
  const seen = new Set<string>();

  for (const report of reports) {
    for (const t of report.techniques_mentioned.slice(0, 3)) {
      if (!seen.has(t)) {
        seen.add(t);
        suggestions.push({
          type: 'technique',
          value: t,
          reason: `Technique referenced in: "${report.title}"`,
          source_tool: tool,
          confidence: 'medium',
        });
      }
    }
    for (const cve of report.cves_mentioned.slice(0, 2)) {
      if (!seen.has(cve)) {
        seen.add(cve);
        suggestions.push({
          type: 'cve',
          value: cve,
          reason: `CVE referenced in: "${report.title}"`,
          source_tool: tool,
          confidence: 'medium',
        });
      }
    }
    for (const actor of report.actors_mentioned.slice(0, 2)) {
      if (!seen.has(actor)) {
        seen.add(actor);
        suggestions.push({
          type: 'actor',
          value: actor,
          reason: `Actor mentioned in: "${report.title}"`,
          source_tool: tool,
          confidence: 'medium',
        });
      }
    }
  }

  return suggestions.slice(0, 12);
}

function buildReportPivots(markers: IntelMarkers, tool: string): PivotSuggestion[] {
  const suggestions: PivotSuggestion[] = [];

  for (const ioc of markers.iocs.slice(0, 6)) {
    const t = ioc.type as PivotSuggestion['type'];
    suggestions.push({
      type: t,
      value: ioc.value,
      reason: 'IOC extracted from vendor report',
      source_tool: tool,
      confidence: 'high',
    });
  }
  for (const t of markers.techniques.slice(0, 4)) {
    suggestions.push({
      type: 'technique',
      value: t,
      reason: 'MITRE technique extracted from report',
      source_tool: tool,
      confidence: 'medium',
    });
  }
  for (const cve of markers.cves.slice(0, 3)) {
    suggestions.push({
      type: 'cve',
      value: cve,
      reason: 'CVE referenced in vendor report',
      source_tool: tool,
      confidence: 'high',
    });
  }
  for (const actor of markers.actors.slice(0, 2)) {
    suggestions.push({
      type: 'actor',
      value: actor,
      reason: 'Threat actor named in report',
      source_tool: tool,
      confidence: 'medium',
    });
  }

  return suggestions.slice(0, 15);
}

// ─── VENDOR TOOL FACTORIES ───────────────────────────────────────────────────

/**
 * Creates a `{vendor.key}_search_reports` tool that fetches the vendor's RSS
 * feed, filters by keyword, extracts intel markers, and caches results.
 */
export function createVendorSearchTool(config: VendorConfig): ToolDefinition {
  const toolName = `${config.key}_search_reports`;

  return defineTool({
    name: toolName,
    description:
      `Search ${config.name} threat intelligence blog for reports matching a ` +
      `keyword, actor name, malware family, or CVE. Automatically extracts MITRE ` +
      `techniques, CVEs, and IOC references from matching articles.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: {
          type: 'string',
          description: 'Search keyword: actor name, malware family, CVE ID, or technique name',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default: 10, max: 30)',
        },
      },
      required: ['query'],
    },
    handler: async (args) => {
      const { query, limit = 10 } = args as { query: string; limit?: number };
      const cap      = Math.min(Math.max(1, Math.floor(limit)), 30);
      const cacheKey = makeCacheKey(config.key, `search:${cap}`, query);

      const cached = getCached<VendorIntelResult<VendorSearchResult>>(cacheKey);
      if (cached !== null) return { ...cached, queried_at: new Date().toISOString() };

      try {
        const xml     = await fetchWithRetry(config.rss);
        const items   = parseRSS(xml);
        const qLow    = query.toLowerCase();

        const filtered = items.filter(item => {
          const hay = `${item.title} ${item.description} ${item.content}`.toLowerCase();
          return hay.includes(qLow);
        }).slice(0, cap);

        const reports: VendorReport[] = filtered.map(item => {
          const text = `${item.title} ${item.description} ${item.content}`;
          const m    = extractIntelMarkers(text);
          return {
            title:               item.title,
            url:                 item.link,
            published:           item.pubDate,
            snippet:             item.description.substring(0, 300),
            tags:                item.categories,
            actors_mentioned:    m.actors,
            techniques_mentioned:m.techniques,
            cves_mentioned:      m.cves,
            malware_mentioned:   m.malware,
          };
        });

        const result: VendorIntelResult<VendorSearchResult> = {
          source: config.key,
          success: true,
          data: { reports, total_found: reports.length, source: config.name, query },
          queried_at: new Date().toISOString(),
          pivot_suggestions: buildSearchPivots(reports, toolName),
        };

        setCached(cacheKey, result, VENDOR_BLOG_TTL);
        return result;
      } catch (err) {
        return makeVendorErr(config.key, err instanceof Error ? err.message : String(err));
      }
    },
  });
}

/**
 * Creates a `{vendor.key}_fetch_report` tool that fetches a specific URL,
 * extracts the article body, and returns structured TTP intelligence.
 */
export function createVendorFetchTool(config: VendorConfig): ToolDefinition {
  const toolName = `${config.key}_fetch_report`;

  return defineTool({
    name: toolName,
    description:
      `Fetch a specific ${config.name} report URL and extract structured TTP intelligence: ` +
      `actors, MITRE techniques, CVEs, IOCs, tools used, target sectors, and regions.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        url: {
          type: 'string',
          description: 'Full URL of the vendor report to fetch and analyze',
        },
      },
      required: ['url'],
    },
    handler: async (args) => {
      const { url } = args as { url: string };
      const cacheKey = makeCacheKey(config.key, 'report', url);

      const cached = getCached<VendorIntelResult<VendorReportAnalysis>>(cacheKey);
      if (cached !== null) return { ...cached, queried_at: new Date().toISOString() };

      try {
        const html    = await fetchWithRetry(url);
        const body    = extractArticleBody(html);
        const markers = extractIntelMarkers(body);

        // Title from <title> tag
        const titleM = /<title[^>]*>([^<]+)<\/title>/i.exec(html);
        const title  = titleM ? stripHtml(titleM[1]).trim() : url;

        // Published date from meta tags
        const dateM = /<meta[^>]*(?:name|property)=["'](?:article:published_time|date|pubdate|og:published_time)[^"']*["'][^>]*content=["']([^"']+)["']/i.exec(html);
        const published = normalizeDate(dateM?.[1] ?? '');

        // Build technique objects with context snippets
        const sentences = body.split(/(?<=[.!?])\s+/);
        const techniques: ExtractedTechnique[] = markers.techniques.map(id => {
          const ctx = sentences.find(s => s.includes(id))?.trim() ?? '';
          return { id, name: '', context: ctx.substring(0, 200) };
        });

        const confidence = scoreVendorConfidence({
          sources_consulted: [config.key],
          mitre_confirmed:   markers.techniques.length > 0,
          vendor_count:      1,
          ioc_count:         markers.iocs.length,
          cve_confirmed:     markers.cves.length > 0,
        });

        const validIocTypes = new Set(['ip', 'domain', 'hash', 'sha256', 'sha1', 'md5', 'url', 'email']);
        const iocs: ExtractedIOC[] = markers.iocs
          .filter(i => validIocTypes.has(i.type))
          .map(i => ({ type: i.type as ExtractedIOC['type'], value: i.value }));

        const analysis: VendorReportAnalysis = {
          url,
          title,
          published,
          vendor: config.name,
          extracted_intelligence: {
            actors:           markers.actors,
            malware_families: markers.malware,
            techniques,
            cves:             markers.cves,
            iocs,
            tools_used:       markers.tools,
            target_industries:markers.industries,
            target_regions:   markers.regions,
            kill_chain_phases:[],
          },
          raw_text_length: body.length,
          confidence,
        };

        const result: VendorIntelResult<VendorReportAnalysis> = {
          source: config.key,
          success: true,
          data: analysis,
          queried_at: new Date().toISOString(),
          pivot_suggestions: buildReportPivots(markers, toolName),
        };

        setCached(cacheKey, result, VENDOR_BLOG_TTL);
        return result;
      } catch (err) {
        return makeVendorErr(config.key, err instanceof Error ? err.message : String(err));
      }
    },
  });
}
