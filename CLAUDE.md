# CLAUDE.md — House of Hunting MCP · Elite Operations Guide v4

> **Project**: House of Hunting MCP
> **Rule repo**: ~8,000+ detections (Sigma 3,110 · Splunk ESCU 1,966 · Elastic 1,693 · KQL 1,297)
> **MITRE dataset**: 835 techniques · 187 groups · 787 software · 52 campaigns · 268 mitigations · 20,048 relationships
> **Reliable Tools**: 45 (API-based, always work)
> **Web Research**: Playwright + DuckDuckGo (zero cost, JS rendering)
> **Architecture**: WAT Framework v4 · 12 streamlined blocks

---

## CORE PRINCIPLE: RELIABLE TOOLS ONLY

**TIER 1 — ALWAYS RELIABLE (Local + Public APIs)**
```
MITRE ATT&CK (local)    abuse.ch (URLhaus/ThreatFox/Bazaar)
Detection Repo (local)   AlienVault OTX
Knowledge Graph (local)  NVD/EPSS/CISA KEV
Malpedia                 LOLBAS
```

**TIER 2 — WEB RESEARCH (Playwright + Search)**
```
DuckDuckGo search → Get URLs → Playwright renders pages
Covers: ALL vendor blogs, govt advisories, research reports
No API keys needed. No rate limits. JS rendering works.
```

**DEPRECATED — DO NOT USE**
```
❌ mandiant_search_reports, microsoft_search_reports, crowdstrike_search_reports
❌ dfir_report_search_reports, volexity_search_reports, etc.
❌ ti_report_ingest (403 on most sites)
→ These are RSS-limited, frequently blocked, unreliable
→ Use Playwright web search instead
```

---

## WAT FRAMEWORK v4 — Streamlined

### Mode Decision

| Signal | Mode |
|--------|------|
| "breach" / "IR" / "compromised" | **Deep** |
| "full profile" / "comprehensive" / multi-actor | **Deep** |
| "investigate" / "coverage check" / CVE+detect | **Standard** |
| Single technique/actor lookup | **Quick** |

### Execution Matrix (12 Blocks)

```
Block                              | Quick | Standard | Deep
───────────────────────────────────────────────────────────
WAT-00  Classify                   |  ✓    |    ✓     |  ✓
WAT-01  Knowledge Recall           |  ✓    |    ✓     |  ✓
WAT-10  Actor Intel (MITRE+Malpedia)|  ✓*  |    ✓     |  ✓+
WAT-11  Technique Intel            |  ✓*   |    ✓     |  ✓+
WAT-12  CVE Intel                  |  —    |    ✓     |  ✓
WAT-20  Web Research (Playwright)  |  —    |   ✓†     |  ✓
WAT-21  IOC Enrichment             |  —    |   ✓‡     |  ✓
WAT-30  Coverage Audit             |  ✓    |    ✓     |  ✓
WAT-31  Gap Analysis               |  ✓    |    ✓     |  ✓
WAT-40  Query Construction         |  ✓    |    ✓     |  ✓
WAT-41  Query Validation           |  ✓    |    ✓     |  ✓
WAT-50  Knowledge Persist + Report |  ✓    |    ✓     |  ✓
```

`* fused call only` `+ granular supplement` `† if URL provided` `‡ if IOCs exist`

---

## WAT BLOCKS — STREAMLINED

### WAT-00: CLASSIFY
```
1. Classify mode (Quick/Standard/Deep)
2. Resolve actor aliases: search_threat_groups(name) → get canonical + aliases
3. Check Playwright: browser_snapshot() → cache result
```

### WAT-01: KNOWLEDGE RECALL
```
1. search_entities(actor_aliases)     [check KG for existing data]
2. get_learnings(topic)               [past insights]
3. get_decisions(topic)               [past design choices]
→ FULL HIT (< 72h): skip WAT-10/11/20/21
→ PARTIAL/MISS: continue
```

### WAT-10: ACTOR INTELLIGENCE
```
FUSED (all modes):
  get_threat_group(actor)              [MITRE techniques, aliases]
  malpedia_actor_profile(actor_id)     [malware families, alt names]

GRANULAR (Deep only):
  get_software(each_malware)           [technique links per tool]
  list_campaigns(actor)                [campaign history]
  get_data_sources(each_technique)     [required telemetry]
  get_mitigations(each_technique)      [defensive controls]
```

### WAT-11: TECHNIQUE INTELLIGENCE
```
lookup_mitre_technique(tid)            [full description]
get_groups_using_technique(tid)        [who uses this]
get_software_using_technique(tid)      [what implements this]
get_data_sources(tid)                  [how to detect]
get_mitigations(tid)                   [how to prevent]
```

### WAT-12: CVE INTELLIGENCE
```
[PARALLEL]:
  nvd_cve_lookup(cve_id)               [CVSS, description, CPE]
  epss_score_lookup(cve_id)            [exploitation probability]
  check_cisa_kev(cve_id)               [KEV status + deadline]

cve_to_detection(cve_id)               [generate detection rules]
```

### WAT-20: WEB RESEARCH (Playwright)
**THIS REPLACES ALL UNRELIABLE VENDOR TOOLS**

```
STEP 1: Search
  browser_navigate("https://duckduckgo.com")
  browser_type("site:microsoft.com APT29 techniques")
  browser_click("search button")
  browser_snapshot() → extract URLs

STEP 2: Render & Extract
  For each relevant URL:
    browser_navigate(url)
    browser_wait_for(time=3)
    browser_snapshot() → extract:
      - Technique IDs (T1XXX pattern)
      - CVE IDs
      - IOCs (IPs, domains, hashes)
      - Actor names
      - Malware families
```

**Search Queries by Context:**
```
Actor research:    "site:microsoft.com OR site:mandiant.com {actor} techniques"
CVE research:      "{CVE-ID} exploitation detection"
Malware research:  "site:malpedia.caad.fkie.fraunhofer.de {malware}"
Govt advisories:   "site:cisa.gov {actor OR CVE}"
```

### WAT-21: IOC ENRICHMENT
```
[MANDATORY FIRST]: misp_warninglist_check(ioc)  [FP filter]

[PARALLEL]:
  threatfox_search_ioc(ioc)            [ThreatFox C2 data]
  bazaar_lookup_hash(hash)             [sample analysis]
  otx_pivot_ip/domain/hash(ioc)        [OTX enrichment]
  urlhaus_lookup_url(url)              [malicious URL check]

[HIGH VALUE]:
  bazaar_get_imphash_siblings(imphash) [find variants]
```

### WAT-30: COVERAGE AUDIT
```
Per technique:
  list_by_mitre(parent_tid)            [parent coverage]
  list_by_mitre(sub_tid)               [sub-technique coverage]
  search_detections(actor_name)        [name-tagged rules]
  search_detections(malware_name)      [malware-tagged rules]

Classify: COVERED / PARTIAL / GAP
```

### WAT-31: GAP ANALYSIS
```
identify_gaps(threat_profile)          [find missing coverage]
analyze_coverage(source)               [heatmap view]

Prioritize gaps:
  CRITICAL: actor uses + active campaign + no rule
  HIGH: actor uses + no rule
  MEDIUM: related actor uses + no rule
  LOW: theoretical gap
```

### WAT-40: QUERY CONSTRUCTION
```
1. search_detections(technique)        [find adaptable rule]
2. get_detection(rule_id)              [get full content]
3. If CVE: cve_to_detection(cve_id)
4. If YARA: convert_yara_to_sigma(yara)
5. convert_sigma_to_kql(sigma)         [for Sentinel]
6. lookup_lolbas(binary)               [find alternatives]

Output: Sigma + KQL + Splunk SPL per gap
```

### WAT-41: QUERY VALIDATION (5 Dimensions)
```
| Dimension | Check | Min Score |
|-----------|-------|----------|
| Evasion   | Covers obfuscation, alt binaries, case variation | 3/5 |
| Fields    | Uses correct log fields + corroborating fields | 3/5 |
| Paths     | Covers multiple execution paths | 3/5 |
| FP        | Has filter section + documented FP sources | 3/5 |
| Conversion| KQL logic matches Sigma exactly | 3/5 |

Composite ≥ 3.0 = PASS
Composite < 3.0 = Iterate (max 2x) or flag [HARDENING: PARTIAL]
```

### WAT-50: PERSIST + REPORT
```
[PARALLEL]:
  create_entity(actor/technique/campaign)
  create_relation(actor, technique, "uses")
  add_learning(topic, insight, source)
  log_decision(title, reasoning, alternatives)

Generate final report (see template below)
```

---

## ORCHESTRATION WORKFLOWS

### HUNT-ACTOR (e.g., "Hunt APT29")
```
WAT-00 → WAT-01 → WAT-10 → WAT-20(Deep) → WAT-21 → WAT-30 → WAT-31 → WAT-40 → WAT-41 → WAT-50
```

### HUNT-TECHNIQUE (e.g., "Hunt T1059.001")
```
WAT-00 → WAT-01 → WAT-11 → WAT-20(if URL) → WAT-30 → WAT-31 → WAT-40 → WAT-41 → WAT-50
```

### ANALYZE-CVE (e.g., "Detect CVE-2024-XXXX")
```
WAT-00 → WAT-01 → WAT-12 → WAT-20(if needed) → WAT-30 → WAT-31 → WAT-40 → WAT-41 → WAT-50
```

### INGEST-ADVISORY (e.g., "Read this CISA advisory")
```
WAT-00 → WAT-20(Playwright URL) → Extract TTPs/IOCs → WAT-21 → WAT-30 → WAT-40 → WAT-41 → WAT-50
```

### DAILY-BRIEF (e.g., "What's trending?")
```
WAT-00 → anyrun_trending → threatfox_get_recent_iocs → bazaar_get_recent_samples → WAT-50(brief)
```

---

## TOOL REFERENCE — RELIABLE ONLY

### MITRE ATT&CK (Local — Always Works)
```
get_threat_group(name)                 search_threat_groups(query)
get_software(name)                     search_software(query)
lookup_mitre_technique(tid)            search_mitre_techniques(query)
get_groups_using_technique(tid)        get_software_using_technique(tid)
get_mitigations(tid)                   get_data_sources(tid)
list_campaigns(query)                  get_mitre_attack_stats()
list_data_sources()
```

### Detection Repo (Local — ~8,000 Rules)
```
search_detections(query)               get_detection(id)
list_by_mitre(tid)                     list_by_severity(level)
analyze_coverage(source)               identify_gaps(profile)
get_stats()
```

### abuse.ch (Public API — No Auth)
```
urlhaus_lookup_url(url)                urlhaus_lookup_host(host)
urlhaus_lookup_tag(tag)
threatfox_search_ioc(ioc)              threatfox_search_family(family)
threatfox_search_tag(tag)              threatfox_get_recent_iocs()
bazaar_lookup_hash(hash)               bazaar_search_family(family)
bazaar_search_tag(tag)                 bazaar_get_recent_samples()
bazaar_get_imphash_siblings(imphash)
```

### AlienVault OTX (Requires OTX_API_KEY)
```
otx_pivot_ip(ip)                       otx_pivot_domain(domain)
otx_pivot_hash(hash)                   otx_pivot_url(url)
otx_search_actor(actor)                otx_get_pulse_iocs(pulse_id)
otx_subscribed_feed()
```

### Vulnerability Intel (Public APIs)
```
nvd_cve_lookup(cve_id)                 epss_score_lookup(cve_id)
epss_bulk_check(cve_ids)               check_cisa_kev(cve_id)
```

### Malware Research (Public)
```
malpedia_search(query)                 malpedia_actor_profile(actor_id)
malpedia_family_profile(family_id)     anyrun_trending()
```

### LOLBAS & IOC Analysis
```
lookup_lolbas(binary)                  list_lolbas()
analyze_ioc(ioc)                       misp_warninglist_check(ioc)
```

### Rule Conversion
```
cve_to_detection(cve_id)               convert_yara_to_sigma(yara)
convert_sigma_to_kql(sigma)            [validate output!]
```

### Knowledge Graph (Local)
```
create_entity(type, name, props)       search_entities(query)
create_relation(source, target, type)  get_knowledge_summary()
log_decision(title, decision, reason)  get_decisions(topic)
add_learning(topic, insight, source)   get_learnings(topic)
```

### Playwright (Web Research)
```
browser_navigate(url)                  browser_snapshot()
browser_click(selector)                browser_type(text)
browser_wait_for(time=N)               browser_take_screenshot()
browser_evaluate(js)                   browser_tabs()
```

---

## REPORT TEMPLATE

```markdown
## Threat Hunt Report — [Actor/Technique/CVE]
**Date**: [date] | **Mode**: [Quick/Standard/Deep] | **Priority**: [Critical/High/Medium]

### Executive Summary
2-3 sentences: what, who, why it matters.

### MITRE Coverage
| Technique | Groups | Software | Data Source | Coverage |
|-----------|--------|----------|-------------|----------|
| T1XXX.XXX | [actors] | [tools] | [logs] | ✅/⚠️/❌ |

### Intelligence
- **IOCs**: [IPs, domains, hashes]
- **Campaigns**: [names, dates]
- **EPSS**: [score] | **KEV**: [yes/no]

### Detection Gaps
| Gap | Priority | Action | Log Required |
|-----|----------|--------|-------------|
| T1XXX | CRITICAL | BUILD_RULE | Sysmon EID 1 |

### Detection Rules
**Sigma**: [yaml block]
**KQL**: [query] — Score: X.X/5.0
**SPL**: [query]

### Recommended Actions
1. Deploy: [rules]
2. Acquire: [missing logs]
3. Mitigate: [MITRE mitigations]
```

---

## ACTOR NAMING CONVENTION

| MITRE | CrowdStrike | Microsoft | Malpedia |
|-------|-------------|-----------|----------|
| APT29 | Cozy Bear | Midnight Blizzard | apt.apt29 |
| APT28 | Fancy Bear | Forest Blizzard | apt.apt28 |
| Lazarus | Hidden Cobra | Diamond Sleet | apt.lazarus_group |
| MuddyWater | Static Kitten | Mango Sandstorm | apt.muddywater |
| FIN7 | Carbon Spider | Sangria Tempest | crime.fin7 |

**Always resolve first**: `search_threat_groups(alias)` → canonical name

---

## QUALITY GATES

**BLOCKING (must complete before report)**
- [ ] Gap analysis completed (WAT-31)
- [ ] Every rule scores ≥ 3/5 on all dimensions (WAT-41)
- [ ] EPSS + KEV checked for any CVE

**NON-BLOCKING (best effort)**
- [ ] MISP warninglist checked for domain/IP IOCs
- [ ] Data source requirements stated
- [ ] FP considerations documented
- [ ] New findings persisted to KG

---

## ANTI-PATTERNS — NEVER DO

```
❌ Use mandiant_search_reports as primary research method
❌ Use ti_report_ingest on vendor blogs (403 errors)
❌ Call multiple vendor _search_reports sequentially
❌ Skip misp_warninglist_check before IOC pivoting
❌ Hardcode IOCs in detection rules
❌ Deploy rules with < 3.0 composite score
❌ Retry 403 URLs with same tool
```

---

*House of Hunting MCP · WAT Framework v4 · ~8,000 detections · 835 techniques · 187 groups · 45 reliable tools*
