# Harris HawkEye MCP — Operations Guide v8

> **12,769 detections** (KQL 5,051 · Sigma 3,108 · Splunk 1,966 · Elastic 1,689 · Sublime 955)
> **835 techniques** | **187 groups** | **696 malware** | **52 campaigns** | **268 mitigations**
> **Primary output = kill-chain correlated queries (KQL + SPL + Sigma), not atomic rules.**

---

## SKILLS — invoke the matching skill before anything else

### Security Skills
| Trigger | Skill |
|---|---|
| Write / fix / tune / convert any detection rule | **detect-engineer** |
| Parse unstructured threat report, blog, DFIR writeup into rules | **threat-report-parser** |
| Parse CISA / vendor / DFIR advisory for coverage gaps | **advisory-ingest** |
| Stitch multiple techniques into one correlated query | **killchain-synth** |
| Pre-deployment: will this rule actually fire? | **detection-validator** |
| Do I have the telemetry / logs needed for this? | **data-source-mapper** |
| Generate ATT&CK Navigator layer / heatmap / gap JSON | **navigator-layer-gen** |
| Generate a coverage report across techniques or actors | **coverage-reporter** |

### Utility Skills
| Trigger | Skill |
|---|---|
| Read, extract, or create any PDF file | **anthropic-skills:pdf** |
| Read, edit, or create any Word document (.docx) | **anthropic-skills:docx** |
| Read, edit, or create any spreadsheet (.xlsx / .csv) | **anthropic-skills:xlsx** |
| Create or edit a PowerPoint presentation (.pptx) | **anthropic-skills:pptx** |
| Create a new skill or improve an existing one | **anthropic-skills:skill-creator** |
| Schedule a recurring task or remote agent | **anthropic-skills:schedule** |
| Configure Claude Code settings / hooks / permissions | **update-config** |

> If no skill matches, fall through to the WAT pipeline below.

---

## MODE

| Trigger | Mode |
|---|---|
| "breach" / "IR" / "compromised" / "full profile" / "comprehensive" | **Deep** |
| "investigate" / "coverage check" / CVE + detect / specific hunt | **Standard** |
| Single technique or actor lookup | **Quick** |

---

## TOOL TIERS

### Tier 1 — RELIABLE (always use first)

| Category | Tools |
|---|---|
| **MITRE ATT&CK** | get_threat_group, search_threat_groups, get_software, search_software, lookup_mitre_technique, search_mitre_techniques, get_groups_using_technique, get_software_using_technique, get_mitigations, get_data_sources, list_campaigns, list_data_sources, get_mitre_attack_stats |
| **Detection Repo** | search_detections, get_detection, list_by_mitre, list_by_severity, analyze_coverage, identify_gaps, get_stats |
| **Correlation Engine** | ti_multi_source_ttp_lookup, ti_actor_full_profile, ti_hunt_package, ti_daily_brief *(auto-fallbacks to 15 secondary vendors — only trigger Playwright if vendor_reports_found = 0)* |
| **Abuse.ch** | urlhaus_lookup_url/host/tag, threatfox_search_ioc/family/tag, threatfox_get_recent_iocs, bazaar_lookup_hash, bazaar_search_family/tag, bazaar_get_recent_samples, bazaar_get_imphash_siblings |
| **OTX** | otx_pivot_ip/domain/hash/url, otx_search_actor, otx_get_pulse_iocs, otx_subscribed_feed |
| **Vuln Intel** | check_cisa_kev, list_by_cve |
| **Govt Advisories** | cisa_search_advisories, govt_joint_advisory_search |
| **LOL / IOC** | lookup_lolbas, list_lolbas, analyze_ioc, get_threat_profile |
| **LOLFarm** | **get_lolfarm_context** *(call with `mode="summary"` first — ~500 tokens; escalate to `detailed` only if authoring depends on full data)*, then per-source deep-dives: lookup_loldriver, lookup_hijacklib, lookup_lolrmm, lookup_lofp, lookup_wadcom, lookup_lots_domain, lookup_malapi, search_lolfarm, list_loldrivers, list_lolrmm, list_hijacklibs. **sync_lolfarm** runs weekly via scheduled task — do not call manually unless data is suspected stale. |
| **Rule Conversion** *(drafts only — always refine)* | cve_to_detection, convert_yara_to_sigma, convert_sigma_to_kql |
| **Knowledge Graph** | create_entity, search_entities, create_relation, get_knowledge_summary, log_decision, get_decisions, add_learning, get_learnings |

### Tier 2 — WEB RESEARCH (Playwright + DuckDuckGo)
Trigger only when correlation engine returns `vendor_reports_found = 0` after full fallback, or when you need content not available via RSS (PoC code, paywalled reports, campaigns < 4h old).

**Sequence:** `browser_navigate(duckduckgo)` → type query → click search → snapshot → for each result: navigate → wait(3s) → snapshot → extract T-IDs, CVEs, IOCs, CLI patterns, event IDs, inline queries.

**Search patterns:**
- Actor TTPs: `site:microsoft.com OR site:mandiant.com {actor} techniques 2024`
- CVE exploit: `{CVE-ID} exploitation detection site:attackerkb.com OR site:rapid7.com`
- Technique artifacts: `site:ired.team OR site:threathunterplaybook.com {T-ID} artifacts`
- SPL rules: `site:research.splunk.com {query} detection`
- KQL rules: `site:elastic.co/security-labs {query}`
- Govt advisories: `site:cisa.gov {actor OR CVE}`

### BANNED — never use
`*_search_reports`, `*_fetch_report`, `ti_report_ingest` — all deprecated. Use Playwright instead.

### NOT IMPLEMENTED — documented but absent from the server
These appear in this repo's README and in earlier revisions of this guide, but **no such
tools are registered**. Calling them returns "Unknown tool". Verified against
`src/tools/**` — the server registers **102** tools, not the 122 the README badge claims.

| Absent tool | Capability | Substitute |
|---|---|---|
| `nvd_cve_lookup` | CVE detail lookup | `list_by_cve` for local rule coverage; Playwright for CVE detail |
| `epss_score_lookup`, `epss_bulk_check` | EPSS exploit-probability scoring | **none** — EPSS cannot be checked; do not claim it was |
| `misp_warninglist_check` | IOC false-positive screening | **none** — screen IOCs manually before pivoting |
| `malpedia_search`, `malpedia_actor_profile`, `malpedia_family_profile` | Malware family/actor profiles | `get_software`, `search_software`, `ti_actor_full_profile` |
| `anyrun_trending` | Trending sandbox submissions | `bazaar_get_recent_samples`, `threatfox_get_recent_iocs` |
| `get_top_gaps`, `get_coverage_summary` | *(these DO exist — use them)* | — |

Never state that an EPSS score or MISP screening was checked. If the capability is
required, say it is unavailable rather than substituting a guess from training data.

---

## WAT PIPELINE

**WAT-00 Classify** — Determine mode. Resolve actor aliases via search_threat_groups(). Check browser state.
**WAT-01 Recall** — search_entities + get_learnings + get_decisions. Full hit (<72h) = skip WAT-10/11/20/21.
**WAT-10 Actor Intel** — get_threat_group + ti_actor_full_profile + get_software_using_technique → extract ordered_ttp_chain, malware_artifacts, dwell_time. Empty vendor data → WAT-20. Deep: add get_software, list_campaigns, get_mitigations per technique.
**WAT-11 Technique Intel** — lookup_mitre_technique + get_groups_using_technique + get_software_using_technique + get_data_sources + get_mitigations + ti_multi_source_ttp_lookup. vendor_reports_found=0 → WAT-20.
**WAT-12 CVE Intel** *(Standard/Deep)* — check_cisa_kev + list_by_cve in parallel. No NVD or EPSS tool exists (see NOT IMPLEMENTED), so CVSS and EPSS must come from Playwright — mandatory when KEV = yes, or when severity is unknown.
**WAT-20 Web Research** *(Standard/Deep)* — Playwright + DuckDuckGo per Tier 2 sequence. Always run when correlation engine returned empty.
**WAT-21 IOC Enrichment** — no warninglist tool exists, so screen obvious benign infrastructure (CDNs, cloud egress, telemetry endpoints) by inspection first. Then threatfox + bazaar + otx_pivot + urlhaus in parallel. High-value: bazaar_get_imphash_siblings.
**WAT-30 Coverage Audit** — list_by_mitre(parent + sub) + search_detections per technique. Classify: COVERED / PARTIAL / GAP.
**WAT-31 Gap Analysis** — identify_gaps() as baseline only. Manual per-TID check via list_by_mitre. Generic rules = PARTIAL. Priority: CRITICAL > HIGH > MEDIUM > LOW.
**WAT-40 Query Reference** — Collect best existing rules via search_detections + get_detection + lookup_lolbas. Input for WAT-42, not the deliverable.
**WAT-41 Validation** — Score every rule: 5 dimensions (Evasion, Fields, Paths, FP, Syntax) + 3 for correlation (Sequence, Entity, Window). Composite < 3.0 = iterate max 2x then flag [HARDENING: PARTIAL].
**WAT-42 Kill-Chain Synthesis** *(PRIMARY — Standard/Deep)* — invoke **killchain-synth** skill with ordered_ttp_chain + reference rules from WAT-40.
**WAT-50 Persist + Report** — create_entity, create_relation, add_learning, log_decision in parallel. Generate report.

### Shortcuts
| Shortcut | Steps |
|---|---|
| **HUNT-ACTOR** | WAT-00→01→10→20→21→30→31→40→41→42→50 |
| **HUNT-TECHNIQUE** | WAT-00→01→11→20→30→31→40→41→42(if chain)→50 |
| **ANALYZE-CVE** | WAT-00→01→12→20→30→31→40→41→42→50 |
| **INGEST-ADVISORY** | → invoke **advisory-ingest** skill directly |
| **DAILY-BRIEF** | ti_daily_brief + threatfox_get_recent_iocs + bazaar_get_recent_samples → Playwright → WAT-50 |

---

## REPORT STRUCTURE

```
## Threat Hunt Report — [Subject]
**Date** | **Mode** (Quick/Standard/Deep) | **Priority** (Critical/High/Medium)

### Executive Summary — 2-3 sentences: what, who, why now.
### MITRE Kill-Chain Coverage — Table: Phase | Technique | Groups | Data Source | Coverage
### Intelligence Sources — Playwright sites, IOCs, campaigns, EPSS/KEV scores
### Detection Gaps — Table: TID | Phase | Priority | Log Required | Why Critical
### Abuse Matrix — Pattern | T-ID | CLI | Actors | Coverage (all known patterns)
### Atomic Detection Rules — Sigma + KQL + SPL per gap technique, with validation scores
### Kill-Chain Correlation (PRIMARY) — Sigma correlation + KQL let-join + SPL phase-scored
### Kill-Chain Score — X.X/5.0 | Phases covered | FP risk level
### Data Requirements — Table: Phase | Log Source | Event ID | Platform | Collection Status
### Recommended Actions — Deploy order, missing telemetry, MITRE mitigations, KG entities persisted
```

---

## QUALITY GATES

**Blocking — must complete before report:**
- Gap analysis per TID in kill chain (WAT-31) — not just identify_gaps()
- WAT-42 kill-chain synthesis attempted for Standard/Deep
- Every atomic rule scores ≥ 3/5 on all 5 dimensions
- Kill-chain query scores ≥ 3/5 on Sequence + Entity + Window
- Playwright run if any vendor data returned empty
- KEV checked for any CVE via check_cisa_kev (EPSS has no tool — source it via Playwright or state it as unavailable)
- Binary-scoped rules: abuse matrix covering ALL known patterns before writing query

**Non-blocking — best effort:**
- Domain/IP IOCs screened for benign infrastructure before pivoting (no warninglist tool — by inspection)
- Data source requirements stated per phase
- FP considerations documented per phase (not global)
- New findings persisted to Knowledge Graph

---

## ANTI-PATTERNS — NEVER DO

- Use `*_search_reports`, `*_fetch_report`, or `ti_report_ingest` (deprecated)
- Present a single atomic rule as final output for Standard/Deep hunts
- Stop at WAT-40 without WAT-42 synthesis in Standard/Deep mode
- Accept empty vendor_reports without Playwright supplement
- Claim an EPSS score or MISP screening was performed — neither tool exists on this server
- Hardcode IOC values inside detection rule logic
- Deploy rules with composite score < 3.0
- Use identify_gaps() alone for actor-specific hunts (too generic)
- Present cve_to_detection() or convert_yara_to_sigma() output as final (both are drafts)
- Write binary-scoped detection without enumerating all known abuse patterns first
- Call MCP tools (search_detections, list_by_mitre, etc.) via subagent — always call directly in parallel
