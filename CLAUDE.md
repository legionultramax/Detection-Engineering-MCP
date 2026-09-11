# Harris HawkEye MCP — Operations Guide v8

> **15,176 detections** (KQL 5,509 · Sigma 4,030 · Elastic 2,218 · Splunk 2,185 · Sublime 1,234)
> **596 techniques covered** · **365 analytic stories**
> **835 techniques** | **187 groups** | **696 malware** | **52 campaigns** | **268 mitigations**
> **Primary output = kill-chain correlated queries (KQL + SPL + Sigma), not atomic rules.**
> **Target languages: KQL · SPL · CQL · AQL (QRadar).** Every query goes through `validate_query`
> before it is presented — a wrong field name returns zero rows, which reads as "nothing found".

---

## SKILLS — invoke the matching skill before anything else

### Security Skills

These are the skills that exist in `.claude/skills/`. Invoking a skill that is not listed here
fails — check this table rather than assuming a name.

| Trigger | Skill |
|---|---|
| Analyse a threat, map ATT&CK, design the analytic | **cti-detection-engineer** |
| Parse unstructured threat report, advisory, blog, DFIR writeup | **threat-report-parser** |
| Author or fix a detection rule file (Sigma / SPL / KQL / Elastic TOML) | **detection-yaml-engineer** |
| Tune a query for the target engine's indexes | **spl-optimizer** |
| Pre-deployment QA: will this rule fire, and what breaks it? | **detection-reviewer** |
| Build true-positive test scenarios for a rule | **detection-test-engineer** |
| Validate a rule against Atomic Red Team tests | **atomic-red-team-testing** |
| Do I have the telemetry / logs needed for this? | **data-source-mapper** |
| Coverage or gap analysis across techniques, tactics or actors | **coverage-analysis** |
| Generate ATT&CK Navigator layer / heatmap / gap JSON | **attack-navigator-generator** |
| Group related detections into a narrative or analytic story | **analytic-story-builder** |
| Package registry, CI/CD or container supply-chain compromise | **supply-chain-analyst** |
| What does a CrowdStrike Falcon event mean / which exist for a platform | **crowdstrike-falcon-events** |
| Stand up a lab to test detections | **attack-range-builder** |
| Author or deploy a custom atomic test | **custom-atomics-deployment** |
| Review a detection PR for coverage gaps before merge | **pr-extension-workflow** |

**No skill covers these — do them inline against the tool tiers below:**

| Capability | Why there is no skill |
|---|---|
| **Kill-chain synthesis** (WAT-42) | Was `killchain-synth`. Not in this repository. Follow WAT-42 directly |
| **LOLBAS hard gate** | Was part of `detect-engineer`. Enforce it via the quality gate below |
| **LOLFarm enrichment** | No upstream equivalent. Call the LOLFarm tools directly |
| **Advisory → gap table** | Was `advisory-ingest`. Use `threat-report-parser`, then WAT-30/31 |

> **Two things to know before invoking any of the sixteen.** They were vendored from
> [MHaggis/Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP) and reference
> tool names from that server, several of which differ here: `search` → `search_detections`,
> `search_groups` → `search_threat_groups`, `get_technique` → `lookup_mitre_technique`,
> `get_group_techniques` → `get_groups_using_technique`. Others — `find_similar_detections`,
> `search_stories`, the `generate_*_layer` family — have **no equivalent**; do not fabricate a call,
> say the capability is absent.
>
> And `atomic-red-team-testing`, `attack-range-builder`, `custom-atomics-deployment` and
> `pr-extension-workflow` assume infrastructure this project does not run. **Atomic Red Team is not
> indexed**, so the 7 ART tools return empty — treat ART references as unavailable rather than
> retrying them.

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

> This table describes the full 134-tool surface. When `HAWKEYE_TOOL_PROFILE` is set — the
> `phase1-authoring` profile exposes 29 — most of the threat-intel, Abuse.ch, OTX and knowledge-graph
> rows below are simply absent. **Your own tool list is authoritative.** Work with what is there; do
> not call a name because it appears here.

### Tier 1 — RELIABLE (always use first)

| Category | Tools |
|---|---|
| **MITRE ATT&CK** | get_threat_group, search_threat_groups, get_software, search_software, lookup_mitre_technique, search_mitre_techniques, get_groups_using_technique, get_software_using_technique, get_mitigations, get_data_sources, list_campaigns, list_data_sources, get_mitre_attack_stats |
| **Detection Repo** | search_detections, get_detection, list_by_mitre, list_by_severity, analyze_coverage, identify_gaps, get_stats |
| **Correlation Engine** | ti_multi_source_ttp_lookup, ti_actor_full_profile, ti_hunt_package, ti_daily_brief *(auto-fallbacks to 15 secondary vendors — escalate to Tier 2 only if `vendor_reports_found = 0`)* |
| **Abuse.ch** | urlhaus_lookup_url/host/tag, threatfox_search_ioc/family/tag, threatfox_get_recent_iocs, bazaar_lookup_hash, bazaar_search_family/tag, bazaar_get_recent_samples, bazaar_get_imphash_siblings |
| **OTX** | otx_pivot_ip/domain/hash/url, otx_search_actor, otx_get_pulse_iocs, otx_subscribed_feed |
| **Vuln Intel** | nvd_cve_lookup, epss_score_lookup, epss_bulk_check, check_cisa_kev |
| **Malware Research** | malpedia_search, malpedia_actor_profile, malpedia_family_profile, anyrun_trending |
| **LOL / IOC** | lookup_lolbas, list_lolbas, analyze_ioc, misp_warninglist_check |
| **LOLFarm** | **get_lolfarm_context** *(call with `mode="summary"` first — ~500 tokens; escalate to `detailed` only if authoring depends on full data)*, then per-source deep-dives: lookup_loldriver, lookup_hijacklib, lookup_lolrmm, lookup_lofp, lookup_wadcom, lookup_lots_domain, lookup_malapi, search_lolfarm, list_loldrivers, list_lolrmm, list_hijacklibs. **sync_lolfarm** runs weekly via scheduled task — do not call manually unless data is suspected stale. |
| **Rule Conversion** *(drafts only — always refine)* | cve_to_detection, convert_yara_to_sigma, convert_sigma_to_kql |
| **Knowledge Graph** | create_entity, search_entities, create_relation, get_knowledge_summary, log_decision, get_decisions, add_learning, get_learnings |

### Tier 2 — WEB RESEARCH (Playwright + DuckDuckGo) — *only if a browser server is attached*

**This MCP provides no browser tools.** Playwright comes from a separate MCP server. If
`browser_navigate` is not in your tool list, Tier 2 is unavailable — say so and proceed on Tier 1
alone rather than retrying or inventing a call. Do not treat its absence as a failed hunt.

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
`*_search_reports` and `*_fetch_report` (one pair per vendor, generated at runtime). They are still
registered and will answer, which is why this is a rule and not a note: each one is a per-vendor RSS
fetch, so calling them one at a time is what the correlation engine already does across all vendors
in parallel. Use `ti_multi_source_ttp_lookup` / `ti_actor_full_profile` instead, then Tier 2 if it is
available. (`ti_report_ingest` appears in older versions of this guide and no longer exists.)

---

## WAT PIPELINE

**WAT-00 Classify** — Determine mode. Resolve actor aliases via search_threat_groups(). Check up front whether a browser tool is in your tool list; that decides whether WAT-20 is reachable at all.
**WAT-01 Recall** — search_entities + get_learnings + get_decisions. Full hit (<72h) = skip WAT-10/11/20/21.
**WAT-10 Actor Intel** — get_threat_group + malpedia_actor_profile + ti_actor_full_profile → extract ordered_ttp_chain, malware_artifacts, dwell_time. Empty vendor data → WAT-20. Deep: add get_software, list_campaigns, get_mitigations per technique.
**WAT-11 Technique Intel** — lookup_mitre_technique + get_groups_using_technique + get_software_using_technique + get_data_sources + get_mitigations + ti_multi_source_ttp_lookup. vendor_reports_found=0 → WAT-20.
**WAT-12 CVE Intel** *(Standard/Deep)* — nvd_cve_lookup + epss_score_lookup + check_cisa_kev in parallel. When CVSS ≥ 8.0 or KEV = yes, go to WAT-20; if Tier 2 is unavailable, record that the exploitation detail is unverified rather than treating the NVD summary as sufficient.
**WAT-20 Web Research** *(Standard/Deep, Tier 2 only)* — Playwright + DuckDuckGo per Tier 2 sequence. Run whenever the correlation engine returned empty. **Skip and say so if no browser tool is in your tool list** — this step has no Tier 1 substitute, so the honest outcome is a hunt grounded on MITRE and the local corpus with the vendor-reporting gap named in the report.
**WAT-21 IOC Enrichment** — misp_warninglist_check FIRST. Then threatfox + bazaar + otx_pivot + urlhaus in parallel. High-value: bazaar_get_imphash_siblings.
**WAT-30 Coverage Audit** — list_by_mitre(parent + sub) + search_detections per technique. Classify: COVERED / PARTIAL / GAP.
**WAT-31 Gap Analysis** — identify_gaps() as baseline only. Manual per-TID check via list_by_mitre. Generic rules = PARTIAL. Priority: CRITICAL > HIGH > MEDIUM > LOW.
**WAT-40 Query Reference** — Collect best existing rules via search_detections + get_detection + lookup_lolbas. Input for WAT-42, not the deliverable.
**WAT-41 Validation** — Score every rule: 5 dimensions (Evasion, Fields, Paths, FP, Syntax) + 3 for correlation (Sequence, Entity, Window). Composite < 3.0 = iterate max 2x then flag [HARDENING: PARTIAL].
**WAT-42 Kill-Chain Synthesis** *(PRIMARY — Standard/Deep)* — no skill exists for this; do it inline. Take `ordered_ttp_chain` from WAT-10/11 and the reference rules from WAT-40, then for each phase identify the pivot entity (user, host, process lineage) that links it to the next, and express the sequence in the target language: Sigma `correlation` rules, KQL `let` + `join` on the pivot within a stated window, SPL `stats` grouped by the pivot with per-phase flags, CQL `groupBy` over the pivot. State the correlation window explicitly and say which phases could not be linked. **QRadar AQL has no join, no union and no subquery** — `validate_query` blocks all three. For AQL, emit one query per phase plus the correlation logic as a written spec, or collapse the phases into a single pass with conditional aggregation over a shared key; never a single query that cannot express the sequence.
**WAT-50 Persist + Report** — create_entity, create_relation, add_learning, log_decision in parallel. Generate report.

### Shortcuts
| Shortcut | Steps |
|---|---|
| **HUNT-ACTOR** | WAT-00→01→10→20→21→30→31→40→41→42→50 |
| **HUNT-TECHNIQUE** | WAT-00→01→11→20→30→31→40→41→42(if chain)→50 |
| **ANALYZE-CVE** | WAT-00→01→12→20→30→31→40→41→42→50 |
| **INGEST-ADVISORY** | **threat-report-parser** → WAT-30 → WAT-31 → WAT-40 → WAT-41 → WAT-50 *(no `advisory-ingest` skill; the parser plus the gap steps cover it)* |
| **DAILY-BRIEF** | anyrun_trending + threatfox_get_recent_iocs + bazaar_get_recent_samples → WAT-20 *(if Tier 2)* → WAT-50 |

---

## REPORT STRUCTURE

```
## Threat Hunt Report — [Subject]
**Date** | **Mode** (Quick/Standard/Deep) | **Priority** (Critical/High/Medium)

### Executive Summary — 2-3 sentences: what, who, why now.
### MITRE Kill-Chain Coverage — Table: Phase | Technique | Groups | Data Source | Coverage
### Intelligence Sources — vendor reports, IOCs, campaigns, EPSS/KEV scores, and any check that did not run
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
- EPSS + KEV checked for any CVE
- Binary-scoped rules: abuse matrix covering ALL known patterns before writing query

**A gate whose tool is unavailable is reported, not skipped silently.** If a tool is absent from the
tool list, or errors because the host has no outbound HTTPS, state which check did not run and why.
An unrun check is a caveat on the report; pretending it passed is a false assurance. This applies
in particular to:
- **Playwright** — not provided by this server; unavailable unless a browser MCP is attached
- **EPSS / KEV / MISP warninglist** — reach the network, so they fail on an isolated or proxied host

**Non-blocking — best effort:**
- MISP warninglist checked for domain/IP IOCs before pivoting
- Data source requirements stated per phase
- FP considerations documented per phase (not global)
- New findings persisted to Knowledge Graph

---

## ANTI-PATTERNS — NEVER DO

- Use `*_search_reports` or `*_fetch_report` (deprecated — see BANNED above)
- Present a single atomic rule as final output for Standard/Deep hunts
- Stop at WAT-40 without WAT-42 synthesis in Standard/Deep mode
- Accept empty vendor_reports silently — either supplement via Tier 2 or state the gap
- Invent a `browser_*` call, or retry one that is not in your tool list
- Claim a gate passed when the tool backing it was unavailable or errored
- Skip misp_warninglist_check before IOC pivoting
- Hardcode IOC values inside detection rule logic
- Deploy rules with composite score < 3.0
- Use identify_gaps() alone for actor-specific hunts (too generic)
- Present cve_to_detection() or convert_yara_to_sigma() output as final (both are drafts)
- Write binary-scoped detection without enumerating all known abuse patterns first
- Call MCP tools (search_detections, list_by_mitre, etc.) via subagent — always call directly in parallel
