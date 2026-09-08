# Harris HawkEye MCP

**Detection Engineering Command Center for Claude Code**

A Model Context Protocol (MCP) server purpose-built for detection engineers. Indexes 12,800+ detection rules from five major detection ecosystems (Sigma, KQL/Sentinel, Splunk ESCU, Elastic, Sublime), enriches them with MITRE ATT&CK v18.1, Atomic Red Team, LOLBAS, LOLFarm (lolol.farm), and 15+ threat intelligence sources — then exposes everything through 122 tools and 8 Claude Code skills that implement the full detection engineering lifecycle.

The primary output is **kill-chain correlated queries** (KQL + SPL + Sigma), not isolated atomic rules.

![Tools](https://img.shields.io/badge/Tools-122-blue)
![Skills](https://img.shields.io/badge/Skills-8-green)
![Detections](https://img.shields.io/badge/Detections-12%2C810-orange)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-v18.1-red)
![Techniques](https://img.shields.io/badge/Technique_Coverage-602%2F835_(72.1%25)-brightgreen)
![ART](https://img.shields.io/badge/Atomic_Red_Team-1770_tests-yellow)
![TI Sources](https://img.shields.io/badge/TI_Sources-15+-purple)
![LOLFarm](https://img.shields.io/badge/LOLFarm-7_sources-ff69b4)

---

## What It Does

| Capability | Description |
|---|---|
| **Multi-source detection search** | Query 12,810 rules (KQL 5,051 · Sigma 3,108 · Splunk ESCU 1,966 · Elastic 1,689 · Sublime 996) from one interface |
| **MITRE ATT&CK enrichment** | 835 techniques, 187 groups, 787 software, 52 campaigns, 20,048 relationships — all local, all queryable |
| **Atomic Red Team validation** | 1,770 adversary simulation tests cross-referenced against your detection rules for coverage gaps |
| **LOLFarm intelligence** | Aggregated Living-Off-The-Land data from 7 sources: LOLDrivers, HijackLibs, LOLRMM, LoFP, WADComs, LOTS, MalAPI |
| **LOLBAS hard gate** | Every binary-scoped rule must enumerate all known abuse patterns before a single condition is written |
| **Threat intelligence** | 15+ sources: abuse.ch (URLhaus, ThreatFox, MalwareBazaar), AlienVault OTX, CISA/FBI/NSA/NCSC-UK/CERT-EU, Malpedia, NVD/EPSS, ANY.RUN |
| **CVE-to-detection** | Input a CVE ID → get KQL, SPL, and Sigma rules with EPSS scores and KEV status |
| **Coverage engine** | 138 telemetry mappings, 4-state classification (COVERED/DETECTABLE/PARTIAL/GAP), Pareto-optimal log source recommendations |
| **Knowledge graph** | Persist decisions, learnings, and entity relationships across sessions — tribal knowledge that compounds |
| **Kill-chain synthesis** | Stitch atomic rules into correlated multi-phase queries that fire on full attack sequences, not individual events |

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │          Claude Code + 8 Skills          │
                    │  advisory-ingest / threat-report-parser  │
                    │  → data-source-mapper → detect-engineer  │
                    │  → detection-validator → killchain-synth │
                    │  → coverage-reporter → navigator-layer-gen│
                    └──────────────────┬──────────────────────┘
                                       │ MCP Protocol
                    ┌──────────────────▼──────────────────────┐
                    │        Harris HawkEye MCP Server         │
                    │                                          │
                    │  ┌─────────┐ ┌──────────┐ ┌───────────┐ │
                    │  │Detection│ │ Threat   │ │ MITRE     │ │
                    │  │Tools(15)│ │ Intel(59)│ │ ATT&CK(11)│ │
                    │  └─────────┘ └──────────┘ └───────────┘ │
                    │  ┌─────────┐ ┌──────────┐ ┌───────────┐ │
                    │  │ART (6)  │ │Coverage  │ │LOLFarm(12)│ │
                    │  │         │ │Engine (6)│ │           │ │
                    │  └─────────┘ └──────────┘ └───────────┘ │
                    │  ┌─────────┐ ┌──────────┐ ┌───────────┐ │
                    │  │Knowledge│ │Sublime   │ │ Report    │ │
                    │  │Graph (8)│ │Security(4)│ │Generator(1)│ │
                    │  └─────────┘ └──────────┘ └───────────┘ │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │     SQLite (sql.js WASM) — 97 MB DB      │
                    │                                          │
                    │  12,810 detections │ 835 techniques       │
                    │  1,770 ART tests   │ 138 telemetry maps   │
                    │  LOLFarm 7 tables  │ Knowledge graph      │
                    └─────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites
- Node.js 18+
- Claude Desktop or Claude Code

### Installation

```bash
git clone https://github.com/legionultramax/Detection-Engineering-MCP.git
cd Detection-Engineering-MCP

# Install dependencies
npm install

# Build
npm run build
```

### Download Detection Rules

Clone the four rule repositories into the `rules/` directory:

```bash
# SigmaHQ
git clone https://github.com/SigmaHQ/sigma.git rules/sigma

# Splunk Security Content (ESCU)
git clone https://github.com/splunk/security_content.git rules/splunk

# Elastic Detection Rules
git clone https://github.com/elastic/detection-rules.git rules/elastic

# Azure Sentinel (KQL)
git clone https://github.com/Azure/Azure-Sentinel.git rules/sentinel
```

### Configure Claude Desktop

Add to `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "harris-hawkeye": {
      "command": "node",
      "args": ["<path-to>/security-detections-mcp/dist/index.js"],
      "env": {
        "SIGMA_PATHS": "<path-to>/security-detections-mcp/rules/sigma/rules",
        "SPLUNK_PATHS": "<path-to>/security-detections-mcp/rules/splunk/detections",
        "ELASTIC_PATHS": "<path-to>/security-detections-mcp/rules/elastic/rules",
        "KQL_PATHS": "<path-to>/security-detections-mcp/rules/sentinel/Hunting Queries",
        "STORY_PATHS": "<path-to>/security-detections-mcp/rules/splunk/stories"
      }
    }
  }
}
```

Restart Claude Desktop after configuration. First launch auto-indexes all rules into SQLite (~2 minutes).

### Environment Variables

| Variable | Description | Required |
|---|---|---|
| `SIGMA_PATHS` | Comma-separated paths to Sigma rule directories | Yes |
| `SPLUNK_PATHS` | Comma-separated paths to Splunk ESCU detection directories | Yes |
| `ELASTIC_PATHS` | Comma-separated paths to Elastic rule directories | Yes |
| `KQL_PATHS` | Comma-separated paths to Sentinel KQL directories (auto-discovers sibling `Detections/` and `Solutions/` dirs) | Yes |
| `STORY_PATHS` | Path to Splunk analytic stories | Optional |
| `OTX_API_KEY` | AlienVault OTX API key ([free](https://otx.alienvault.com)) | For OTX tools |
| `MALPEDIA_API_KEY` | Malpedia API key ([free](https://malpedia.caad.fkie.fraunhofer.de)) | For full Malpedia access |

---

## Detection Engineering Skills

Eight Claude Code skills implement the full detection engineering lifecycle. Each skill is a self-contained workflow that calls MCP tools — nothing is hallucinated from training data.

```
Advisory / Threat Report / Vendor Blog / DFIR Writeup
        │
        ├──────────────────────────┐
        ▼                          ▼
┌────────────────────┐  ┌────────────────────┐
│   advisory-ingest  │  │threat-report-parser│  Parse unstructured intel →
│  CISA/vendor → gap │  │  scored rules out  │  scored deployment-ready rules
└────────────────────┘  └────────────────────┘
        │                          │
        └──────────────┬───────────┘
                       ▼
┌────────────────────┐
│  data-source-mapper│  Confirm: do we have the telemetry to detect this?
└────────────────────┘
        │
        ▼
┌────────────────────┐
│  detect-engineer   │  Build: Sigma + KQL + SPL rules grounded in ART + LOLBAS + LOLFarm
└────────────────────┘
        │
        ▼
┌────────────────────┐
│detection-validator │  Prove: ART-mapped test runbook, DEPLOY-READY verdict
└────────────────────┘
        │
        ▼
┌────────────────────┐
│  killchain-synth   │  Correlate: single multi-phase query across all phases
└────────────────────┘
        │
        ▼
┌────────────────────┐
│  coverage-reporter │  Document: hunt cards + optional Word (.docx) export
└────────────────────┘
        │
        ▼
┌────────────────────┐
│navigator-layer-gen │  Visualize: ATT&CK Navigator JSON layers
└────────────────────┘
        │
        ▼
    Production SIEM
```

| Skill | What It Does | Trigger |
|---|---|---|
| **detect-engineer** | Writes production-ready Sigma, KQL, SPL, ESCU YAML, or Elastic TOML rules. LOLBAS is a hard gate — every binary-scoped rule must enumerate all known abuse patterns first. LOLFarm enriches with driver, DLL hijack, RMM, and FP intelligence. 6-dimension validation (Evasion, Fields, Paths, FP, Syntax, LOLFarm). | "Write a detection for X", "Sigma for T1003", "my rule FPs too much" |
| **advisory-ingest** | Parses CISA advisories, vendor reports, DFIR writeups. Extracts T-IDs, CVEs, IOCs, validates against local data, produces prioritized gap table. | "New CISA advisory dropped", "check this report" |
| **threat-report-parser** | Turns unstructured intel (vendor blogs, Red Team writeups, malware analysis, conference talks) into scored, deployment-ready Sigma/KQL/SPL detection rules. Deeper than advisory-ingest — fully operationalizes a report. | "Parse this Mandiant blog into rules", "operationalize this Red Team writeup" |
| **killchain-synth** | Stitches atomic rules into correlated multi-phase queries (KQL let-join, SPL phase-scored, Sigma correlation). Only fires when the full attack sequence is observed on the same host/identity within a time window. | "Correlate these techniques into one alert" |
| **detection-validator** | Maps detection conditions to ART test artifacts, scores field-level coverage, generates executable test runbooks. Issues DEPLOY-READY / DEPLOY-WITH-CAUTION / DO NOT DEPLOY verdict. | "Will this rule actually fire?" |
| **data-source-mapper** | Maps techniques to required MITRE data sources, identifies collection gaps, outputs exact Sysmon XML / audit policy / GPO configuration. | "Do I have the logs needed for T1003?" |
| **coverage-reporter** | Produces structured hunt cards with confidence and priority scores, optionally exports as Word document. | "Generate hunt report", "export to Word" |
| **navigator-layer-gen** | Generates ATT&CK Navigator-compatible JSON layers: coverage heatmaps, actor mapping, gap analysis overlays. | "Generate a navigator layer" |

---

## Data Indexed

### Detection Rules — 12,810

| Source | Rules | Format |
|---|---|---|
| Azure Sentinel (KQL) | 5,051 | KQL/YAML |
| SigmaHQ | 3,108 | YAML |
| Splunk ESCU | 1,966 | YAML |
| Elastic | 1,689 | TOML/YAML |
| Sublime Security | 996 | YAML |

**MITRE technique coverage:** 602 of 835 techniques (72.1%) have at least one detection rule mapped.

### MITRE ATT&CK v18.1

| Entity | Count |
|---|---|
| Techniques | 835 |
| Threat Groups | 187 |
| Malware | 696 |
| Tools | 91 |
| Campaigns | 52 |
| Mitigations | 268 |
| Data Sources | 38 |
| Data Components | 109 |
| Relationships | 20,048 |

### Atomic Red Team — 1,770 Tests

| Platform | Tests |
|---|---|
| Windows | 1,205 |
| Linux | 384 |
| macOS | 245 |
| Cloud (AWS/Azure/GCP) | 42 |
| Container | 19 |

### LOLFarm — 7 Sources

Aggregated Living-Off-The-Land intelligence from [lolol.farm](https://lolol.farm/):

| Source | What It Covers | Seed Entries |
|---|---|---|
| **LOLDrivers** | Vulnerable kernel drivers used in BYOVD attacks (hashes, CVEs, actor attribution) | 10 |
| **HijackLibs** | DLL hijacking opportunities (phantom, sideloading, search order, env variable) | 10 |
| **LOLRMM** | Legitimate RMM tools abused for C2/persistence (executables, network artifacts, registry) | 10 |
| **LoFP** | Known false positives mapped to ATT&CK techniques with suppression logic | 20 |
| **WADComs** | Offensive AD tools and commands (Impacket, BloodHound, Rubeus, Mimikatz, CrackMapExec) | 10 |
| **LOTS** | Legitimate domains/services abused for data exfil and C2 (pastebin, Discord, ngrok, etc.) | 14 |
| **MalAPI** | Windows API calls commonly used by malware (process injection, credential access, MBR wipe) | 12 |

Seed data provides instant offline availability for the most critical entries. Full databases are expandable via GitHub sync.

### Coverage Engine — 138 Telemetry Mappings

Pre-seeded mappings that bridge EventID → MITRE Data Source/Component across 19 event sources: Windows Security, Sysmon, PowerShell, MDE, CrowdStrike, Linux auditd, AWS CloudTrail, Azure AD, and more.

---

## Tools

### Detection Tools (15)

| Tool | Description |
|---|---|
| `search_detections` | Full-text search across all enriched fields (FTS5) |
| `get_detection` | Get full rule details by ID |
| `list_by_mitre` | List detections by ATT&CK technique ID (includes logsource, data_sources, process_names) |
| `list_by_severity` | Filter by severity level |
| `list_by_mitre_tactic` | Filter by ATT&CK tactic |
| `list_by_process_name` | Find rules referencing a specific executable |
| `list_by_cve` | Find rules tagged with a CVE |
| `list_by_logsource` | Filter Sigma rules by logsource (product/category/service) |
| `list_by_data_source` | Find rules by required data source |
| `get_stats` | Detection statistics by source and severity |
| `analyze_coverage` | ATT&CK technique coverage analysis |
| `identify_gaps` | Detection gaps for threat profiles |
| `cve_to_detection` | Generate KQL/SPL/Sigma from CVE ID |
| `convert_yara_to_sigma` | Convert YARA to Sigma (draft — always refine) |
| `convert_sigma_to_kql` | Convert Sigma to KQL for Sentinel |

### MITRE ATT&CK Tools (11)

| Tool | Description |
|---|---|
| `get_threat_group` | APT details, aliases, techniques |
| `search_threat_groups` | Search groups by keyword |
| `get_software` | Malware/tool details with technique mapping |
| `search_software` | Search software by keyword |
| `lookup_mitre_technique` | Full technique details, detection notes, data sources |
| `search_mitre_techniques` | Search techniques by keyword |
| `get_groups_using_technique` | All groups using a specific technique |
| `get_software_using_technique` | All software using a specific technique |
| `get_mitigations` | Defensive controls per technique |
| `get_data_sources` | Required data sources for detection |
| `list_data_sources` | All MITRE data sources with components |

### Atomic Red Team Tools (6)

| Tool | Description |
|---|---|
| `art_get_tests` | All ART tests for a technique (with platform filter) |
| `art_search` | Full-text search across 1,770+ tests |
| `art_get_test` | Full test details by GUID |
| `art_validate_technique` | Cross-reference ART tests against detection rules |
| `art_get_stats` | Index statistics |
| `art_coverage_report` | Batch coverage validation across technique sets |

### LOLFarm Tools (12)

| Tool | Description |
|---|---|
| `lookup_loldriver` | Look up a vulnerable driver by name or SHA256 hash |
| `lookup_hijacklib` | Look up DLL hijacking opportunities by DLL or executable name |
| `lookup_lolrmm` | Look up RMM tool abuse details (executables, network artifacts, registry) |
| `lookup_lofp` | Get known false positives for a technique ID with suppression logic |
| `lookup_wadcom` | Look up offensive AD tool/command details |
| `lookup_lots_domain` | Check if a domain is a known legitimate service abused for C2/exfil |
| `lookup_malapi` | Look up a Windows API for malware usage context |
| `search_lolfarm` | Unified cross-source search across all 7 LOLFarm databases |
| `list_loldrivers` | List all indexed vulnerable drivers |
| `list_lolrmm` | List all indexed RMM tools |
| `list_hijacklibs` | List all indexed DLL hijack opportunities |
| `get_lolfarm_context` | **Key tool** — get all LOLFarm intelligence for a technique ID (queries all 7 tables, returns only sources with data) |

### Threat Intelligence Tools (59)

| Category | Tools |
|---|---|
| **Core Intel** (7) | `lookup_mitre_technique`, `search_mitre_techniques`, `lookup_lolbas`, `list_lolbas`, `check_cisa_kev`, `get_threat_profile`, `analyze_ioc` |
| **abuse.ch** (12) | `urlhaus_lookup_url/host/tag`, `threatfox_search_ioc/family/tag`, `threatfox_get_recent_iocs`, `bazaar_lookup_hash`, `bazaar_search_family/tag`, `bazaar_get_recent_samples`, `bazaar_get_imphash_siblings` |
| **AlienVault OTX** (7) | `otx_pivot_ip/domain/hash/url`, `otx_search_actor`, `otx_get_pulse_iocs`, `otx_subscribed_feed` |
| **Government/CERT** (10) | `cisa_search_advisories`, `ncsc_uk_search`, `nsa_search_advisories`, `fbi_flash_search`, `cert_eu_search`, `anssi_search`, `jpcert_search`, `acsc_search`, `cccs_search`, `govt_joint_advisory_search` |
| **Correlation Engine** (4) | `ti_multi_source_ttp_lookup`, `ti_actor_full_profile`, `ti_hunt_package`, `ti_daily_brief` |
| **Vulnerability Intel** (10) | `nvd_cve_lookup`, `epss_score_lookup/bulk_check`, `project_zero_search`, `exploit_db_search`, `rapid7_search`, `qualys_search`, `tenable_search`, `zdi_search`, `google_tag_search` |
| **Malware Research** (9) | `malpedia_search/actor_profile/family_profile`, `anyrun_trending`, `bleeping_search`, `malwarebytes_search`, `sans_isc_search`, `vx_underground_search`, `misp_warninglist_check` |

### Coverage Engine Tools (6)

| Tool | Description |
|---|---|
| `coverage_ingest_log` | Parse raw logs or structured input, map to MITRE data sources |
| `coverage_assess_session` | Full ATT&CK matrix assessment — classifies every technique into 4 states |
| `coverage_gaps_detail` | Detailed gap report with missing data sources and remediation |
| `coverage_compare` | Compare before/after sessions — shows improvement |
| `coverage_recommend` | Pareto-optimal log source recommendations ranked by gap closure |
| `coverage_list_mappings` | View all 138 telemetry mappings and session history |

### Knowledge Graph Tools (8)

| Tool | Description |
|---|---|
| `create_entity` | Create entity in knowledge graph |
| `search_entities` | Search entities by name/description |
| `create_relation` | Create relation between entities |
| `log_decision` | Log analytical decision with reasoning |
| `get_decisions` | Retrieve logged decisions |
| `add_learning` | Store insight/learning from analysis |
| `get_learnings` | Get learnings by topic |
| `get_knowledge_summary` | Summary of knowledge graph contents |

### Sublime Security & Report Generator

| Tool | Description |
|---|---|
| `sublime_search` | Search Sublime Security email detection rules |
| `sublime_get_rule` | Get full Sublime rule details |
| `sublime_get_stats` | Sublime index statistics |
| `sublime_sync` | Sync Sublime rules from GitHub |
| `generate_hunt_report` | Generate threat hunt report (Word .docx export) |

---

## Prompts (6)

| Prompt | Description | Parameters |
|---|---|---|
| `analyze-technique` | Analyze a MITRE ATT&CK technique | `technique_id` |
| `threat-hunt` | Generate threat hunting plan | `profile` |
| `coverage-report` | Generate detection coverage report | `focus` |
| `investigate-ioc` | Investigate an indicator of compromise | `ioc` |
| `detection-review` | Review and analyze a detection rule | `detection_id` |
| `yara-to-sigma` | Convert YARA rule to Sigma | `yara_rule` |

---

## Example Workflows

### Write a Detection Rule
```
"Write a Sigma rule for LSASS credential dumping"
"KQL detection for T1059.001 PowerShell abuse — MDE, no Sysmon"
"ESCU YAML for scheduled task persistence"
"Elastic TOML rule for lateral movement via WMI"
"My rule FPs on SCCM — help me tune it"
```

### Hunt an APT
```
"Full profile on APT29 — what's my coverage?"
"Generate detections for all Volt Typhoon techniques I'm missing"
"Kill-chain correlation query for Lazarus Group attack sequence"
```

### Respond to an Advisory
```
"Parse this CISA advisory and show me coverage gaps"
"Do I have the telemetry to detect these techniques?"
"Generate a navigator layer showing my gaps vs this threat"
```

### Assess Coverage
```
"Ingest this Windows Event 4688 log and map it to MITRE"
"What log sources should I enable to close the most gaps?"
"Compare my coverage before and after adding Sysmon"
```

### Investigate IOCs
```
"Look up this hash in MalwareBazaar and ThreatFox"
"Pivot on this IP across OTX"
"Is this domain on any MISP warninglist?"
```

---

## Project Structure

```
security-detections-mcp/
├── src/
│   ├── index.ts                    # Entry point — schema init, auto-indexing, server start
│   ├── server.ts                   # MCP server setup
│   ├── indexer.ts                  # Detection rule indexer (enriched fields, FTS5)
│   ├── db/
│   │   ├── connection.ts           # SQLite (sql.js WASM) + FTS5 + migrations
│   │   ├── threat-intel.ts         # Threat intel schema (LOLBAS, CISA KEV)
│   │   ├── knowledge.ts            # Knowledge graph schema
│   │   ├── mitre-attack.ts         # MITRE ATT&CK STIX v18.1 parser
│   │   ├── atomic-red-team.ts      # ART repo sync + YAML indexer
│   │   ├── coverage-engine.ts      # Coverage engine + 138 telemetry mappings
│   │   ├── lolfarm.ts              # LOLFarm 7-table schema + query functions
│   │   └── sublime-rules.ts        # Sublime Security rules
│   ├── handlers/
│   │   ├── tools.ts                # Tool dispatch handler
│   │   ├── prompts.ts              # Prompt definitions (6)
│   │   └── resources.ts            # Resource handler (stats, coverage, LOLFarm)
│   └── tools/
│       ├── registry.ts             # Tool registry + defineTool pattern
│       ├── index.ts                # Tool aggregation — registerAllTools()
│       ├── detections/             # 15 detection search/analysis tools
│       ├── threat-intel/           # 59 TI tools
│       │   ├── index.ts            # Core: abuse.ch, OTX, LOLBAS, IOC analysis
│       │   ├── government/         # CISA, FBI, NSA, NCSC-UK, CERT-EU, ANSSI, JPCERT, ACSC, CCCS
│       │   ├── correlation/        # Multi-source correlation engine
│       │   ├── exploit/            # NVD, EPSS, Exploit-DB, Rapid7, Qualys, Tenable, ZDI
│       │   └── community/          # Malpedia, ANY.RUN, SANS ISC, BleepingComputer
│       ├── mitre-attack/           # 11 MITRE ATT&CK query tools
│       ├── atomic-red-team/        # 6 ART validation tools
│       ├── coverage-engine/        # 6 coverage assessment tools
│       │   ├── parser.ts           # Log parser (XML, JSON, auditd, CEF, k=v)
│       │   ├── mapper.ts           # Telemetry → MITRE data component mapper
│       │   └── assessor.ts         # Graph traversal + 4-state classifier
│       ├── lolfarm/                # 12 LOLFarm tools
│       │   ├── index.ts            # Tool definitions + lazy seed loading
│       │   └── seed.ts             # Curated seed data (86 entries across 7 sources)
│       ├── knowledge/              # 8 knowledge graph tools
│       ├── sublime/                # Sublime Security rule tools
│       └── report-generator/       # Hunt report generator (Word .docx)
├── rules/                          # Downloaded detection rule repos
│   ├── sigma/                      # SigmaHQ
│   ├── splunk/                     # Splunk ESCU + analytic stories
│   ├── elastic/                    # Elastic detection rules + MITRE STIX bundle
│   └── sentinel/                   # Azure Sentinel KQL
├── dist/                           # Compiled JavaScript
├── package.json
├── tsconfig.json
└── README.md

~/.claude/skills/                   # Claude Code skills (per-user, not in repo)
├── detect-engineer/
│   ├── SKILL.md                    # 7-step pipeline, 5-platform output, LOLBAS gate, LOLFarm validation
│   └── references/                 # sigma-template, fp-*, kql-patterns, spl-patterns, validation-rubric, etc.
├── advisory-ingest/
├── threat-report-parser/
├── killchain-synth/
├── detection-validator/
├── data-source-mapper/
├── coverage-reporter/
└── navigator-layer-gen/
```

---

## How the detect-engineer Skill Works

The detect-engineer skill is the core rule authoring pipeline. When you ask "write a detection for X", it runs a 7-step process:

1. **Classify** — New rule, fix/tune, convert, or validate? Which platform(s)?
2. **Coverage assessment** — Parallel queries: `list_by_mitre`, `search_entities`, `get_learnings`, `get_lolfarm_context`, and `lookup_lolbas` (for binaries)
3. **Coverage gate** — Score existing coverage. ≥95% = refine path. <95% = build path. Zero = full build.
4. **Author** — Behavioral invariant analysis (what's hard for the attacker to change?), narrowing test (would an admin trigger this?), evasion test (can the attacker bypass by renaming one thing?). FP filters sourced per-logsource from reference files.
5. **Validate** — 6-dimension scoring: Evasion, Fields, Paths, FP, Syntax, LOLFarm. Composite < 3.0 triggers iteration.
6. **Output** — Structured format with coverage score, validation matrix, FP documentation, data requirements, and gaps.
7. **Persist** — Entities, learnings, and decisions saved to knowledge graph for future sessions.

**Platform disambiguation:** "Splunk"/"SPL" → bare SPL query. "ESCU"/"security_content" → full YAML with tstats + RBA + tests. "Elastic TOML" → `.toml` rule file. "KQL"/"Sentinel" → bare KQL. Default = Sigma only.

---

## Technology

- **Runtime:** Node.js 18+ with TypeScript (ES modules)
- **Database:** [sql.js](https://github.com/sql-js/sql.js) — SQLite compiled to WebAssembly, runs in-process with no native dependencies
- **Protocol:** [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) over stdio
- **Indexing:** Auto-indexes on first startup, incremental re-index on source changes
- **Storage:** `~/.cache/security-detections-mcp/detections.db` (~97 MB)

---

## License

MIT
