# 🏠 House of Hunting MCP

**Your Security Detection Engineering Command Center for Claude Desktop**

A powerful Model Context Protocol (MCP) server that provides detection engineering, threat intelligence from 15+ sources, CVE-to-detection generation, YARA conversion, MITRE ATT&CK enrichment, and knowledge management.

![Tools](https://img.shields.io/badge/Tools-122-blue)
![Prompts](https://img.shields.io/badge/Prompts-6-green)
![Detections](https://img.shields.io/badge/Detections-8000+-orange)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-v18.1-red)
![TI Sources](https://img.shields.io/badge/TI_Sources-15+-purple)

---

## ✨ Features

### 🔍 Detection Management
- **Multi-source search** - Query Sigma, Splunk ESCU, Elastic, and KQL detections from a single interface
- **MITRE mapping** - Find detections by ATT&CK technique ID
- **Coverage analysis** - Identify detection gaps by threat profile
- **Format conversion** - Convert between Sigma, KQL, and YARA

### 🚨 CVE to Detection
- Input any CVE ID → Get ready-to-use detection queries
- Auto-fetches CVE details from NVD + EPSS scores
- Maps to MITRE ATT&CK techniques
- Generates **KQL**, **Splunk SPL**, and **Sigma** rules
- Includes threat hunting hypotheses and response actions

### 🔄 Rule Converters
- **YARA to Sigma** - Convert YARA rules to Sigma detection format
- **Sigma to KQL** - Convert Sigma rules for Azure Sentinel/Microsoft Defender

### 🛡️ Threat Intelligence (93 Tools, 15+ Sources)
- **Vendor Intel** - Mandiant, CrowdStrike, Microsoft, Elastic, Unit42, Kaspersky
- **Government/CERT** - CISA, FBI, NSA, NCSC-UK, CERT-EU, ANSSI, JPCERT, ACSC, CCCS
- **Research Firms** - DFIR Report, Red Canary, Volexity, Huntress, Dragos, NCC Group
- **abuse.ch** - URLhaus, ThreatFox, MalwareBazaar
- **AlienVault OTX** - IOC pivoting, pulse intelligence, actor search
- **Vulnerability Intel** - NVD, EPSS, Project Zero, Exploit-DB, Rapid7, Qualys, Tenable, ZDI
- **Malware Research** - Malpedia, ANY.RUN, VX-Underground, Google TAG

### 🎯 MITRE ATT&CK (Full STIX v18.1)
- **187 Threat Groups** - APT details, aliases, techniques used
- **787 Software** - Malware (696) + Tools (91) with technique mapping
- **835 Techniques** - Full descriptions, mitigations, data sources
- **52 Campaigns** - Named operations with timelines
- **268 Mitigations** - Defensive controls per technique
- **20,048 Relationships** - Group→Technique, Software→Technique mappings

### 🧠 Knowledge Graph
- **Entity management** - Create and link security entities
- **Decision logging** - Capture analytical decisions with reasoning
- **Learning capture** - Store insights and tribal knowledge
- **Relationship mapping** - Connect techniques, detections, and threats

---

## 📊 Data Indexed

### Detection Rules (~8,000+)

| Source | Rules | Format |
|--------|-------|--------|
| **SigmaHQ** | ~3,110 | YAML |
| **Splunk ESCU** | ~1,966 | YAML |
| **Elastic** | ~1,693 | TOML |
| **Azure Sentinel** | ~1,297 | KQL/YAML |

### MITRE ATT&CK v18.1

| Entity Type | Count |
|-------------|-------|
| Techniques | 835 |
| Threat Groups | 187 |
| Malware | 696 |
| Tools | 91 |
| Campaigns | 52 |
| Mitigations | 268 |
| Data Sources | 38 |
| Data Components | 109 |
| Relationships | 20,048 |

---

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Claude Desktop

### Installation

```bash
cd C:\Users\harsh\OneDrive\Desktop\security-detections-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

### Claude Desktop Configuration

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "house-of-hunting": {
      "command": "node",
      "args": ["C:\\Users\\harsh\\OneDrive\\Desktop\\security-detections-mcp\\dist\\index.js"],
      "env": {
        "SIGMA_PATHS": "C:\\Users\\harsh\\OneDrive\\Desktop\\security-detections-mcp\\rules\\sigma\\rules",
        "SPLUNK_PATHS": "C:\\Users\\harsh\\OneDrive\\Desktop\\security-detections-mcp\\rules\\splunk\\detections",
        "ELASTIC_PATHS": "C:\\Users\\harsh\\OneDrive\\Desktop\\security-detections-mcp\\rules\\elastic\\rules",
        "KQL_PATHS": "C:\\Users\\harsh\\OneDrive\\Desktop\\security-detections-mcp\\rules\\sentinel\\Hunting Queries"
      }
    }
  }
}
```

Restart Claude Desktop after configuration.

---

## 🛠️ Tools (122)

### Detection Tools (10)

| Tool | Description |
|------|-------------|
| `search_detections` | Search detections by keyword across all sources |
| `get_detection` | Get full details of a detection by ID |
| `list_by_mitre` | List detections by MITRE ATT&CK technique ID |
| `list_by_severity` | List detections filtered by severity level |
| `get_stats` | Get detection statistics (counts by source/severity) |
| `analyze_coverage` | Analyze MITRE ATT&CK technique coverage |
| `identify_gaps` | Find detection gaps for threat profiles |
| `cve_to_detection` | Generate KQL/Splunk/Sigma rules from CVE ID |
| `convert_yara_to_sigma` | Convert YARA rules to Sigma format |
| `convert_sigma_to_kql` | Convert Sigma rules to KQL for Sentinel |

### MITRE ATT&CK Tools (11)

| Tool | Description |
|------|-------------|
| `get_threat_group` | Get APT details (aliases, techniques, description) |
| `search_threat_groups` | Search groups by keyword (name, description, aliases) |
| `get_software` | Get malware/tool details (Cobalt Strike, Mimikatz, etc.) |
| `search_software` | Search malware and tools by keyword |
| `get_mitigations` | Get mitigations for a specific technique |
| `get_data_sources` | Get required data sources/logs for technique detection |
| `list_campaigns` | List MITRE ATT&CK campaigns |
| `get_groups_using_technique` | Find all groups that use a specific technique |
| `get_software_using_technique` | Find all software that uses a specific technique |
| `get_mitre_attack_stats` | Get statistics about indexed MITRE data |
| `list_data_sources` | List all MITRE data sources with components |

### Threat Intelligence Tools (93)

#### Core Intel (7)
`lookup_mitre_technique`, `search_mitre_techniques`, `lookup_lolbas`, `list_lolbas`, `check_cisa_kev`, `get_threat_profile`, `analyze_ioc`

#### abuse.ch (12)
`urlhaus_lookup_url`, `urlhaus_lookup_host`, `urlhaus_lookup_tag`, `threatfox_search_ioc`, `threatfox_search_family`, `threatfox_search_tag`, `threatfox_get_recent_iocs`, `bazaar_lookup_hash`, `bazaar_search_family`, `bazaar_search_tag`, `bazaar_get_recent_samples`, `bazaar_get_imphash_siblings`

#### AlienVault OTX (8)
`otx_pivot_ip`, `otx_pivot_domain`, `otx_pivot_hash`, `otx_pivot_url`, `otx_search_actor`, `otx_get_pulse_iocs`, `otx_subscribed_feed`, `pivot_expand_iocs`

#### Vendor Reports (12)
`mandian
t_search_reports`, `mandiant_fetch_report`, `microsoft_search_reports`, `microsoft_fetch_report`, `crowdstrike_search_reports`, `crowdstrike_fetch_report`, `elastic_search_reports`, `elastic_fetch_report`, `unit42_search_reports`, `unit42_fetch_report`, `kaspersky_search_reports`, `kaspersky_fetch_report`

#### Government/CERT (12)
`cisa_search_advisories`, `ncsc_uk_search`, `nsa_search_advisories`, `fbi_flash_search`, `cert_eu_search`, `anssi_search`, `jpcert_search`, `acsc_search`, `cccs_search`, `govt_joint_advisory_search`

#### Research Firms (20)
`dfir_report_search_reports`, `dfir_report_fetch_report`, `red_canary_search_reports`, `red_canary_fetch_report`, `volexity_search_reports`, `volexity_fetch_report`, `huntress_search_reports`, `huntress_fetch_report`, `dragos_search_reports`, `dragos_fetch_report`, `ncc_group_search_reports`, `ncc_group_fetch_report`, `withsecure_search_reports`, `withsecure_fetch_report`, `intezer_search_reports`, `intezer_fetch_report`, `sekoia_search_reports`, `sekoia_fetch_report`, `blackberry_search_reports`, `blackberry_fetch_report`

#### TI Orchestration (5)
`ti_multi_source_ttp_lookup`, `ti_actor_full_profile`, `ti_hunt_package`, `ti_report_ingest`, `ti_daily_brief`

#### Vulnerability Intelligence (9)
`epss_score_lookup`, `epss_bulk_check`, `nvd_cve_lookup`, `project_zero_search`, `exploit_db_search`, `rapid7_search`, `qualys_search`, `tenable_search`, `zdi_search`

#### Malware Research (10)
`google_tag_search`, `malpedia_search`, `malpedia_actor_profile`, `malpedia_family_profile`, `sans_isc_search`, `anyrun_trending`, `bleeping_search`, `malwarebytes_search`, `vx_underground_search`, `misp_warninglist_check`

### Knowledge Graph Tools (8)

| Tool | Description |
|------|-------------|
| `create_entity` | Create entity in knowledge graph |
| `search_entities` | Search entities by name/description |
| `create_relation` | Create relation between entities |
| `log_decision` | Log analytical decision (tribal knowledge) |
| `get_decisions` | Retrieve logged decisions |
| `add_learning` | Add insight/learning from analysis |
| `get_learnings` | Get learnings by topic |
| `get_knowledge_summary` | Summary of knowledge graph contents |

---

## 💬 Prompts (6)

| Prompt | Description | Parameters |
|--------|-------------|------------|
| `analyze-technique` | Analyze a MITRE ATT&CK technique | `technique_id` |
| `threat-hunt` | Generate threat hunting plan | `profile` |
| `coverage-report` | Generate detection coverage report | `focus` |
| `investigate-ioc` | Investigate an indicator of compromise | `ioc` |
| `detection-review` | Review and analyze a detection rule | `detection_id` |
| `yara-to-sigma` | Convert YARA rule to Sigma | `yara_rule` |

---

## 🎯 Elite Detection Engineering Workflows

### Daily Threat Intel Routine
```
1. ti_daily_brief                    → What's new today?
2. anyrun_trending                   → Trending malware
3. cisa_search_advisories            → Government alerts
4. FOR EACH high-priority item:
   - ti_report_ingest [report]       → Extract IOCs + TTPs
   - list_by_mitre [technique]       → Do we detect this?
   - identify_gaps                   → What's missing?
```

### CVE Response Workflow
```
1. nvd_cve_lookup "CVE-XXXX-XXXXX"   → CVE details
2. epss_score_lookup "CVE-XXXX"      → Exploitation probability
3. check_cisa_kev "CVE-XXXX"         → In KEV? Deadline?
4. exploit_db_search "CVE-XXXX"      → Public PoC?
5. cve_to_detection "CVE-XXXX"       → Generate detections
```

### APT Hunt Workflow
```
1. get_threat_group "APT29"          → Techniques used
2. ti_actor_full_profile "APT29"     → Cross-source intel
3. FOR EACH technique:
   - list_by_mitre [technique]       → Existing detections
   - get_mitigations [technique]     → Controls
   - get_data_sources [technique]    → Required logs
4. identify_gaps                     → Missing coverage
5. Generate detections for gaps
```

### IOC Investigation Workflow
```
1. analyze_ioc [ioc]                 → Type detection
2. pivot_expand_iocs [ioc]           → Expand across sources
3. otx_pivot_* [ioc]                 → OTX enrichment
4. threatfox_search_ioc [ioc]        → ThreatFox data
5. bazaar_lookup_hash [hash]         → Sample analysis
6. create_entity + create_relation   → Knowledge graph
```

### Malware Family Analysis
```
1. malpedia_family_profile [family]  → Family details
2. threatfox_search_family [family]  → Active C2s
3. bazaar_search_family [family]     → Recent samples
4. get_software [malware]            → MITRE techniques
5. search_detections [family]        → Existing rules
```

---

## 📖 Usage Examples

### Search for Detections
```
"Search for detections related to mimikatz"
"Find all detections for MITRE technique T1003"
"Show me high severity ransomware detections"
```

### Generate Detections from CVE
```
"Generate detections for CVE-2024-21412"
"Create detection rules for Log4Shell CVE-2021-44228"
```

### MITRE ATT&CK Queries
```
"What techniques does APT29 use?"
"How do I mitigate T1059.001?"
"What data sources do I need to detect T1021?"
"Which groups use Cobalt Strike?"
```

### Threat Intelligence
```
"Get a full profile on Lazarus Group"
"What's trending in malware today?"
"Search CISA advisories for Volt Typhoon"
"Look up this hash in MalwareBazaar"
```

### Knowledge Management
```
"Log a decision: We tuned rule X because of false positives"
"Add a learning: Encoded PowerShell often indicates malware"
"Show me recent analytical decisions"
```

---

## 📁 Project Structure

```
security-detections-mcp/
├── src/
│   ├── index.ts                    # Entry point
│   ├── server.ts                   # MCP server setup
│   ├── indexer.ts                  # Detection rule indexer
│   ├── db/
│   │   ├── connection.ts           # SQLite database (sql.js)
│   │   ├── threat-intel.ts         # Threat intel schema
│   │   ├── knowledge.ts            # Knowledge graph schema
│   │   └── mitre-attack.ts         # MITRE ATT&CK STIX parser
│   ├── handlers/
│   │   ├── tools.ts                # Tool handler
│   │   ├── prompts.ts              # Prompt definitions (6)
│   │   └── resources.ts            # Resource handler
│   └── tools/
│       ├── detections/             # Detection tools (10)
│       ├── threat-intel/           # Threat intel tools (93)
│       │   ├── index.ts            # Core TI tools
│       │   ├── abusech.ts          # URLhaus, ThreatFox, Bazaar
│       │   ├── otx.ts              # AlienVault OTX
│       │   ├── vendors.ts          # Vendor report tools
│       │   ├── government.ts       # Govt/CERT tools
│       │   └── research.ts         # Research firm tools
│       ├── mitre-attack/           # MITRE ATT&CK tools (11)
│       └── knowledge/              # Knowledge graph tools (8)
├── rules/                          # Downloaded detection rules
│   ├── sigma/                      # SigmaHQ rules
│   ├── splunk/                     # Splunk ESCU
│   ├── elastic/                    # Elastic detection rules
│   │   └── detection_rules/etc/    # MITRE ATT&CK STIX bundle
│   └── sentinel/                   # Azure Sentinel KQL
├── dist/                           # Compiled JavaScript
├── package.json
├── tsconfig.json
└── README.md
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SIGMA_PATHS` | Path to Sigma rules | Yes |
| `SPLUNK_PATHS` | Path to Splunk ESCU | Yes |
| `ELASTIC_PATHS` | Path to Elastic rules | Yes |
| `KQL_PATHS` | Path to Sentinel KQL | Yes |
| `OTX_API_KEY` | AlienVault OTX API key | For OTX tools |

### API Keys

| Service | Required | How to Get |
|---------|----------|------------|
| AlienVault OTX | For OTX tools | https://otx.alienvault.com (free) |
| ThreatFox | No | Public API |
| MalwareBazaar | No | Public API |
| URLhaus | No | Public API |

---

## 📚 Built-in Reference Data

### MITRE ATT&CK Techniques (20)
T1059, T1059.001, T1059.003, T1055, T1003, T1003.001, T1547, T1547.001, T1566, T1566.001, T1021, T1021.001, T1486, T1490, T1078, T1190, T1027, T1070, T1053, T1218

### LOLBAS Binaries (8)
certutil.exe, mshta.exe, regsvr32.exe, rundll32.exe, powershell.exe, wmic.exe, bitsadmin.exe, cscript.exe

### Threat Profiles (5)
Ransomware, APT, Insider Threat, Web Attack, Supply Chain

---

## 🔧 Development

```bash
# Build
npm run build

# Watch mode (if configured)
npm run dev

# Run server directly
node dist/index.js
```

---

## 🐛 Troubleshooting

### MCP not showing in Claude Desktop
1. Verify config path: `%APPDATA%\Claude\claude_desktop_config.json`
2. Check JSON syntax (no trailing commas, proper escaping)
3. Restart Claude Desktop completely
4. Check Settings → Developer for MCP status

### Rules not indexing
1. Verify rule directories exist
2. Check environment variables in config
3. Run server manually to see errors: `node dist/index.js`

### Reset database (force re-index)
```powershell
Remove-Item "$env:LOCALAPPDATA\Temp\security-detections-mcp\detections.db" -Force
```

### Build errors
```bash
rm -rf dist node_modules
npm install
npm run build
```

---

## 🙏 Credits

- Detection rules: [SigmaHQ](https://github.com/SigmaHQ/sigma), [Splunk](https://github.com/splunk/security_content), [Elastic](https://github.com/elastic/detection-rules), [Azure Sentinel](https://github.com/Azure/Azure-Sentinel)
- Inspired by [MHaggis/Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP)
- Built with [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/sdk)

---

## 📄 License

MIT

---

**Made with ❤️ for the security community**

```
    __  __                        ____  ____  __  __            __  _            
   / / / /___  __  __________    / __ \/ __/ / / / /_  ______  / /_(_)___  ____ _
  / /_/ / __ \/ / / / ___/ _ \  / / / / /_  / /_/ / / / / __ \/ __/ / __ \/ __ `/
 / __  / /_/ / /_/ (__  )  __/ / /_/ / __/ / __  / /_/ / / / / /_/ / / / / /_/ / 
/_/ /_/\____/\__,_/____/\___/  \____/_/   /_/ /_/\__,_/_/ /_/\__/_/_/ /_/\__, /  
                                                                        /____/   
```

Co-Authored-By: Warp <agent@warp.dev>
