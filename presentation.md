# Security Detections MCP
### AI-Powered Security Detection Management Platform
#### Management Briefing

---

## The Problem

- Security teams manage **thousands of detection rules** across multiple SIEM platforms (Splunk, Elastic, Microsoft Sentinel)
- Rules are scattered across different repositories, formats, and tools
- No unified way to search, analyze gaps, or map detections to the MITRE ATT&CK framework
- Tribal knowledge (why a detection was written, what was tried) gets lost when analysts leave
- Gap analysis is manual, time-consuming, and error-prone

---

## The Solution

**Security Detections MCP** is an AI-integrated platform that consolidates detection rules from 4 major sources into a single searchable interface, with built-in threat intelligence and knowledge management.

It plugs directly into Claude (AI assistant) via the **Model Context Protocol (MCP)**, enabling analysts to query detections using natural language.

---

## What's Inside: Detection Rules

| Source | Rules | Platform |
|--------|------:|----------|
| SigmaHQ | 3,108 | Platform-agnostic (translatable to any SIEM) |
| Elastic | 1,693 | Elastic Security / SIEM |
| Microsoft Sentinel (KQL) | 1,293 | Azure Sentinel / Microsoft Defender |
| **Total Indexed** | **6,094** | |

### By Severity

| Critical | High | Medium | Low | Informational |
|---------:|-----:|-------:|----:|--------------:|
| 87 | 1,794 | 3,428 | 760 | 25 |

---

## MITRE ATT&CK Coverage

The platform maps detections to **421 unique MITRE ATT&CK techniques**.

### Top Covered Techniques

| Technique | Description | Detections |
|-----------|-------------|----------:|
| T1059 | Command & Scripting Interpreter | 312 |
| T1566 | Phishing | 286 |
| T1078 | Valid Accounts | 224 |
| T1218 | System Binary Proxy Execution | 184 |
| T1059.001 | PowerShell | 177 |
| T1562 | Impair Defenses | 165 |
| T1098 | Account Manipulation | 130 |
| T1562.001 | Disable or Modify Tools | 125 |
| T1027 | Obfuscated Files or Information | 121 |
| T1112 | Modify Registry | 115 |

---

## Key Capabilities

### 1. Unified Detection Search
- Search **6,094 rules** by keyword, severity, MITRE technique, or source
- Get full rule details including detection logic, references, and metadata
- Filter across Sigma, Elastic, and KQL formats in one query

### 2. Coverage & Gap Analysis
- Automated MITRE ATT&CK coverage reports across all detection sources
- Pre-built threat profiles: **Ransomware, APT, Insider Threat, Web Attack, Supply Chain**
- Identifies which techniques have zero detection coverage

### 3. Threat Intelligence (Built-in)
- **MITRE ATT&CK** technique lookup and search
- **LOLBAS** (Living Off The Land Binaries) abuse database
- **CISA KEV** (Known Exploited Vulnerabilities) checking
- **IOC Analysis** - automatic classification of hashes, IPs, domains, URLs

### 4. Knowledge Graph (Tribal Knowledge)
- Log analytical decisions with reasoning ("why did we write this detection?")
- Capture learnings and insights by topic
- Map relationships between techniques, actors, tools, and detections
- Prevents knowledge loss when team members transition

---

## How It Works

```
Analyst asks a question in natural language
        |
        v
   Claude (AI) interprets the request
        |
        v
   MCP Server processes via 25 specialized tools
        |
        v
   SQLite database with 6,094 indexed rules
        |
        v
   Structured answer returned to analyst
```

### Example Interactions

**Analyst:** "What detections do we have for PowerShell abuse?"
> Returns all rules mapped to T1059.001 across Sigma, Elastic, and KQL

**Analyst:** "Where are our detection gaps for ransomware?"
> Analyzes coverage against ransomware threat profile, highlights missing techniques

**Analyst:** "Is CVE-2021-44228 in the CISA KEV list?"
> Checks the Known Exploited Vulnerabilities catalog instantly

**Analyst:** "Log that we decided to prioritize credential access detections because of recent incidents"
> Saves the decision with reasoning for future reference

---

## Technical Architecture

| Component | Technology |
|-----------|------------|
| Language | TypeScript |
| Runtime | Node.js 18+ |
| Database | SQLite (embedded, zero-config) |
| Protocol | Model Context Protocol (MCP) |
| Integration | Claude Desktop / Claude Code |
| Rule Formats | YAML (Sigma, Splunk), TOML (Elastic), YAML (KQL) |

**Codebase:** ~3,250 lines of TypeScript across 14 source files
**Tools:** 25 tools across 3 modules (Detection, Threat Intel, Knowledge)

---

## Value Proposition

| Benefit | Impact |
|---------|--------|
| **Centralized rule management** | No more switching between 4 different repos and formats |
| **Natural language queries** | Analysts ask questions instead of writing complex searches |
| **Automated gap analysis** | Minutes instead of days to identify coverage blind spots |
| **Knowledge retention** | Tribal knowledge survives team transitions |
| **MITRE ATT&CK alignment** | Every detection mapped to the industry standard framework |
| **Zero infrastructure cost** | Runs locally, embedded database, no cloud dependencies |

---

## Current Status

- **6,094 detection rules** indexed and searchable
- **421 MITRE techniques** covered
- **25 tools** fully operational
- **5 pre-built workflows** for common security tasks
- Integrated with Claude Desktop for immediate use

---

## Next Steps / Roadmap Ideas

1. **Add Splunk ESCU rules** to the index (1,982 additional rules available but not yet indexed)
2. **Expand threat profiles** for industry-specific coverage analysis
3. **Team-wide deployment** via shared database or API endpoint
4. **Automated rule updates** - scheduled pulls from upstream rule repositories
5. **Custom detection authoring** - create and validate new rules within the platform
6. **Dashboard/reporting** - export coverage reports for compliance and audit

---

## Summary

Security Detections MCP transforms how security teams interact with their detection library:

- **From** fragmented rule repositories **to** a unified, searchable platform
- **From** manual gap analysis **to** automated MITRE ATT&CK coverage reports
- **From** lost tribal knowledge **to** persistent decision logs and learnings
- **From** complex query languages **to** natural language conversations with AI

**6,094 rules. 421 techniques. 25 tools. One interface.**
