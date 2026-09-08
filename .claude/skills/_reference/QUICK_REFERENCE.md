# Skills Quick Reference Card

## Configure for Your SIEM

Before using skills, set your target SIEM platform. This affects detection output format, field names, and validation methods.

### Quick Setup (3 steps)

```bash
# 1. Set your SIEM in agents/.env (or export in your shell)
export SIEM_PLATFORM=sentinel   # splunk | sentinel | elastic | sigma

# 2. Set your detection repo path
export SECURITY_CONTENT_PATH=./my-detections

# 3. Set your validation tool (or use defaults)
export VALIDATION_TOOL="az monitor log-analytics query"
```

### SIEM-Specific Defaults

| SIEM_PLATFORM | Detection Format | Validation Command | Key Field Names |
|---------------|-----------------|-------------------|-----------------|
| `splunk` | SPL YAML | `contentctl validate` | `process_name`, `dest`, `user`, `src_ip` |
| `sentinel` | KQL | `az monitor log-analytics query` | `FileName`, `DeviceName`, `AccountName` |
| `elastic` | EQL / TOML | `detection_rules validate-rule` | `process.name`, `host.name`, `user.name` |
| `sigma` | Sigma YAML | `sigma convert -t <backend>` | `Image`, `Computer`, `User` |

### Validation per SIEM

| SIEM | Validate a Rule | Convert/Test |
|------|----------------|--------------|
| Splunk | `cd $SECURITY_CONTENT_PATH && source venv/bin/activate && contentctl validate` | Run in Splunk UI |
| Sentinel | `az monitor log-analytics query --workspace <name> --analytics-query "$(cat rule.kql)"` | Run in Sentinel > Logs |
| Elastic | `python -m detection_rules validate-rule path/to/rule.toml` | Run in Kibana Dev Tools |
| Sigma | `sigma convert -t splunk -p sysmon rule.yml` | Convert, then test in target SIEM |

See [docs/E2E-TESTING-GUIDE.md](../../docs/E2E-TESTING-GUIDE.md) for full setup instructions.

---

## Skill Selection Guide

| Task | Skill to Use |
|------|-------------|
| Analyzing a threat report | `threat-report-parser` → `cti-detection-engineer` |
| Creating a detection | `detection-yaml-engineer` + `data-source-mapper` |
| Reviewing a detection | `detection-reviewer` |
| Testing a detection | `detection-test-engineer` + `atomic-red-team-testing` |
| Checking coverage | `cti-detection-engineer` + MCP `analyze_coverage` |
| Visualizing coverage | `attack-navigator-generator` |
| Optimizing SPL queries | `spl-optimizer` |
| Grouping detections | `analytic-story-builder` |
| Setting up test lab | `attack-range-builder` |
| Supply chain analysis | `supply-chain-analyst` |

## Quick Commands

### Check existing coverage before creating detections
```
MCP: security-detections:search("powershell encoded", limit=20)
MCP: security-detections:list_by_mitre("T1059.001")
```

### Validate technique IDs
```
MCP: mitre-attack:get_technique("T1003.001")
```

### Generate Navigator layer
```
MCP: mitre-attack:generate_coverage_layer(covered_ids=[...], name="My Coverage")
```

## Detection Creation Checklist

1. [ ] Search existing detections via MCP
2. [ ] Extract MITRE technique (sub-technique level)
3. [ ] Identify data source requirements
4. [ ] Write detection query for target SIEM
5. [ ] Add proper metadata (description, FPs, references)
6. [ ] Map to MITRE ATT&CK
7. [ ] Create test scenario
8. [ ] Run validation tool
9. [ ] Review with detection-reviewer skill

## MITRE Mapping Rules

- Always use sub-techniques: `T1003.001` not `T1003`
- Map to the technique being DETECTED, not the entire chain
- One detection = one primary technique
- Verify IDs with `mitre-attack:get_technique`

## Common Patterns

### Process-Based Detection
Monitor: parent-child relationships, command-line arguments, unusual paths, unsigned binaries

### Network-Based Detection
Monitor: beaconing, unusual ports, DNS tunneling, large transfers, C2 patterns

### File-Based Detection
Monitor: suspicious paths, double extensions, temp directories, unauthorized writes

### Auth-Based Detection
Monitor: impossible travel, brute force, pass-the-hash, privilege escalation
