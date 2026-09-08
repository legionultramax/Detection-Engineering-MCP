# Claude Skills for Detection Engineering

This directory contains Claude **Skills** that provide specialized expertise for detection engineering, threat intelligence analysis, and security content development.

## What are Skills?

Skills are packages of expertise that teach Claude how to excel at specific tasks. Unlike MCPs (Model Context Protocol) which provide data access, Skills provide **methodology and best practices**.

- **MCPs** = Access to your data (Splunk, detection database, MITRE ATT&CK)
- **Skills** = Expert knowledge (CTI analysis, detection engineering, query optimization)

Claude automatically loads relevant skills based on your task.

## Available Skills

| Skill | Priority | When to Use |
|-------|----------|-------------|
| **cti-detection-engineer** | Core | Threat analysis, MITRE mapping, detection design |
| **detection-yaml-engineer** | Core | Creating/validating detection rule files |
| **threat-report-parser** | Core | Analyzing threat reports and extracting TTPs |
| **detection-reviewer** | Core | QA review before deployment |
| **detection-test-engineer** | Core | Creating test scenarios for detections |
| **atomic-red-team-testing** | Testing | Running atomic tests for validation |
| **attack-range-builder** | Testing | Building test environments |
| **custom-atomics-deployment** | Testing | Creating custom attack simulations |
| **attack-navigator-generator** | Visualization | ATT&CK Navigator layers and coverage maps |
| **analytic-story-builder** | Organization | Grouping detections into stories/use cases |
| **supply-chain-analyst** | Specialty | Supply chain attack analysis |
| **spl-optimizer** | Specialty | Splunk SPL query optimization |
| **data-source-mapper** | Reference | Mapping detections to data sources |
| **pr-extension-workflow** | Workflow | Extending PR coverage |

## SIEM Platform Support

These skills are designed to be **SIEM-agnostic**. Set `$SIEM_PLATFORM` in your `agents/.env` to customize output:

| Value | Output Format | Validation | Best For |
|-------|--------------|------------|----------|
| `splunk` | SPL with CIM data models | `contentctl validate` | Splunk shops, security_content contributors |
| `sentinel` | Microsoft Sentinel KQL | Azure CLI | Microsoft / Azure shops |
| `elastic` | Elastic Security EQL/ES\|QL | detection-rules CLI | Elastic shops |
| `sigma` | Platform-agnostic Sigma YAML | pySigma conversion | Multi-SIEM, maximum portability |

### Not Using Attack Range?

Attack Range is only required for the `splunk` platform with automated atomic testing. For other SIEMs:
- **Sentinel**: Use Azure VMs with Defender for Endpoint
- **Elastic**: Use Docker-based Elastic Stack with Elastic Agent
- **Manual testing**: Any VM with Sysmon + Invoke-AtomicRedTeam installed
- **No lab needed**: Set `DRY_RUN=true` for rule authoring without live validation

See [docs/E2E-TESTING-GUIDE.md](../../docs/E2E-TESTING-GUIDE.md) for complete lab setup per SIEM.

## Environment Variables

Skills reference these environment variables for portability:

| Variable | Description | Example | Required |
|----------|-------------|---------|----------|
| `SIEM_PLATFORM` | Target SIEM platform | `splunk` | Yes |
| `SECURITY_CONTENT_PATH` | Detection content repository | `./security_content` | Yes |
| `VALIDATION_TOOL` | Validation command override | `contentctl validate` | No (has defaults) |
| `ATTACK_RANGE_PATH` | Attack Range installation | `./attack_range` | Splunk only |
| `ATTACK_DATA_PATH` | Attack data repository | `./attack_data` | Splunk only |

## Integration with MCPs

Skills work best when combined with MCP servers:

| MCP Server | What It Provides | Required For |
|------------|-----------------|-------------|
| `security-detections` | Detection database, coverage analysis, gap identification | All SIEMs |
| `splunk-mcp` | Live Splunk queries, detection validation | Splunk only |
| `mitre-attack` | Technique lookup, group TTPs, Navigator layers | All SIEMs |

> **Non-Splunk users**: You don't need `splunk-mcp`. The `security-detections` MCP indexes rules from all formats (Sigma, Splunk, Elastic, KQL) regardless of which SIEM you use for live validation.

## Creating New Skills

1. Create a directory under `.claude/skills/your-skill-name/`
2. Add a `SKILL.md` file with YAML frontmatter (`name`, `description`)
3. Include configuration requirements at the top
4. Document the methodology and examples
5. Keep skills focused on one domain of expertise
