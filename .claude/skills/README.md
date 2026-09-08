# Skills — Detection Engineering

Project-scoped Claude Code skills. Claude loads these automatically when working in this
repository, and they are versioned with the code they drive.

## Why they live here

The original eight Harris HawkEye skills (`detect-engineer`, `killchain-synth`,
`advisory-ingest`, `detection-validator`, `data-source-mapper`, `coverage-reporter`,
`navigator-layer-gen`, `threat-report-parser`) lived only in `~/.claude/skills/` on a
previous machine. Being per-user and outside version control, they did not survive the
machine migration — the `C:\Users\harsh` profile they referenced no longer exists, and
they are unrecoverable.

Skills are now project-scoped under `.claude/skills/` so this cannot happen again. To also
use them outside this project:

```bash
# Linux / macOS
ln -s "$(pwd)/.claude/skills" ~/.claude/skills

# Windows (PowerShell, as admin)
New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\.claude\skills" -Target "$(Get-Location)\.claude\skills"
```

## What is here now

The 15 skills currently present were **copied verbatim from
[MHaggis/Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP)**
(Apache-2.0, Michael Haag). They are **not** the original Harris HawkEye skills. See
[NOTICE.md](NOTICE.md) for attribution and licensing — that content remains Apache-2.0
and cannot be relicensed under this repository's MIT terms.

These are methodology skills rather than tool scripts, which is why they port cleanly:
upstream's own documentation puts it as *"MCPs = access to your data; Skills = expert
knowledge."*

| Skill | Focus |
|---|---|
| `cti-detection-engineer` | Threat analysis, MITRE mapping, detection design |
| `detection-yaml-engineer` | Creating and validating detection rule files |
| `threat-report-parser` | Extracting TTPs from threat reports |
| `detection-reviewer` | QA review before deployment |
| `detection-test-engineer` | Test scenarios for detections |
| `coverage-analysis` | Coverage and gap analysis |
| `data-source-mapper` | Mapping detections to data sources |
| `attack-navigator-generator` | ATT&CK Navigator layers |
| `analytic-story-builder` | Grouping detections into Splunk analytic stories |
| `spl-optimizer` | SPL query optimisation (596 lines — the most detailed here) |
| `atomic-red-team-testing` | Running atomic tests for validation |
| `attack-range-builder` | Building test environments |
| `custom-atomics-deployment` | Custom attack simulations |
| `supply-chain-analyst` | Supply chain attack analysis |
| `pr-extension-workflow` | Extending PR coverage |

Plus `_reference/` (upstream's data-source and quick reference docs) and `../rules/`
(upstream's detection templates and threat-analysis workflow).

## Known adaptation work

**Tool names that resolve correctly against this server** — no change needed:
`analyze_coverage`, `identify_gaps`, `suggest_detections`, `list_by_mitre`,
`list_by_mitre_tactic`, `get_technique_ids`, `get_technique_count`.

**Tool names these skills call that do not exist here.** Four are simple renames; the rest
have no local equivalent:

| Referenced | This server |
|---|---|
| `search(...)` | `search_detections(...)` |
| `search_groups(...)` | `search_threat_groups(...)` |
| `get_technique(...)` | `lookup_mitre_technique(...)` |
| `get_group_techniques(...)` | `get_groups_using_technique(...)` (inverse direction) |
| `generate_navigator_layer`, `generate_coverage_layer`, `generate_gap_layer`, `generate_group_layer` | **no equivalent** — this server has no Navigator tool |
| `find_similar_detections` | **no equivalent** |
| `search_stories` | **no equivalent** |

**Skills depending on infrastructure this project does not run:**
`attack-range-builder`, `custom-atomics-deployment`, `atomic-red-team-testing` (this
server indexes ART tests but does not execute them), `pr-extension-workflow`,
`analytic-story-builder`.

## What is still missing

Nothing here covers this project's distinguishing capabilities. Upstream has **zero**
LOLBAS, LOLFarm, or YARA content, so the following have no counterpart and still need to
be authored:

- **The LOLBAS hard gate** — every binary-scoped rule enumerating all known abuse patterns
  before a condition is written. This was the defining constraint of `detect-engineer`.
- **LOLFarm enrichment** — driver, DLL-hijack, RMM, and known-FP intelligence across the
  seven sources.
- **`killchain-synth`** — stitching atomic rules into correlated multi-phase queries.
- **`advisory-ingest`** — CISA/vendor advisory parsing into prioritised gap tables.
- **Coverage engine integration** — the 4-state classifier and 138 telemetry mappings.

## Hard rule

Never assert a detection fact from training data. Every technique detail, existing rule,
LOLBAS entry, false positive, and ART test must come from an MCP tool call against this
server. If a tool returns nothing, say so rather than filling the gap from memory.
