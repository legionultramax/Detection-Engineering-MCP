# Running this server on Gemma 4 26B-A4B

How to operate Harris HawkEye MCP behind a local Gemma 4 model in Open WebUI, and why
[CLAUDE.md](../CLAUDE.md) cannot be used to do it.

Written for the deployment the project is actually headed for: `Gemma-4-26B-A4B` served by vLLM on
an NVIDIA DGX Spark, with Open WebUI as the front end.

---

## 1. Why CLAUDE.md does not transfer

CLAUDE.md is a good operations guide for Claude Code and a bad one for this deployment. Not because
of its content — because of three structural mismatches, each measured rather than assumed.

**It is never read.** CLAUDE.md is a Claude Code convention. Open WebUI does not look for it, and
nothing in the MCP protocol transmits it. On a Gemma deployment it is an unreferenced file.

**Two-thirds of the tools it names are not there.** CLAUDE.md references 72 tools that really exist
in the registry. Under `HAWKEYE_TOOL_PROFILE=phase1-authoring` — the profile this deployment should
run — **22 are exposed and 50 are not.** It also names 8 tool-shaped strings that exist nowhere
(`find_similar_detections`, `search_stories`, `get_technique`, `search_groups`,
`get_group_techniques`, `otx_pivot`, `ti_report_ingest`, `vendor_reports`), inherited from the
vendored skills. A guide whose tool table is 69% wrong trains a model to guess.

**It spends its length on machinery this deployment does not have.** By section weight:

| Section | Share | Status under Open WebUI + Gemma |
|---|---|---|
| WAT pipeline | 20.8% | Mostly names absent tools |
| Security Skills | 19.1% | **No skill system exists** — Open WebUI cannot invoke a `SKILL.md` |
| Tier 1 tool table | 13.1% | Describes the full 132-tool surface |
| Tier 2 (Playwright) | 7.7% | **No browser tool exists** on any deployment |
| Quality gates | 7.6% | Prose gates, unenforceable |
| Utility skills | 4.3% | No skill system |

Roughly **31% is structurally inapplicable** and most of the remainder points at tools that are
absent.

And it omits what matters most here: **`get_query_language_spec` and `translate_detection` are never
mentioned in CLAUDE.md at all**, along with `list_by_process_name`, `list_by_logsource` and
`list_by_mitre_tactic`. Five of the 27 tools this deployment exposes — including two thirds of the
query-authoring workflow — appear nowhere in the guide.

> CLAUDE.md stays as-is. It is correct for Claude Code, where the skills and the full tool surface
> do exist. This file is the Gemma equivalent, not a replacement.

---

## 2. What actually reaches the model

This is the part worth being precise about, because every piece of guidance has to travel one of
three channels and two of them are narrower than they look.

| Channel | Reaches Gemma? | Notes |
|---|---|---|
| **Tool names, descriptions, JSON schemas** | **Always** | The only guaranteed channel. 27 tools, 15.6 KB, ~4,500 tokens |
| **Open WebUI system prompt** | **Yes** | Gemma 4 has native `system` role support, unlike Gemma 3 which folded it into the first user turn |
| MCP `instructions` (the server's own preamble) | **Do not rely on it** | See below |

The server builds a careful profile-aware `instructions` block in
[`src/server.ts`](../src/server.ts) — the tool inventory, the "only these tools exist" warning,
suggested starting points. Whether any of it reaches the model depends on the client:

- **Through `mcpo`** it does not. mcpo sets the OpenAPI description to `serverInfo.name + " MCP
  Server"` and drops `instructions`; this was raised as
  [mcpo issue #142](https://github.com/open-webui/mcpo/issues/142), which is closed with no visible
  implementation in the thread.
- **Through Open WebUI's native MCP client**, the documentation does not say either way.

So: treat the server `instructions` as a bonus, and put anything load-bearing in the **system
prompt** in §4. That is the channel you control and can verify.

---

## 3. Wiring

### Use native MCP, not mcpo

Open WebUI has supported MCP natively since **v0.6.31**, and its native support is **Streamable HTTP
only** — which is exactly the transport this server speaks. mcpo exists to bridge *stdio* servers;
you do not have a stdio problem.

Dropping mcpo removes a process, removes the `instructions` loss described above, and removes a
translation layer between you and the protocol.

```bash
export DETECTIONS_DB_PATH=/abs/path/detections.db
export HAWKEYE_READONLY=1
export HAWKEYE_TOOL_PROFILE=phase1-authoring
export HAWKEYE_TRANSPORT=http
export HAWKEYE_HTTP_TOKEN="$(openssl rand -hex 32)"
# Bind stays on 127.0.0.1 by default. If Open WebUI is on another host, prefer an
# SSH tunnel over widening the bind — the server refuses a non-loopback bind
# without a token for exactly this reason.
node dist/index.js
```

Then add the server in Open WebUI as an MCP tool server pointing at `http://127.0.0.1:<port>/mcp`
with the bearer token. `/health` answers unauthenticated for liveness.

### vLLM

Gemma 4 has native function calling, but vLLM still needs it switched on:

```bash
vllm serve nvidia/Gemma-4-26B-A4B-NVFP4 \
  --enable-auto-tool-choice \
  --tool-call-parser <parser matching the Gemma 4 template>
```

**Confirm the parser value against your vLLM version rather than copying one.** The parser has to
match the model's chat template, and a mismatch does not error — it silently produces assistant text
that looks like a tool call and is never dispatched. Smoke-test it before anything else:

> "Call get_stats and tell me how many detections are indexed."

If the answer contains a real number, tool calling works end to end. If the model *describes*
calling the tool, the parser is wrong.

### Context budget

| | Tokens |
|---|---|
| Gemma 4 26B-A4B context | 262,144 |
| Tool definitions (27 tools) | ~4,500 |
| System prompt below | ~700 |

Context is not the constraint. **Discrimination is** — 25.2B total parameters but only **3.8B active
per token**, so routing across near-identical tool names is where this model degrades, long before
the window fills. That is what the `phase1-authoring` profile and the routing rules in §5 exist for.

---

## 4. The system prompt

Paste this into Open WebUI's system prompt for the model. It is deliberately short: a 3.8B-active
router follows a page better than a chapter.

```text
You are a detection engineering assistant. You have tools over a local corpus of 15,176
detection rules, MITRE ATT&CK, and living-off-the-land intelligence. You author, translate
and validate detection queries.

GROUND EVERYTHING IN A TOOL CALL
You do not reliably remember specific rule IDs, technique IDs, field names, table names or
LOLBAS entries. Look them up. If a tool returns nothing, say it returned nothing — never
fill the gap from memory. Only the tools in your tool list exist; never invent a tool name.

CHOOSING A TOOL — pick exactly one per question
Detection rules:
  have a technique ID (T1059.001)  -> list_by_mitre
  have a tactic name (persistence) -> list_by_mitre_tactic
  have an executable (certutil.exe)-> list_by_process_name
  have a log source (sysmon)       -> list_by_logsource
  have free text ("cred dumping")  -> search_detections
  have a rule ID from a result     -> get_detection
MITRE:
  known technique ID -> lookup_mitre_technique
  words, need the ID -> search_mitre_techniques
  what logs are needed -> get_data_sources
  who uses it -> get_groups_using_technique
  how to mitigate -> get_mitigations
  actor by name -> get_threat_group ; by words -> search_threat_groups
CVE: call nvd_cve_lookup, epss_score_lookup and check_cisa_kev together.
IOC: call misp_warninglist_check before treating any domain or IP as malicious.
Binaries: call lookup_lolbas before writing any rule scoped to a signed Windows binary.
  Enumerate every abuse pattern it returns before you write a condition.
Technique context: get_lolfarm_context(technique_id) for vulnerable drivers, DLL hijacks,
  RMM tools and known false positives. Always pass technique_id.

WRITING A QUERY — this sequence is required
  1. get_query_language_spec(language)   before writing anything
  2. write the query, using only field names the spec or brief gave you
  3. validate_query(query, language)     always, no exceptions
  4. blocking findings -> fix and validate again. Never present a query that has
     blocking findings, and never present a query you did not validate.
Porting an existing rule: translate_detection first, then steps 2-4.

QRADAR AQL
  Do not write START, STOP, LAST n HOURS or domainId. The hunt backend adds them, and a
    second copy conflicts with the injected one.
  Ariel has no JOIN, no UNION and no subquery. If the logic needs two event shapes,
    emit one query per shape and describe the correlation in words.
  If the hunt range may exceed 7 days, avoid GROUP BY and COUNT: the backend runs one
    query per day and concatenates, so an aggregate comes back computed per day.
  Double-quoted names like "Process CommandLine" are custom properties that differ
    between deployments. List every one in your answer so the analyst can check them.

REPORT HONESTLY
  Zero rows is not proof of a clean environment. It is equally likely a field name is
    wrong. Say which you cannot distinguish.
  If a tool errored or was missing, name the check that did not run.
  State every field the tools marked unconfirmed, next to the query, not in a footnote.
  Say plainly what you could not express rather than approximating it silently.
```

---

## 5. Tool routing — the 27 exposed tools

The reason routing needs help: the profile contains **six ways to retrieve a detection rule** and
**seven MITRE lookups**. Near-synonymous names are exactly the shape a 3.8B-active router gets
wrong, and the profile exists to keep that number at 27 rather than 132.

Counts below sum to 27: detection 7, MITRE 7, authoring 4, vulnerability/IOC 4, LOL 2, coverage 3.

### Detection corpus (7) — disambiguated by what you have, not what you want

| Tool | Use when you have | Required |
|---|---|---|
| `list_by_mitre` | A technique ID | `technique_id` |
| `list_by_mitre_tactic` | A tactic name | `tactic` |
| `list_by_process_name` | An executable name | `process` |
| `list_by_logsource` | A product / category / service | none |
| `list_by_severity` | Only a severity filter | `severity` |
| `search_detections` | Free text and nothing better | `query` |

`get_detection(id)` expands one result. `search_detections` is the fallback, not the default — a
technique ID handed to it returns worse results than `list_by_mitre`.

### MITRE ATT&CK (7)

`lookup_mitre_technique` (ID → detail) · `search_mitre_techniques` (words → ID) ·
`get_data_sources` (what logs) · `get_mitigations` (how to stop it) ·
`get_groups_using_technique` (who uses it) · `get_threat_group` (actor by name) ·
`search_threat_groups` (actor by words).

The pair that gets confused is `lookup_mitre_technique` and `search_mitre_techniques`: the first
takes an ID and the second produces one. Asking the lookup for "credential dumping" returns nothing.

### Query authoring (4) — the core loop

`get_query_language_spec` → write → `validate_query` → fix → present.
`translate_detection` replaces the first step when porting an existing rule.
`convert_sigma_to_kql` is a **draft generator only**; its output still goes through `validate_query`.

`validate_query` is the only real gate in the system: it is deterministic, involves no model
judgement, and blocking findings mean the query would fail or silently return nothing.

### Vulnerability and IOC (4)

`nvd_cve_lookup` · `epss_score_lookup` · `check_cisa_kev` · `misp_warninglist_check`.
All four reach the network. On an isolated or proxied host they fail visibly — which is the point:
an error says the check did not happen, an absent tool says nothing.

### Living off the land (2)

`lookup_lolbas(binary)` and `get_lolfarm_context(technique_id, mode)`.

`get_lolfarm_context` has **no required parameter**, so a model can call it with nothing and get a
useless answer. The system prompt says "always pass technique_id" for that reason. Call it with
`mode="summary"` (~500 tokens) first and escalate to `detailed` only if authoring depends on it.

### Coverage (3)

`analyze_coverage` · `identify_gaps` · `get_stats`. All three take no required arguments, which makes
them cheap to over-call. They frame a problem; they do not answer a specific one.

---

## 6. Workflows

CLAUDE.md's WAT pipeline is 13 stages. That is a reasonable structure for Claude Code and too many
branches for this model. These four cover the same ground.

**Author a rule for a technique**
`lookup_mitre_technique` + `list_by_mitre` + `get_data_sources` + `get_lolfarm_context` in parallel →
`lookup_lolbas` for any binary named → `get_query_language_spec` → write → `validate_query` → fix →
present with the unconfirmed fields named.

**Port an existing rule to another language**
`search_detections` or `list_by_mitre` to find it → `translate_detection(detection_id, target)` →
write from the brief → `validate_query` → fix → present, listing every mapping the brief graded
unconfirmed.

**Assess coverage for a technique or tactic**
`list_by_mitre` (parent and sub-techniques) → `analyze_coverage` → `identify_gaps` as a baseline
only. A generic rule is partial coverage, not coverage.

**Assess a CVE**
`nvd_cve_lookup` + `epss_score_lookup` + `check_cisa_kev` in parallel → `search_detections` for
existing coverage → author if there is a gap.

---

## 7. What this cannot enforce, and what would

Be clear-eyed about the system prompt: **it converts hard requirements into strong suggestions.** A
3.8B-active router will skip a prose instruction some fraction of the time, and neither this file nor
CLAUDE.md can change that. Two things in §4 are load-bearing and unenforced:

- **The LOLBAS gate.** "Enumerate every abuse pattern before writing a condition" is a sentence. If
  the model skips it, nothing notices.
- **The validate-before-present rule.** `validate_query` is deterministic and reliable — but only
  once it is *called*. Nothing forces the call.

The fix is not a better prompt. It is to collapse each gate into a single deterministic server-side
tool, so the gate is a return value rather than an instruction — `build_authoring_brief` returning
`gate: BLOCKED` when a binary-scoped abuse matrix is incomplete, and a `synthesize_killchain`
scaffold. That is Phase 4 of
[OPENWEBUI-GEMMA-INTEGRATION-PLAN.md](OPENWEBUI-GEMMA-INTEGRATION-PLAN.md), and it is not built:
`src/tools/authoring/` does not exist. Until it does, treat the prompt as mitigation, not control.

Also unmeasured: **generation quality against the real model.** Nothing in this repository has been
evaluated end to end on Gemma 4. The tools are tested; what Gemma does with them is not.

---

## 8. Verify before trusting it

Run these in order. Each has a wrong answer that tells you which layer is broken.

| # | Ask the model | Confirms | Wrong answer means |
|---|---|---|---|
| 1 | "Call get_stats." | Tool calling works at all | Model narrates a call → vLLM tool parser mismatch |
| 2 | "How many tools do you have?" | Profile is applied | Not 27 → `HAWKEYE_TOOL_PROFILE` unset |
| 3 | "Find detections for T1059.001." | Routing on a technique ID | Used `search_detections` → routing rules not in the system prompt |
| 4 | "Search for certutil download." | Corpus + FTS5 | Zero results → database missing or index stale (`npm run fts:status`) |
| 5 | "Write a KQL rule for T1003.001." | The authoring loop | Skipped `validate_query` → the sequence is not being followed |
| 6 | "Write a QRadar AQL query for encoded PowerShell." | AQL constraints | Contains `LAST 24 HOURS` → the AQL block is not reaching the model |
| 7 | "Look up CVE-2021-44228." | Network-bound tools | Errors → expected on an isolated host; the model must *say* the check did not run |

Server-side, all seven suites should pass first:

```bash
npm run lint && npm run tools:check
npm run verify:readonly && npm run verify:queries && npm run verify:aql
npm run verify:search && npm run verify:http && npm run verify:coverage
```

---

## Sources

- [Gemma 4 model card](https://ai.google.dev/gemma/docs/core/model_card_4) — 25.2B total / 3.8B
  active, 256K context, native `system` role, native structured tool use
- [google/gemma-4-26B-A4B-it](https://huggingface.co/google/gemma-4-26B-A4B-it)
- [Open WebUI — MCP support](https://docs.openwebui.com/features/extensibility/mcp/) — native MCP
  from v0.6.31, Streamable HTTP only
- [mcpo issue #142](https://github.com/open-webui/mcpo/issues/142) — MCP `instructions` not passed
  through to the model
- Tool counts, section weights and the 72/22/50 split were measured against this repository at
  commit `f486d2c`, not estimated.
