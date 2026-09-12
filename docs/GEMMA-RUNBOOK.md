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
| Tier 1 tool table | 13.1% | Describes the full 134-tool surface |
| Tier 2 (Playwright) | 7.7% | **No browser tool exists** on any deployment |
| Quality gates | 7.6% | Prose gates, unenforceable |
| Utility skills | 4.3% | No skill system |

Roughly **31% is structurally inapplicable** and most of the remainder points at tools that are
absent.

And it omits what matters most here: **`get_query_language_spec` and `translate_detection` are never
mentioned in CLAUDE.md at all**, along with `list_by_process_name`, `list_by_logsource` and
`list_by_mitre_tactic`. Five of the 29 tools this deployment exposes — including two thirds of the
query-authoring workflow — appear nowhere in the guide.

> CLAUDE.md stays as-is. It is correct for Claude Code, where the skills and the full tool surface
> do exist. This file is the Gemma equivalent, not a replacement.

---

## 2. What actually reaches the model

This is the part worth being precise about, because every piece of guidance has to travel one of
three channels and two of them are narrower than they look.

| Channel | Reaches Gemma? | Notes |
|---|---|---|
| **Tool names, descriptions, JSON schemas** | **Always** | The only guaranteed channel. 29 tools, 19.6 KB, ~5,600 tokens |
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
export HAWKEYE_MAX_RESULTS=10          # see the context budget below — not optional at 16K
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

Gemma 4 has native function calling, but vLLM needs it switched on, and Gemma's format is not JSON —
it is a custom serialisation, `<|tool_call>call:name{key:<|"|>value<|"|>}<tool_call|>`, which is why
a dedicated parser is required:

```bash
vllm serve nvidia/Gemma-4-26B-A4B-NVFP4 \
  --max-model-len 32768 \
  --enable-auto-tool-choice \
  --tool-call-parser gemma4 \
  --reasoning-parser gemma4 \
  --chat-template examples/tool_chat_template_gemma4.jinja
```

A parser mismatch does not error. It silently produces assistant text that looks like a tool call and
is never dispatched. Smoke-test before anything else:

> "Call get_stats and tell me how many detections are indexed."

A real number means tool calling works end to end. If the model *describes* calling the tool, the
parser or the chat template is wrong.

> **Known upstream bug, and this server defends against it.** vLLM's `gemma4` parser has been
> reported leaking its own string delimiters into parsed argument values — `<|"|>certutil<|"|>`
> arriving where `certutil` was meant ([vllm#39468](https://github.com/vllm-project/vllm/issues/39468),
> open; [vllm#44522](https://github.com/vllm-project/vllm/issues/44522)). The failure is silent and
> ugly: a search term wrapped in delimiters matches nothing, and "no detections found" reads as
> coverage information rather than as a broken argument.
>
> The registry now strips those delimiters from incoming arguments and **logs once** with a link to
> the issue, so a repaired call still tells you the parser needs attention. Verified end to end: a
> leaked search term, technique ID and query each return results identical to the clean form, while
> ordinary `<`, `>` and `|` characters in a real query are untouched. Do not treat this as a reason
> to skip the smoke test — it repairs arguments, it does not fix your parser.

**Parallel tool calls: keep them to three.** Gemma 4 can emit several in one turn but reliability
falls off past about three, so the CLAUDE.md habit of firing six lookups at once does not transfer.
The workflows in §6 are written in small parallel batches for that reason.

### Context budget — read this before choosing `--max-model-len`

The model's ceiling is 262,144 tokens. **That is not what you get by default.** vLLM's own Gemma 4
recipe recommends `--max-model-len 16384`, and at 16K the arithmetic changes completely:

| | Tokens | Share of 16K |
|---|---|---|
| Tool definitions, 29-tool profile | ~5,600 | **34%** |
| Tool definitions, full 134 tools | ~19,450 | **does not fit** |
| System prompt in §4 | ~700 | 4% |

Those are resident for the whole conversation. Then the responses land on top, and they are larger
than the definitions:

| Call | Tokens | Share of 16K |
|---|---|---|
| `list_by_mitre("T1059.001")` at the old default of 50 rows | 4,535 | **28%** |
| `get_query_language_spec("aql")` | 4,054 | 25% |
| `get_mitigations("T1059.001")` before trimming | 3,404 | 21% |
| `get_groups_using_technique("T1059.001")` uncapped | 2,488 | 15% |

Measured end to end, a perfectly ordinary six-call authoring session —
`lookup_mitre_technique` → `list_by_mitre` → `get_data_sources` → `get_lolfarm_context` →
`lookup_lolbas` → `get_query_language_spec` — consumed **14,873 of 16,384 tokens, 91% of the window,
before the model wrote a single token of output.**

**Two changes fix this, and you need both.**

```bash
export HAWKEYE_MAX_RESULTS=10      # caps every list-shaped tool, and the caller too
```

and serve with more room:

```bash
--max-model-len 32768              # 65536 if memory allows
```

The same session then measures **11,268 tokens: 69% of 16K, 34% of 32K.** `get_mitigations` now
trims prose by default (3,404 → 826 tokens) and `get_groups_using_technique` is capped, both
reported rather than silent.

`HAWKEYE_MAX_RESULTS` bounds the caller as well as the default — a model asking for 200 rows is
exactly the case a per-tool default cannot catch. An explicit *smaller* limit is still honoured.

| `--max-model-len` | Set `HAWKEYE_MAX_RESULTS` to |
|---|---|
| 8192 | 5 — though the tool definitions alone are 55% of it; prefer raising the window |
| 16384 | 10 |
| 32768 | 15 |
| 131072+ | leave unset (default 50) |

Context is the constraint this runbook can actually measure, and the profile exists to fit it. The
routing rules in §5 are a separate, weaker claim: fewer near-duplicate tool names is plausibly easier
to route across, but nothing here tested that, so treat §5 as a convenience rather than a
requirement.

> **A correction, since an earlier draft of this file got it wrong.** It repeatedly justified the
> profile and the short system prompt by calling Gemma 4 26B-A4B a "3.8B-active router" — reasoning
> from its active parameter count as though it behaved like a 4B dense model. Active parameters
> govern inference speed, not judgement. This is a **25.2B-parameter model**, considerably more
> capable than that framing implied, and nothing in this repository has been evaluated against it.
> The profile is justified above on arithmetic: 20,400 tokens of tool definitions do not fit in a
> 16,384-token window. That argument does not depend on the model being weak, and it is the one to
> rely on.

### Schema compatibility — clean, and verified

Gemma 4 degrades on deeply nested schemas and complex enums; the guidance is one to two levels of
nesting. Every tool in the `phase1-authoring` profile is inside that, checked by
`npm run verify:gemma`: no nesting beyond a flat property bag, no `anyOf`/`oneOf`/`allOf`/`$ref`,
no object-typed arguments, at most 5 arguments on any tool, 2 of 27 using a simple enum.

Two tools on the **full** surface would not be: `generate_hunt_report` takes an array of nested
objects, and `create_entity` takes a free-form object. Both are excluded from `phase1-authoring`, so
neither reaches this deployment — but both are reasons not to point Gemma at the `research` or
`full` profile.

---

## 4. The system prompt

Paste this into Open WebUI's system prompt for the model. It is kept short for a concrete reason:
at `--max-model-len 16384` the tool definitions already take a third of the window, so every token
spent on standing instructions is one unavailable for tool results and the answer. It is ~700 tokens
against ~5,400 of definitions.

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

WRITING A RULE — this sequence is required
  1. build_authoring_brief(technique_id, language)   ALWAYS first. One call gives you
     the technique, reference rules, telemetry, known false positives, the field
     vocabulary and the LOLBAS abuse matrix. Do not make those six calls yourself.
     Pass binary="name.exe" when the rule is scoped to a specific executable.
  2. If it returns gate=BLOCKED: do not write a query. Report what is missing.
     If gate=CAVEATS: write it, and state every caveat in your answer.
  3. Write the query using only names from target.field_vocabulary, covering every
     pattern in lolbas_gate.matrices, excluding the known false positives.
  4. validate_query(query, language)     always, no exceptions
  5. blocking findings -> fix and validate again. Never present a query that has
     blocking findings, and never present a query you did not validate.
Porting an existing rule instead: translate_detection first, then steps 3-5.
Two or more techniques as one chain: synthesize_killchain(technique_ids, language),
  then build_authoring_brief per phase to fill in each predicate.
get_query_language_spec(language) is for depth — operators, cost, worked examples.
  The brief already carries the vocabulary and the blocking prohibitions.

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

## 5. Tool routing — the 29 exposed tools

The profile contains **six ways to retrieve a detection rule** and **seven MITRE lookups**, several
of them near-synonymous. Spelling out which input selects which tool costs a few lines and removes
the ambiguity for any reader, model or person — but this is guidance, not a measured constraint.
The profile's size is justified by context (§3); this section is about making the remaining 29
easy to choose between.

Counts below sum to 29: composite 2, detection 7, MITRE 7, authoring 4, vulnerability/IOC 4, LOL 2,
coverage 3.

### Composite (2) — start here

| Tool | Replaces | Why |
|---|---|---|
| `build_authoring_brief` | six lookups | Everything needed to write one rule, in one call, at **82% fewer tokens** than making those six calls. Carries the LOLBAS abuse matrix as *data*, so the "enumerate every abuse pattern" rule cannot be skipped. Returns `gate: BLOCKED` — and withholds the material — when a rule cannot be safely grounded |
| `synthesize_killchain` | WAT-42 by hand | Computes the phase order from ATT&CK tactics, the pivot entity, and the correlation idiom for the target language. You fill in the per-phase predicates |

These are the two highest-leverage tools in the profile. A model that reaches for
`build_authoring_brief` first makes one call where it used to make six, and cannot forget the gate.

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
branches for this model. These five cover the same ground.

**Author a rule for a technique**
`build_authoring_brief(technique_id, language)` → write → `validate_query` → fix → present with the
unconfirmed fields named.

That is one lookup, not six. The brief carries the technique, the reference rules, the telemetry, the
false positives, the field vocabulary and the LOLBAS matrix in ~1,500 tokens — the six calls it
replaces measured ~8,200. If it returns `gate: BLOCKED`, report the gap; do not write the rule
anyway.

**Correlate several techniques into a kill chain**
`synthesize_killchain(technique_ids, language)` → `build_authoring_brief` per phase for the
predicates → fill the scaffold → `validate_query` → present with the correlation window stated.
For AQL you get one query per phase plus a written spec, because Ariel cannot join.

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

A system prompt **converts hard requirements into strong suggestions**. Any model skips a prose
instruction occasionally, and no amount of rewriting makes a sentence binding. So the two
requirements that actually matter were moved out of the prompt and into code.

**The LOLBAS gate is now enforced.** "Enumerate every abuse pattern before writing a condition" used
to be a sentence; it is now the payload of `build_authoring_brief`. The abuse matrix arrives whether
the model asked for it or not, so it cannot be forgotten — and when a binary has no matrix, the brief
returns `gate: BLOCKED` **and withholds the authoring material**, because a BLOCKED flag sitting next
to a usable payload is just another suggestion. Measured: a blocked brief is 842 bytes against 6,109
for a usable one.

**Kill-chain structure is now computed.** `synthesize_killchain` derives the phase order from ATT&CK
tactics rather than from the order the caller listed them, picks the pivot, and emits the right
correlation idiom per language. For AQL it refuses to emit a joined query at all, because Ariel has
no JOIN and this server's own `validate_query` would reject one.

What remains genuinely unenforced:

- **The validate-before-present rule.** `validate_query` is deterministic and reliable — but only
  once it is *called*, and nothing forces the call. The brief's `next_step` asks for it; that is
  still a request.
- **Whether the model uses the composite tools at all.** Nothing stops it making the six separate
  calls and skipping the gate that way. The routing rules in §4 and §5 point at the composites, but
  they are prompt-level, not structural.

Also still unmeasured: **anything about the model itself.** Nothing in this repository has been
evaluated end to end on Gemma 4 — not generation quality, not tool-routing accuracy, not how often
it skips a step. The tools are tested (62 checks on the composites alone); what Gemma does with them
is not, and no claim here about its behaviour should be read as evidence. Where this runbook
describes model behaviour, it is quoting Google's or vLLM's documentation; where it describes token
counts and payload sizes, those are measured against this repository.

---

## 8. Verify before trusting it

### First: prove the server, so a later failure is unambiguous

```bash
npm run preflight                                   # on the server's own machine
npm run preflight -- --url http://HOST:PORT/mcp --token XYZ   # against a deployed one
```

This starts the server with the documented deployment settings, speaks MCP over HTTP the way Open
WebUI will, and drives the same seven scenarios below as **direct tool calls** — no model involved.
23 checks: transport, auth, session handling, the 29-tool profile, the corpus, FTS5, the LOLBAS
gate, the AQL constraints, and read-only enforcement.

The point is isolation. Asking the model a question exercises the model, the tool parser, the
transport, the profile and the data all at once, so a bad answer says nothing about which of them
broke. **If a step below fails on the real stack and its counterpart passes in preflight, the fault
is above the server** — the parser, the system prompt, or the model.

Preflight cannot tell you whether Gemma picks the right tool, fills arguments correctly, or follows
the authoring sequence. Nothing server-side can. That is what the table is for.

### Then: the seven questions, against the real stack

Run these in order. Each has a wrong answer that tells you which layer is broken.

| # | Ask the model | Confirms | Wrong answer means |
|---|---|---|---|
| 1 | "Call get_stats." | Tool calling works at all | Model narrates a call → vLLM tool parser mismatch |
| 2 | "How many tools do you have?" | Profile is applied | Not 29 → `HAWKEYE_TOOL_PROFILE` unset |
| 3 | "Find detections for T1059.001." | Routing on a technique ID | Used `search_detections` → routing rules not in the system prompt |
| 4 | "Search for certutil download." | Corpus + FTS5 | Zero results → database missing or index stale (`npm run fts:status`) |
| 5 | "Write a KQL rule for T1003.001." | The authoring loop | Skipped `validate_query` → the sequence is not being followed |
| 6 | "Write a QRadar AQL query for encoded PowerShell." | AQL constraints | Contains `LAST 24 HOURS` → the AQL block is not reaching the model |
| 7 | "Look up CVE-2021-44228." | Network-bound tools | Errors → expected on an isolated host; the model must *say* the check did not run |
| 8 | Watch the server's stderr during 3–5 | The tool parser | A `Stripped Gemma 4 tool-call delimiters` line → your vLLM parser is leaking (vllm#39468). Calls still work; fix the parser |

Server-side, all eight suites should pass first — `npm run preflight` assumes they do:

```bash
npm run lint && npm run tools:check
npm run verify:readonly && npm run verify:queries && npm run verify:aql
npm run verify:search && npm run verify:http && npm run verify:coverage
npm run verify:gemma      # 35 checks — schema shape, context budget, delimiter repair
npm run verify:authoring  # 68 checks — the composite tools and the LOLBAS gate
```

`verify:gemma` is the one that keeps this document true. It asserts that the profile's schemas stay
inside Gemma's nesting ceiling, that the scoped payload still fits a third of a 16K window, that
`HAWKEYE_MAX_RESULTS` binds the caller and not just the default, and that a leaked-delimiter argument
resolves identically to a clean one.

---

## Sources

- [Gemma 4 model card](https://ai.google.dev/gemma/docs/core/model_card_4) — a **25.2B-parameter**
  MoE, 3.8B of them active per token, 262K context, native `system` role, native structured tool
  use. The active count describes inference cost, not capability; it says how fast the model runs,
  not how well it reasons
- [google/gemma-4-26B-A4B-it](https://huggingface.co/google/gemma-4-26B-A4B-it)
- [Function calling with Gemma 4](https://ai.google.dev/gemma/docs/capabilities/text/function-calling-gemma4)
  — the `<|tool_call>call:name{key:<|"|>value<|"|>}<tool_call|>` serialisation, and tool declaration
  via `apply_chat_template(tools=…)`
- [vLLM Gemma 4 recipe](https://docs.vllm.ai/projects/recipes/en/stable/Google/Gemma4.html) —
  `--tool-call-parser gemma4`, `--reasoning-parser gemma4`, `--chat-template
  tool_chat_template_gemma4.jinja`, and the `--max-model-len 16384` recommendation that drives the
  context budget in §3
- [vllm#39468](https://github.com/vllm-project/vllm/issues/39468) (open) and
  [vllm#44522](https://github.com/vllm-project/vllm/issues/44522) — the `gemma4` parser leaking
  `<|"|>` delimiters into argument values
- [Open WebUI — MCP support](https://docs.openwebui.com/features/extensibility/mcp/) — native MCP
  from v0.6.31, Streamable HTTP only
- [mcpo issue #142](https://github.com/open-webui/mcpo/issues/142) — MCP `instructions` not passed
  through to the model

Every number in this document was measured against this repository rather than estimated: the
72/22/50 tool split, the section weights in §1, the payload and response sizes in §3, and the 91% →
69% session figures. `npm run verify:gemma` re-checks the ones that can drift.
