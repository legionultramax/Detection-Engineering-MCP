# Harris HawkEye MCP — Open WebUI / Gemma-4-26B-A4B Integration Plan

> **SUPERSEDED.** Written before the downstream execution contract was known, and kept only for
> the environment details below, which remain accurate.
>
> Three things in it are wrong and were corrected elsewhere. Phase 5 places pipeline run state in
> this repo's SQLite; run state belongs to whatever system executes the queries, not to the tool
> server. Phase 6 places tenant isolation here; that also belongs downstream. And the database
> figure is stale — it was 58.6 MB before the corpus was re-indexed and is roughly 120 MB after.
>
> Treat the phase numbering below as historical. What this repository actually provides is the
> tool server: read-only mode, tool profiles, the detection corpus, and the query-language field
> catalog.

**Target stack**
| Layer | Component |
|---|---|
| Inference | `nvidia/Gemma-4-26B-A4B-NVFP4` (25.2B-parameter MoE, 3.8B active per token — an inference-cost figure, not a capability one; native function calling) |
| Serving | vLLM OpenAI-compatible API @ `http://10.10.105.65:8000/v1`, launched with `--enable-auto-tool-choice --tool-call-parser gemma4 --reasoning-parser gemma4` |
| Hardware | NVIDIA DGX Spark (GB10 Grace Blackwell, aarch64) |
| Frontend | Open WebUI v0.11.3 |
| Tooling | this repo (`harris-hawkeye-mcp`, 122 tools, sql.js/WASM SQLite) |

**Pipeline being served**
- **Phase 1** — analyst + Gemma generate a detection query, grounded in this MCP server.
- **Phase 2** — approved query is dispatched to all client environments and executed.
- **Phase 3** — results are aggregated into a report.

**Core design principle.** Everything that currently depends on a frontier model's judgment (the `detect-engineer` 7-step pipeline, the LOLBAS hard gate, the 5–6 dimension validation rubric) must become **server-side code**, not prompt instructions. No model self-orchestrates a multi-step rubric reliably from prose, because a sentence is not binding on anything — a skipped step leaves a rule that still looks finished. The server does the orchestration; the model writes the query text.

**Compatibility constraint.** Claude Code (stdio) usage must keep working unchanged throughout. Every change below is additive and flag-gated.

---

## Phase 0 — Baseline and guardrails

The repo currently has two test files (`tests/test.js`, `tests/test_surgical_tools.mjs`). That is not enough coverage to refactor transport and storage safely.

1. **Golden-output snapshot.** Capture current output for ~20 representative tool calls (`get_stats`, `search_detections`, `list_by_mitre` for a handful of T-IDs, `get_lolfarm_context`, `lookup_lolbas`, `art_get_tests`, `coverage_assess_session`) into `tests/golden/`. Every later phase must diff clean against these.
2. **Record the invariants** that must not regress: 12,810 detections indexed, 122 tools registered, 835 techniques, 1,770 ART tests, FTS5 search returning identical top-N ordering.
3. **Branch strategy.** `feat/http-gateway` off `main`. The repo has 3 commits and a clean tree — tag `pre-openwebui` first so there is a rollback point.

**Exit criteria:** golden snapshot committed; `npm test` green; tag pushed.

---

## Phase 1 — Datastore split (P0 — correctness blocker)

### The problem

`src/db/connection.ts`:

- `runStatement()` calls `saveDb()` after every write.
- `saveDb()` does `db.export()` (serializes the **entire** database to a byte array) then `fs.writeFileSync(dbPath, buffer)`.
- The database is ~97 MB.

Consequences once this server is reachable over HTTP by a multi-client pipeline:

| Risk | Impact |
|---|---|
| Every write serializes + rewrites 97 MB | Write latency in the hundreds of ms to seconds; pathological under load |
| Two concurrent writes | Each exports its own in-memory image and overwrites the file — **the second write silently discards the first**. Lost approvals, lost client results. |
| No WAL / no transactions / no row-level durability | A crash mid-`writeFileSync` can truncate the whole corpus, not one row |
| sql.js is single-threaded WASM | No real concurrency; requests serialize on the JS event loop |

This is fine for one stdio client doing occasional knowledge-graph writes. It is unacceptable for Phase 2 posting results back from N clients.

### The fix — split read-mostly corpus from mutable ops state

**`detections.db` becomes a read-only serving corpus.** It holds detections, MITRE ATT&CK, ART, LOLFarm seeds, coverage mappings — all of which are written only by the indexer/sync jobs, never by request handlers.

- Add `HAWKEYE_DB_READONLY=1` (default in HTTP serving mode). When set, `saveDb()` becomes a no-op and any write attempt throws loudly rather than silently rewriting 97 MB.
- Indexing/sync runs as a separate offline invocation (`npm run reindex`) with the flag off.

**New `ops.db` for all mutable state**, on `better-sqlite3` with WAL enabled:

- knowledge graph (entities, relations, decisions, learnings)
- pipeline queries, approvals, dispatches, client results, audit log (Phase 5)

Rationale: WAL gives real concurrent readers + serialized writers, row-level durability, and proper transactions. Upstream `MHaggis/Security-Detections-MCP` uses `better-sqlite3` for the same reason.

**aarch64 note.** DGX Spark is ARM64. `better-sqlite3` ships linux-arm64 prebuilds in recent versions; if the prebuild misses, it needs `node-gyp` + build-essential + python3 in the image. Verify this early — it is the one native dependency in an otherwise pure-JS/WASM stack. Fallback if native builds are a problem: keep `ops.db` on sql.js but as a **separate small file** (a few hundred KB), where export-per-write is cheap, plus the mutex below.

**Write serialization.** Regardless of engine, add `src/db/write-queue.ts` — a promise-chained mutex wrapping all writes, with debounced persist (coalesce writes within ~250 ms into one flush). This closes the interleaving window.

- New: `src/db/ops-connection.ts`, `src/db/write-queue.ts`
- Modified: `src/db/connection.ts` (readonly guard, no-op `saveDb`), `src/db/knowledge.ts` (repoint to `ops.db`)

**Exit criteria:** concurrency test — 200 parallel knowledge-graph writes, all 200 present afterward, corpus DB byte-identical (mtime unchanged).

---

## Phase 2 — Dual transport: stdio + Streamable HTTP (P0 — integration blocker)

### The problem

`src/server.ts:241` hardcodes `new StdioServerTransport()`. There is no HTTP/SSE path anywhere in the repo (grep for `StreamableHTTP`/`SSE`/`mcpo` returns nothing). Open WebUI cannot reach a bare stdio process the way it reaches the vLLM endpoint.

### The fix

Refactor `startServer()` to select transport from env, and add an HTTP gateway.

```
HAWKEYE_TRANSPORT = stdio | http | both     # default: stdio (Claude Code unchanged)
HAWKEYE_HTTP_PORT = 8787
HAWKEYE_BIND      = 127.0.0.1               # never 0.0.0.0 without a token
HAWKEYE_API_TOKEN = <required in http mode>
```

**New `src/http/gateway.ts`** — an Express app exposing two parallel surfaces:

| Route | Purpose |
|---|---|
| `POST /mcp` + `GET /mcp` (SSE) | MCP Streamable HTTP via the SDK's `StreamableHTTPServerTransport`, session-managed |
| `POST /mcp/:profile` | Profile-scoped MCP surface (Phase 3) — e.g. `/mcp/phase1_authoring` |
| `GET /openapi.json?profile=` | OpenAPI 3.1 spec generated from the tool registry |
| `POST /tools/:name` | Flat REST tool invocation |
| `GET /healthz`, `/readyz` | Liveness + DB-loaded readiness for the pipeline |

**Why both MCP and OpenAPI.** Open WebUI's native MCP support varies by build; its **Tool Servers speak OpenAPI reliably**, and that is also the path `mcpo` would produce — so generating OpenAPI natively removes the need for `mcpo` as a separate process entirely. It additionally lets the Phase 2/3 orchestrator call tools over plain REST with no MCP client library.

Generate the OpenAPI spec from `toolRegistry` — the `ToolDefinition.inputSchema` is already JSON Schema, so this is a mechanical projection, not hand-authored spec drift.

**Security middleware** (this server will hold client detection data on a LAN):
- Bearer token check against `HAWKEYE_API_TOKEN`, constant-time compare, before any route.
- `express-rate-limit` per token.
- CORS locked to the Open WebUI origin only.
- Structured request log with tool name, profile, caller token id, latency, outcome.

- New: `src/http/gateway.ts`, `src/http/auth.ts`, `src/http/openapi.ts`
- Modified: `src/server.ts` (transport selection), `src/index.ts` (boot path), `package.json` (promote `express`, `cors`, `express-rate-limit` to direct deps — currently only transitive)

**Exit criteria:** `curl -H "Authorization: Bearer …" localhost:8787/openapi.json` lists the profile's tools; a tool call over `POST /tools/search_detections` returns the same payload as the stdio path; unauthenticated request gets 401.

---

## Phase 3 — Tool profiles and context budget (the small-model fix)

### The problem

All 122 tools are registered unconditionally (`registerAllTools()` in `src/tools/index.ts`) and `listTools()` returns `toolRegistry.toMcpTools()` — the whole surface. The full registry (detections + 59 threat-intel + coverage engine + knowledge graph + LOLFarm + reporting) is ~20,400 tokens of definitions, which does not fit in the 16,384-token window vLLM's own Gemma 4 recipe recommends serving at — the task cannot start.

Gemma-4-26B-A4B's native function-calling training makes it materially better at this than a dense 4B, but the right number of tools for "write one detection query" is still ~12, not 122.

### The fix

**`src/tools/profiles.ts`** — named, curated profiles:

| Profile | Tools | Consumer |
|---|---|---|
| `phase1_authoring` | `build_authoring_brief`, `search_detections`, `get_detection`, `list_by_mitre`, `lookup_mitre_technique`, `get_data_sources`, `lookup_lolbas`, `get_lolfarm_context`, `validate_query`, `convert_sigma_to_kql`, `cve_to_detection`, `list_by_logsource` | Gemma via Open WebUI |
| `phase3_reporting` | `generate_hunt_report`, `get_detection`, `lookup_mitre_technique`, `coverage_gaps_detail`, `get_mitigations` | Gemma, report generation |
| `ops_pipeline` | pipeline state-machine tools only | orchestrator (no LLM) |
| `full` | all 122 | Claude Code / stdio |

**Registry changes** (`src/tools/registry.ts`) — additive, non-breaking:

```ts
export interface ToolDefinition {
  name: string;
  description: string;          // existing, Claude-oriented
  shortDescription?: string;    // NEW: ≤160 chars, emitted in compact mode
  profiles?: string[];          // NEW: omitted ⇒ 'full' only
  inputSchema: { … };
  handler: (args) => Promise<unknown>;
}

toMcpTools(opts?: { profile?: string; compact?: boolean })
```

`compact: true` emits `shortDescription` and strips schema `description` fields on obvious params — meaningful token savings across a manifest.

**Schema hygiene.** Gemma 4's documentation advises one to two levels of nesting and simple enums. Audit every `phase1_authoring` tool for:
- enum-constrained values wherever the domain is closed (`source`, `severity`, `platform`, `tactic`) — enums dramatically cut invalid-argument rates
- ≤5 parameters per tool
- no free-form nested objects
- required params genuinely minimal

**Token budget test.** `tests/token-budget.test.js` asserts the serialized `phase1_authoring` compact manifest stays under a set ceiling (~2,500 tokens). CI fails if a new tool bloats the Phase 1 surface. This is the guardrail that keeps the scoping from eroding over time.

- New: `src/tools/profiles.ts`, `tests/token-budget.test.js`
- Modified: `src/tools/registry.ts`, `src/handlers/tools.ts` (accept profile), each tool module (add `shortDescription` + `profiles`)

**Exit criteria:** `/mcp/phase1_authoring` advertises 12 tools; `full` still advertises 122; token budget test green.

---

## Phase 4 — Composite orchestration tools (highest leverage)

### The problem

The detection-engineering logic that makes this repo trustworthy lives in Claude Code `SKILL.md` files under `~/.claude/skills/` — `detect-engineer`'s 7-step pipeline, the LOLBAS hard gate, `killchain-synth`, the validation rubric. **Open WebUI has no concept of these.** Point Gemma at the raw tools and you get data retrieval with none of the guardrails.

Re-encoding the rubric as a long system prompt does not fix this: it converts hard requirements into suggestions, which are intermittently skipped by any model — and at 16K it also spends context that the tool results need.

### The fix — collapse each multi-step skill into one deterministic server-side tool

**`build_authoring_brief({ technique_id, platform, telemetry?, client_id? })`**

Server-side, in code, in one call:
1. `list_by_mitre(technique_id)` — parent + sub-techniques, existing reference rules
2. `lookup_mitre_technique` + `get_data_sources` + `get_mitigations`
3. `get_lolfarm_context(technique_id)` — drivers, hijackable DLLs, RMM, known FPs
4. `lookup_lolbas` for every binary implicated — **the hard gate, enforced in code**: if the technique is binary-scoped and the abuse matrix is not fully enumerated, the brief returns `gate: BLOCKED` and the model is given nothing to write from
5. `art_get_tests(technique_id, platform)` — validation artifacts
6. per-client telemetry profile (Phase 6) to constrain fields to what that client actually collects

Returns one structured brief: reference rules, required fields, LOLBAS abuse matrix, known FP suppressions, ART tests, telemetry requirements, gate status.

Effect: the model makes **one** tool call instead of six, cannot skip the LOLBAS gate, and cannot invent fields absent from the client's telemetry.

**`validate_query({ query, platform, technique_id?, brief_id? })`** — deterministic validation, no model judgment:

| Platform | Checks |
|---|---|
| Sigma | YAML parse; sigma spec v2.0.0 schema (repo already declares `sigmaSpecVersion`); logsource/detection/condition presence; condition references defined selections |
| KQL | tokenize; bracket/paren balance; operator allowlist; table name validity; `where` before `project`/`summarize` |
| SPL | balance; command allowlist; leading `|` correctness; `tstats` field validity |
| All | field cross-check against the brief's required fields; hardcoded-IOC detector (an existing anti-pattern in CLAUDE.md); FP-filter presence |

Returns per-dimension scores (Evasion, Fields, Paths, FP, Syntax) + composite + hard `pass|fail`. Same rubric as the skill, now executable and callable by non-LLM pipeline code.

**`synthesize_killchain({ technique_ids[], platform, window })`** — server-generated correlation scaffold (KQL let-join, SPL phase-scored, Sigma correlation) with per-phase entity join keys, so the model fills in phase predicates rather than inventing correlation structure.

- New: `src/tools/authoring/brief.ts`, `src/tools/authoring/validate.ts`, `src/tools/authoring/killchain.ts`, `src/validators/{sigma,kql,spl}.ts`

**Exit criteria:** golden-file validator corpus (known-good and known-broken rules per platform) passes; a binary-scoped technique with an incomplete abuse matrix returns `gate: BLOCKED`.

---

## Phase 5 — Pipeline state machine (Phases 1 → 2 → 3)

### The problem

Nothing in the repo tracks a generated query's lifecycle, and the described flow goes from "model generated a query" straight to "query all clients." A malformed or hallucinated query reaching every client environment simultaneously is the highest-consequence failure mode in this design.

Enforcing the gate in Open WebUI's Automations config is not enough — that is a UI setting, editable, bypassable, and invisible to audit.

### The fix — the gate lives in the schema, in `ops.db`

**Tables:** `clients`, `pipeline_queries`, `approvals`, `dispatches`, `client_results`, `audit_log`.

**States:**

```
draft ──► validated ──► pending_approval ──► approved ──► dispatched ──► results_in ──► reported
   └──► rejected                    └──► rejected                └──► failed
```

**Hard invariant, enforced in code:** `dispatch-payload` returns nothing unless the row is `approved`, and a row cannot reach `approved` without a passing `validate_query` record plus a distinct human approver identity. Illegal transitions throw.

**REST surface for the orchestrator:**

| Endpoint | Phase |
|---|---|
| `POST /api/v1/queries` | 1 — register generated query (auto-runs validation) |
| `POST /api/v1/queries/:id/approve` \| `/reject` | 1→2 gate — human |
| `GET /api/v1/queries/:id/dispatch-payload` | 2 — fan-out fetch (approved only) |
| `POST /api/v1/queries/:id/results` | 2 — per-client results posted back |
| `POST /api/v1/reports` | 3 — aggregate into report (existing `generate_hunt_report`) |

**Provenance on every row** — model id, prompt hash, brief hash, tool calls made, validator scores, approver identity, timestamps. This is what makes generated detections defensible in client-facing work: you can reconstruct exactly which model, which brief, and whose sign-off produced any query that ran in a client environment.

- New: `src/db/pipeline.ts`, `src/pipeline/state-machine.ts`, `src/http/api-v1.ts`, `src/tools/pipeline/index.ts`

**Exit criteria:** every illegal transition rejected in tests; unapproved query returns 409 on `dispatch-payload`; full round trip draft→reported passes.

---

## Phase 6 — Multi-tenant client isolation

### The problem

`client-profiles/` holds a single markdown file (`nmdc.md`) — informal, not enforced anywhere in code. Meanwhile Phase 2 fans out across multiple clients, and the knowledge graph (`add_learning`, `search_entities`, `get_learnings`) is global. A learning captured while working Client A ("exclude `SCCM` service account", "EDR is CrowdStrike, no Sysmon") will surface in Client B's authoring brief.

This is the same contamination risk as Open WebUI's Memories feature — and the right place to fix it is here, server-side, not by trusting a UI toggle.

### The fix

- `client_id` column on every knowledge-graph table and every pipeline row; **required** in HTTP mode.
- `search_entities`, `get_learnings`, `get_decisions`, `add_learning`, `log_decision` all scope by `client_id`, with an explicit `global` scope for genuinely cross-client tradecraft.
- Formalize client profiles into `clients` rows: telemetry inventory (which log sources they actually have), SIEM platform, naming conventions, standing exclusions.
- `build_authoring_brief` consumes the client's telemetry inventory so generated queries only reference fields that client actually collects — this alone eliminates a large class of "query is valid but returns nothing here" failures in Phase 2.

**Exit criteria:** a learning written under client A is absent from client B's brief and from B's `get_learnings`; brief for a client without Sysmon contains no Sysmon-only fields.

---

## Phase 7 — Open WebUI wiring

**Connections** (per the current settings screenshot):
- Keep the OpenAI-API-type connection to `http://10.10.105.65:8000/v1` (vLLM on the Spark).
- **Disable `https://api.openai.com/v1`**, or restrict model visibility so non-admins cannot select it. As configured, one wrong dropdown pick sends client-derived detection data to a cloud API — which defeats the purpose of self-hosting on the Spark.
- Verify the vLLM launch actually carries `--enable-auto-tool-choice --tool-call-parser gemma4 --reasoning-parser gemma4`. Without them the model returns prose describing tool calls instead of structured `tool_calls`, and the MCP integration fails silently.

**Integrations / Tool Servers:** register `http://<host>:8787/openapi.json?profile=phase1_authoring` with the bearer token. Register `phase3_reporting` as a second, separate tool server. Never register `full`.

**Model profile:** dedicated Open WebUI model entry for the pipeline — temperature 0.1–0.2, thinking mode off, tools scoped to the Phase 1 profile, and a **short** system prompt (the checklist, not the full skill text; the gates now live in server code).

**General settings:** Community Sharing **off**; Memories off or narrowly scoped (server-side `client_id` scoping now covers this properly); Calendar off if unused; Webhooks/Automations admin-only with the target pinned to the orchestrator endpoint.

---

## Phase 8 — Testing and observability

| Area | Test |
|---|---|
| Transport | stdio and HTTP return identical payloads for the same tool call |
| Auth | missing/wrong token → 401; rate limit trips |
| Profiles | `phase1_authoring` = 12 tools, `full` = 122; token budget under ceiling |
| Validators | golden corpus of valid + broken Sigma/KQL/SPL, per platform |
| Gates | binary-scoped technique with incomplete abuse matrix → `BLOCKED` |
| State machine | every illegal transition rejected; unapproved dispatch → 409 |
| Concurrency | 200 parallel `ops.db` writes, zero lost; corpus DB untouched |
| Isolation | client A learning invisible to client B |

**Observability:** structured JSON logs (tool, profile, client_id, latency, outcome), `/metrics` with per-tool latency and error rates, `/healthz` + `/readyz`. Phase 2 fan-out depends on this service being up — it needs to be monitorable.

---

## Sequencing

| Order | Phase | Why this position | Rough effort |
|---|---|---|---|
| 1 | 0 — baseline | Nothing else is safe to refactor without it | 0.5 day |
| 2 | 1 — datastore split | P0 correctness; must precede any concurrent access | 2–3 days |
| 3 | 2 — dual transport | P0 integration; nothing testable end-to-end until this exists | 2–3 days |
| 4 | 3 — profiles + budget | Cheap, immediately improves model behavior | 1–2 days |
| 5 | 4 — composite tools | Highest leverage on output quality | 4–5 days |
| 6 | 5 — state machine | Required before Phase 2 touches real clients | 3–4 days |
| 7 | 6 — client isolation | Required before multi-client production use | 2–3 days |
| 8 | 7 — Open WebUI wiring | Config only, but validates the whole chain | 0.5 day |
| 9 | 8 — tests + observability | Continuous; harden before go-live | 2–3 days |

Phases 1–3 are the minimum to get a working Phase 1 demo. Phases 4–6 are the minimum before any generated query is allowed to reach a client environment.

---

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| `saveDb()` full-image rewrite under concurrency → lost writes | **Critical** | Phase 1 datastore split + write mutex; readonly guard on corpus |
| Unapproved/malformed query fans out to all clients | **Critical** | Phase 5 state machine invariant, enforced in schema not UI |
| `better-sqlite3` native build fails on aarch64 Spark | Medium | Verify prebuild early; fallback to separate small sql.js `ops.db` + mutex |
| vLLM missing tool-parser flags → silent tool-call failure | Medium | Assert structured `tool_calls` in a startup smoke test against the endpoint |
| Cross-client knowledge contamination | Medium | Phase 6 `client_id` scoping, server-side |
| Client data egress via the enabled OpenAI cloud connection | Medium | Disable connection; restrict model visibility |
| Tool surface creep back toward 122 for Phase 1 | Low | Token budget test in CI |
| Open WebUI native MCP support varies by build | Low | OpenAPI surface is the guaranteed path; MCP HTTP is the bonus |

---

## What this plan deliberately does not do

- **No rewrite of the Claude Code skills.** They stay as-is for stdio/frontier-model use. Phase 4 re-implements their *enforcement* server-side; it does not replace the richer authoring workflow you get with Claude.
- **No migration off sql.js for the corpus.** The read path over 12,810 detections works and is architecture-independent (a real advantage on ARM). Only mutable state moves.
- **No autonomous execution.** Unlike upstream's LangGraph pipeline, nothing here runs Atomic tests or auto-opens PRs. The human approval gate in Phase 5 is the deliberate stopping point.
