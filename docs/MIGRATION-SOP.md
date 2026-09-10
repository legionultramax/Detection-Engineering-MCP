# Migration SOP — standing this server up on a new machine

Procedure for moving or deploying Harris HawkEye MCP. Written to be followed in order by someone
who has not read the codebase.

**The one thing that catches everyone:** the detection database is not in git. It is ~163 MB and
gitignored, so a fresh clone produces a server with **zero detections** that answers every query
with silence. Step 3 is not optional.

---

## Decide two things first

Both change the steps you follow, and both are easier to decide now than to discover later.

**Who connects to it?**

| Client | Transport | Notes |
|---|---|---|
| Claude Desktop / Claude Code | `stdio` (default) | Local, one client, no listener |
| A web UI, or anything over the network | `http` | Needs a token and a bind decision |

**Where does the database come from?**

| | When to choose it | Time |
|---|---|---|
| **A. Copy an existing database** | Someone already has a built one | Minutes |
| **B. Index from rule repositories** | First build, or you want current rules | 30–60 min, ~7 GB of clones |

Take **A** if the option exists. It removes cloning, indexing and network from the critical path.

---

## Step 1 — Node

Node 18 or newer; **24 LTS is what this is tested against**.

`better-sqlite3` is a native module, but it ships prebuilt binaries, so no compiler is needed in
practice. If `npm ci` tries to run `node-gyp rebuild`, a prebuild was unavailable for your Node
version — **pin to Node 24 rather than installing build tools.**

No-root install on Linux:

```bash
curl -fsSLO https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.xz
curl -fsSL https://nodejs.org/dist/v24.20.0/SHASUMS256.txt | grep linux-x64.tar.xz | sha256sum -c -
tar -xJf node-v24.20.0-linux-x64.tar.xz -C "$HOME/.local" --strip-components=1
export PATH="$HOME/.local/bin:$PATH"
node --version
```

Swap `x64` for `arm64` on aarch64. On Windows without admin: unpack the `.zip` to
`%LOCALAPPDATA%\nodejs` and add that to your user PATH.

## Step 2 — Clone and build

```bash
git clone https://github.com/legionultramax/Detection-Engineering-MCP.git
cd Detection-Engineering-MCP
npm ci
npm run build
```

Two gates before going further. Do not skip these — they take seconds and catch a bad Node or a
broken install immediately:

```bash
npm run lint          # tsc --noEmit --strict — must exit 0
npm run tools:check   # must print: ok — 132 tools registered, documentation agrees
```

## Step 3 — The database

### Option A — copy an existing one

Get `detections.db` from whoever has it and put it anywhere readable. **Confirm it is the current
file**, not an older copy:

```bash
DETECTIONS_DB_PATH=/abs/path/detections.db npm run fts:status
```

Expect the detection count and `index: <n> rows, current`. If it reports the index missing or
stale, the copy predates the full-text index — build it per Step 5, or get a newer file. An old
copy still works, it just silently falls back to substring search.

### Option B — index from source

```bash
mkdir -p ~/hawkeye-rules && cd ~/hawkeye-rules
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
git clone --depth 1 https://github.com/splunk/security_content.git splunk
git clone --depth 1 https://github.com/elastic/detection-rules.git elastic
git clone --depth 1 --filter=blob:none --sparse https://github.com/Azure/Azure-Sentinel.git sentinel
cd sentinel && git sparse-checkout set Detections Solutions "Hunting Queries"
```

Sentinel is the large one; sparse-checkout keeps it to the three directories that hold rules.

> **Put these somewhere that is not synced to cloud storage.** In a OneDrive- or Dropbox-backed
> folder the files become cloud-only placeholders, and every read costs a network round trip. That
> turned a 5-minute index into an estimated 55 minutes, at roughly 3 files per second, on 2.8 KB
> files. It is latency, not bandwidth, and pinning the folder does not fix it.

Then index, pointing at rule directories rather than repository roots:

```bash
export DETECTIONS_DB_PATH=/abs/path/data/detections.db
export SIGMA_PATHS=~/hawkeye-rules/sigma/rules,~/hawkeye-rules/sigma/rules-emerging-threats,~/hawkeye-rules/sigma/rules-threat-hunting
export SPLUNK_PATHS=~/hawkeye-rules/splunk/detections
export STORY_PATHS=~/hawkeye-rules/splunk/stories
export ELASTIC_PATHS=~/hawkeye-rules/elastic/rules
export KQL_PATHS="~/hawkeye-rules/sentinel/Detections,~/hawkeye-rules/sentinel/Solutions,~/hawkeye-rules/sentinel/Hunting Queries"
export HAWKEYE_SKIP_SYNC=1
node dist/index.js
```

The server indexes on startup, then keeps running — stop it once the log says
`Indexing complete`. Expect roughly 5 minutes against local files.

`ELASTIC_PATHS` must point at `<repo>/rules`, not the repository root: MITRE ATT&CK is loaded from a
STIX bundle the server locates relative to it. If the log says
`MITRE ATT&CK STIX bundle not found`, that path is wrong and about a third of the tools will return
nothing.

## Step 4 — Reference data

Three datasets are separate from the rule corpus. Each is a deliberate decision.

**LOLFarm — 7,519 entries, 8 metadata endpoints.** Driver hashes, DLL hijack paths, RMM tool names,
abused domains. Metadata about abusable software, not the software.

```bash
# writable, then call sync_lolfarm through any MCP client
```

**Five of the eight sources have a live feed** — LOLDrivers, HijackLibs, LOLRMM, LoFP and LOLBAS.
`sync_lolfarm` reports per-source status.

The other three publish nothing machine-readable and stay on seed data. They return
`status: "no_upstream"` with a `reason` saying what was checked; that is permanent, so retrying will
not help:

| Source | Why |
|---|---|
| **WADComs** | No JSON API. One Markdown file per tool with YAML front matter (144 files). Carries no ATT&CK technique IDs, so synced rows could not be reached by `get_lolfarm_context`, which selects on `mitre_techniques` |
| **LOTS** | No public data repository. `lots-project.com` serves HTML and returns **200 for unknown paths** |
| **MalAPI** | No official repository. `malapi.io` also returns 200 for unknown paths; every existing consumer keeps a private scrape |

Because two of those hosts answer unknown paths with 200-and-HTML rather than 404, `sync_lolfarm`
checks the response body and reports "expected JSON but got markup" instead of failing inside
`JSON.parse` with an error about an unexpected `<`.

**Sublime — 1,234 email detection rules.** A `git clone` of `sublime-security/sublime-rules`, then
indexed. Set `SUBLIME_REPO_PATH` to somewhere outside any synced folder.

**Atomic Red Team — not populated, on purpose.** The sync clones a repository of working attack
payloads. On an EDR-monitored endpoint that raises alerts. Enable it knowingly or leave the 7 ART
tools returning empty.

## Step 5 — Full-text index

Required if you took Option A with an older database, and after any re-index or data load.

```bash
npm run fts:status   # reports without changing anything
npm run fts:build    # ~2-5 seconds per 5,000 rules
```

The index lives **inside** the database file, because a read-only server cannot build one. Adding
detections without rebuilding leaves it stale — search detects the row-count mismatch, says so, and
falls back to substring matching rather than returning a partial answer.

## Step 6 — Configure the client

### stdio (Claude Desktop / Claude Code)

```json
{
  "mcpServers": {
    "harris-hawkeye": {
      "command": "node",
      "args": ["/abs/path/dist/index.js"],
      "env": {
        "DETECTIONS_DB_PATH": "/abs/path/data/detections.db",
        "HAWKEYE_SKIP_SYNC": "1"
      }
    }
  }
}
```

### HTTP (web clients, shared instances)

```bash
export DETECTIONS_DB_PATH=/abs/path/detections.db
export HAWKEYE_READONLY=1
export HAWKEYE_TOOL_PROFILE=phase1-authoring
export HAWKEYE_TRANSPORT=http
export HAWKEYE_HTTP_TOKEN="$(openssl rand -hex 32)"
node dist/index.js
```

`initialize` returns an `Mcp-Session-Id` header; every subsequent request must echo it back. There
is an unauthenticated `/health` endpoint for liveness checks.

**Open WebUI connects to this directly.** Native MCP support landed in v0.6.31 and is Streamable
HTTP only, which is what this server speaks — `mcpo` is for bridging *stdio* servers and is not
needed here. For the system prompt, tool-routing rules and model-side setup, see
[GEMMA-RUNBOOK.md](GEMMA-RUNBOOK.md).

**Security defaults, and why they are not warnings.** The listener binds `127.0.0.1` unless told
otherwise, and **refuses to start on a non-loopback address without a token** — this server exposes
a detection corpus and its tool surface, and an unauthenticated listener on `0.0.0.0` hands both to
anyone who can route to the host. If the client is on another machine, prefer an SSH tunnel over
widening the bind.

`HAWKEYE_READONLY=1` is strongly recommended for anything shared. It is enforced by SQLite rather
than by convention, and it withholds the 8 write tools from the tool list instead of letting a
caller spend a turn on one that cannot work.

## Step 7 — Verify

```bash
npm run verify:readonly   # 53  read-only really is read-only
npm run verify:search     # 36  FTS5, ranking, query-syntax safety
npm run verify:queries    # 95  language specs and the validation gate
npm run verify:aql        # 74  QRadar AQL spec, validation, pipeline constraints
npm run verify:coverage   # 16  translation brief coverage
npm run verify:http       # 26  the HTTP transport, on an ephemeral port
npm test                  # 138 full contract suite — needs a writable database
```

All local, all offline. Run `npm test` against a copy, since it writes.

A healthy stdio start looks like:

```
[db] Initializing database at /abs/path/detections.db (read-only)
[tools] Registry initialized with 132 tools
[harris-hawkeye-mcp] read-only mode — 15176 detections available, indexing disabled
[harris-hawkeye-mcp] Server started (v1.0.0 - Enhanced Edition, stdio)
```

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every search returns nothing | No database, or `DETECTIONS_DB_PATH` unset and pointing at the empty default. Check the startup log for the path it opened |
| `read-only mode requested but no database exists` | Correct behaviour. A read-only server cannot create or index one — point it at a populated file |
| Search results feel unranked | The FTS index is missing or stale. `npm run fts:status`, then `npm run fts:build` |
| `MITRE ATT&CK STIX bundle not found` | `ELASTIC_PATHS` points at the repository root instead of `<repo>/rules` |
| Startup hangs for about a minute | An upstream git sync cannot reach its remote, and it blocks the event loop. Set `HAWKEYE_SKIP_SYNC=1` |
| Client connects then goes silent | Same cause as above |
| `Refusing to bind …` | A non-loopback bind with no `HAWKEYE_HTTP_TOKEN`. Deliberate |
| HTTP 400 on every request after `initialize` | The client is not sending back the `Mcp-Session-Id` header |
| `npm ci` runs `node-gyp rebuild` | No `better-sqlite3` prebuild for your Node version. Pin Node 24 |
| `.env` file ignored | There is no `dotenv` dependency. Use the process environment |
| Tool count is not 132 | Stale build. `npm run build`, then `npm run tools:check` |
| ART tools return nothing | Not indexed, deliberately. See Step 4 |

## Moving an existing installation

1. `npm run fts:status` on the old machine — confirm the database is current.
2. Copy `detections.db` across. Nothing else in `data/` is needed.
3. Steps 1, 2, 6, 7 on the new machine. Skip 3, 4 and 5 entirely.
4. Re-run `npm run fts:status` on the new host to confirm the index survived the copy.

The database is self-contained: rules, MITRE, LOLFarm, Sublime, the coverage mappings and the
full-text index are all inside that one file. The rule repositories are only needed to build or
refresh it, never to run.
