---
name: crowdstrike-falcon-events
description: >-
  Answer questions about CrowdStrike Falcon sensor events using a community data
  dictionary of 998 events (name, description, supported platforms). Use this
  whenever the user asks what a Falcon event means, which events exist for a
  platform (Windows/Linux/macOS/iOS/Android/ChromeOS/Falcon Container/
  Kubernetes/Public Cloud/Forensics), how to map events for threat hunting,
  detection engineering, SIEM/Splunk onboarding, FDR (Falcon Data Replicator),
  or CrowdStrike event-schema work.
license: Apache-2.0
---

# CrowdStrike Falcon Events Data Dictionary

A searchable reference of 998 CrowdStrike Falcon sensor events, extracted from the official
(auth-gated, 1,500+ page) PDF into clean plain text. Each record has three fields: `header` (the
event name), `description` (human-readable), and `platforms` (comma-separated list of supported
OSes / sensor environments).

## When to use this skill

Use it for any question about CrowdStrike Falcon sensor events, e.g.:

- "What does DnsRequest / ProcessRollup2 / NetworkConnectIP4 mean?"
- "Which events fire on macOS only?" / "List all Active Directory events."
- "What event should I hunt on for process execution on Linux?"
- "Map Falcon events to MITRE ATT&CK / build a Splunk or CQL detection."
- "Diff the event schema between two snapshots."

**Do not use it as authoritative for production detections** — it is an unofficial community
export. Always cite the official docs as source of truth.

## How to load the data

The dataset is small and fits directly into a modern context window, but prefer reading it from disk
and filtering programmatically over pasting it into context.

**Vendored locally in this repository** (offline, no fetch required):

```
data/third-party/crowdstrike-events/sensor_events.csv
```

Columns: `header,description,platforms` — one row per event, `platforms` is a quoted
comma-separated list.

**Upstream, if a fresher snapshot is needed:**

- CSV: `https://raw.githubusercontent.com/erickatwork/CrowdStrike-Falcon-Events-Data-Dictionary/main/data/current/sensor_events.csv`
- Markdown: `.../data/current/sensor_events.md`
- Repo map for agents: `.../main/llms.txt`

`data/current/` is an auto-maintained mirror of the newest ISO-dated folder (e.g. `data/2026-06-02/`);
read a dated folder directly if you need a fixed snapshot.

If you cannot read or fetch the file, **say so explicitly rather than guessing from memory.**

## How to answer

1. Load the data as above. Do not answer from memory for event specifics.
2. Match the event name exactly where possible — the dataset is **case-sensitive PascalCase**
   (`ProcessRollup2`, not `process_rollup2`). If given another casing, search loosely and confirm.
3. Quote `description` and `platforms` verbatim.
4. For "which events…" questions, filter the full list rather than recalling a subset, and report
   counts.
5. Always include the caveat: unofficial export, verify against
   https://docs.crowdstrike.com/r/en-US/sensormap.ftmap

## Notes on the data

- **337 of the 998 events have an empty description** (undocumented in the source PDF). Say so
  rather than inventing a definition.
- `platforms` values include OSes and sensor environments: Windows, Linux, macOS, iOS, Android,
  ChromeOS, Falcon Container, Kubernetes, Public Cloud, Vmcluster, Forensics.

## Known extraction artifacts in this snapshot

Found while building the CQL field catalog. These are reasons to verify rather than trust:

- **`ProcessRollup2` lists `Windows` only.** Cross-platform process telemetry needs
  `SyntheticProcessRollup2` (Windows, Linux, macOS, Falcon Container). A Linux process rule written
  against `ProcessRollup2` returns nothing.
- **`DnsRequest` lists `Android` only**, while its description plainly describes general host DNS
  behaviour. Almost certainly a PDF-extraction artifact rather than fact.

Treat `platforms` as a hint, not a constraint, and confirm against the official sensor map before
relying on it for a production detection.

## Caveats

- Unofficial, community-maintained. Not affiliated with or endorsed by CrowdStrike, Inc.
  "CrowdStrike" and "Falcon" are trademarks of CrowdStrike.
- Event definitions are the property of CrowdStrike; reproduced for reference.
- Snapshots are point-in-time. Check the snapshot date and note that newer events may exist in the
  live documentation.
