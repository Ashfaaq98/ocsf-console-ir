<div align="center">

<img src="assets/logo.png" alt="OCSF Console IR logo" width="200" />

<h1>OCSF Console IR</h1>

<p><b>Incident response for the terminal, not another platform to deploy.</b></p>

</div>

<p align="center">
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/releases"><img src="https://img.shields.io/github/v/release/Ashfaaq98/ocsf-console-ir?display_name=tag" alt="Release" /></a>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml"><img src="https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/pkgs/container/console-ir"><img src="https://img.shields.io/badge/docker-ghcr.io%2Fashfaaq98%2Fconsole--ir-2496ED?logo=docker&logoColor=white" alt="Docker" /></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/go-%E2%89%A51.23-00ADD8?logo=go&logoColor=white" alt="Go" /></a>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/releases"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platforms" /></a>
  <a href="https://schema.ocsf.io/"><img src="https://img.shields.io/badge/OCSF-native-6f42c1" alt="OCSF" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPLv3-blue.svg" alt="License" /></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" /></a>
</p>

## Overview

Console-IR is a **terminal-first, OCSF-native** incident-response workspace. It ingests
[OCSF](https://schema.ocsf.io/) detections and events, enriches indicators, and gives a security
analyst a fast, keyboard-driven place to triage, investigate, and document incidents, all from a
**single binary backed by SQLite, with no broker, no server, and no cloud dependency**.

You open it to a ranked queue of **findings** — the detections your SIEM or EDR actually flagged —
rather than to a wall of log lines. Raw events stay one keystroke away as the corroboration layer.

It's built for the moment an incident starts: on a jump box, an IR laptop, or a lab, where
you need to investigate *now* rather than stand up a platform first.

## What it is, and isn't

| Console-IR is | Console-IR is not |
|---|---|
| A zero-infrastructure, local-first IR workstation | A replacement for a SIEM, EDR, SOAR, or enterprise case platform |
| A fast OCSF investigation and documentation layer | A collaborative multi-user system (no RBAC or shared backend yet) |
| A keyboard-first tool for technical analysts | A browser-based SOC console |

It complements the tools you already run: your SIEM/EDR collect and detect, MISP/OpenCTI hold
threat intel, and Console-IR is the focused investigation layer once relevant OCSF events exist.

## Features

- **Findings-first triage:** Detection Findings (and any event flagged `is_alert`) land in a queue
  ranked by risk, with OCSF status and verdict set from the keyboard
- **Real OCSF semantics:** findings are updated in place through their `activity_id` lifecycle, so
  one alert reported five times stays one row — not five
- **Indicator pivot:** observables are indexed, so "every event and finding touching this IP, hash,
  or host" is one lookup, not a text search
- **Case model that matches the schema:** cases hold findings as *members* and events as *evidence*,
  and the same finding can belong to more than one case
- **OCSF-native ingestion:** JSON/JSONL files, stdin, folder drop-in, and an optional HTTP endpoint
- **Keyboard-first TUI:** findings, cases, events, timelines, evidence, notes, IOCs, full-text search
- **Built-in enrichment:** GeoIP and WHOIS run in-process, with no external services
- **AI-assisted analysis:** case summaries and a copilot via pluggable LLM providers (Ollama, OpenRouter, Groq, and more); fully optional
- **Local SQLite storage:** full-text search, and your data never leaves the machine
- **Runs fully offline:** one static binary, with no broker, no database server, and no cloud
- **Optional distributed mode:** enable Redis and threat-intel plugins (MISP, OpenCTI, IntelOwl) when you want them

### OCSF coverage

Class handling is driven by a vendored **OCSF 1.8.0** registry, so classes are named and categorised
the way the schema defines them.

| Arrives as | Treated as |
|---|---|
| Findings category (`class_uid` 2001–2008) — Detection Finding, Incident Finding, … | A **finding**: triage queue, status, verdict, evidence, ATT&CK |
| Any activity class with `is_alert: true` | **Both** — a finding to triage *and* an event to query |
| Activity classes (System, IAM, Network, Discovery, Application, …) | An **event**: searchable telemetry and case evidence |

> **Status:** early and evolving (v0.2.x). The TUI workflow is the supported path today.
> Headless/Docker serving and the external plugins are experimental (see notes below).

## Install

```bash
# Homebrew (macOS / Linux)
brew install Ashfaaq98/tap/console-ir

# curl (Linux / macOS)
curl -sSfL https://raw.githubusercontent.com/Ashfaaq98/ocsf-console-ir/main/scripts/install.sh | bash

# From source (Go >= 1.23)
git clone https://github.com/Ashfaaq98/ocsf-console-ir.git
cd ocsf-console-ir && make build
```

## Quick start

Load the shipped sample and open it in the TUI:

```bash
mkdir -p data/incoming
cp examples/sample-events.jsonl data/incoming/
./bin/console-ir serve
```

The shipped sample contains a Detection Finding, so Console-IR opens on the **findings queue**.
From there:

- **Enter** — open the finding: evidence artifacts, the events it came from, and its indicators
- **`s`** set status, **`v`** set verdict, **`e`** escalate it into a case
- **`A`** — switch to **ALL EVENTS** and open one to see **GeoIP/WHOIS enrichment** attached
  (press **`r`** to refresh as async lookups land)

To ingest your own data, drop OCSF `.jsonl` files into `data/incoming/`, either before launch or
while running.

[![TUI walkthrough](assets/demo.gif)](assets/demo.mp4)

## Keys

Press **`?`** in the app for the full list. The ones that matter most:

| Key | Does |
|---|---|
| `D` | Findings queue (detections awaiting triage) |
| `A` | All events |
| `Enter` | Open the selected item |
| `r` | Reload |
| `f` / `F` | Filter events / clear filters |
| `?` | Help · `q` Quit |

In the findings queue:

| Key | Does |
|---|---|
| `s` | Set status (New, In Progress, Suppressed, Resolved, Archived) |
| `v` | Set verdict (True/False Positive, Suspicious, Benign, …) |
| `e` | Escalate into a new or existing case |
| `o` | Toggle between open findings and all findings |

Navigation follows vim conventions: `j`/`k` move, `h`/`l` change pane, `g`/`G` jump to top/bottom,
`J`/`K` page.

## Ingesting events

1. **Folder drop-in (recommended):** drop OCSF `.jsonl`/`.json` files into `data/incoming/`;
   they're ingested and enriched automatically. Files staged before launch are picked up on
   startup. See [internal/ingest/folder.go](internal/ingest/folder.go).
2. **CLI batch:** `./bin/console-ir ingest <file>` pre-loads a file into the store. Note that batch
   import does not run enrichment; open the events in the TUI for that. See [cmd/ingest.go](cmd/ingest.go).
3. **HTTP endpoint** *(experimental)*: accepts POSTed events, localhost by default, with a bearer
   token required on non-loopback binds. See [internal/ingest/http_ingest.go](internal/ingest/http_ingest.go).

## Enrichment & plugins

**GeoIP and WHOIS are built in** and run in-process, with no configuration and no external services.

Threat-intel integrations (**MISP, OpenCTI, IntelOwl**) run as optional external plugins over
Redis Streams for distributed deployments. They're disabled by default; enable one with an
`.enabled` marker next to its executable (e.g. `plugins/misp/misp.enabled`). See
[`docs/plugins.md`](docs/plugins.md).

## Configuration

- **LLM provider** (optional): set the provider/model/API key from the TUI's LLM Settings
  (Shift+L), or copy [`config/llm_settings.sample.json`](config/llm_settings.sample.json) to
  `config/llm_settings.json`. With no config, Console-IR defaults to a local Ollama model.
- **Redis** (optional): pass `--redis redis://host:6379` only to enable distributed mode.
  The default is standalone with no external services.

## Architecture

![Architecture](assets/architecture.png)

Records flow **ingest → OCSF parser → router → SQLite**. The router reads `class_uid` and
`is_alert` to decide what arrived: Findings-category records become findings, activity classes
become events, and an alertable activity event becomes both. Indicators are extracted into an
indexed `observables` table on the way through, which is what makes the pivot fast.

Enrichment runs in-process via a worker queue. The TUI reads from SQLite, and the LLM subsystem
powers summaries and the copilot. Redis is an *optional* transport for distributed/external
plugins, not a requirement.

## Troubleshooting

- **No findings?** Your data may contain no detections — findings come from OCSF Findings classes
  (`class_uid` 2001–2008) or events flagged `is_alert`. Plain telemetry produces events, not
  findings. Press `A` for all events, or drop `examples/sample-events.jsonl` into `data/incoming/`
  for a sample that includes one. Note the queue hides already-triaged findings by default —
  press `o` to show everything.
- **Empty event list?** Drop `examples/sample-events.jsonl` into `data/incoming/` and press `r`.
- **TUI won't start?** Use a native terminal; it needs a real TTY. (`--no-tui` is experimental and does not ingest.)
- **Enrichment missing?** It's asynchronous, so press `r` to refresh an event's detail once WHOIS/GeoIP lookups complete.
- **Build issues?** Run `go mod download` then `make build`.
- **Redis errors?** You don't need Redis unless you explicitly pass `--redis ...`.

### Upgrading from v0.1.x

Opening an existing database migrates it in place: OCSF identity columns are added and backfilled
from the stored raw events, observables are extracted, and `event_type` is rewritten to OCSF
category slugs (`system`, `findings`, `iam`, `network`, …) — replacing the incorrect values earlier
versions produced. Nothing is lost, and the migration is safe to re-run.

**Downgrading afterwards is not clean.** A v0.1.x binary reads the migrated database but only offers
its old five type filters, none of which match the new values, so filtering appears to return
nothing. Back up `data/console-ir.db` first if you need to roll back.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for workflow, coding standards, and local checks.
Quick version: fork, branch, add tests, run `make check`, open a PR.

## Security

Do **not** commit API keys or secrets. Use the TUI or the sample config, and keep
`config/llm_settings.json` ignored. See [`SECURITY.md`](SECURITY.md) to report vulnerabilities.

## License

[AGPLv3](LICENSE).

## Support

- Issues: <https://github.com/Ashfaaq98/ocsf-console-ir/issues>
- Discussions: <https://github.com/Ashfaaq98/ocsf-console-ir/discussions>
