<div align="center">

<img src="assets/logo.png" alt="OCSF Console IR logo" width="200" />

<h1>OCSF Console IR</h1>

<p><b>Incident response for the terminal, not another platform to deploy.</b></p>

</div>

<p align="center">
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/releases"><img src="https://img.shields.io/github/v/release/Ashfaaq98/ocsf-console-ir?display_name=tag" alt="Release" /></a>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml"><img src="https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
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
- **Case model that matches the schema:** cases hold findings as *members* (their own tab) and events
  as *evidence*, and the same finding can belong to more than one case
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
> Headless mode and the external threat-intel plugins are experimental (see notes below).

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

```bash
console-ir demo
```

That loads a sample incident into a **throwaway database** and opens the TUI. It never touches your
real data, so it is safe to run first and safe to run again.

The sample is one coherent incident — a phishing attachment leads to encoded PowerShell, credential
access, and C2 beaconing on a single host — so the findings queue, the case model, and the indicator
pivot all have something real to show.

When you want your own data:

```bash
console-ir ingest events.jsonl   # a file
console-ir ingest ./incoming     # a directory
console-ir                       # open the TUI
```

Console-IR opens on the **findings queue** whenever detections are waiting. From there:

- **Enter** — open the finding: evidence artifacts, the events it came from, and its indicators
- **`s`** set status, **`v`** set verdict, **`e`** escalate it into a case
- **`A`** — switch to **ALL EVENTS** and open one to see **GeoIP/WHOIS enrichment** attached,
  grouped one card per indicator and updating in place as async lookups land

[![TUI walkthrough](assets/demo.gif)](assets/demo.mp4)

## Commands

```
console-ir                    open the TUI
console-ir ingest <path|->    a file, a directory, or stdin  (--watch, --no-enrich)
console-ir demo               sample incident in a throwaway database
console-ir list               findings | cases | events   (works without a TTY)
console-ir reset              clear the database
console-ir version
```

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

One command, and the path decides what happens — the way `cp` and `tar` work:

```bash
console-ir ingest events.jsonl        # a file
console-ir ingest ./incoming          # every matching file in a directory
console-ir ingest ./incoming --watch  # ...and keep tailing it
cat events.json | console-ir ingest - # stdin
```

Records are enriched (GeoIP, WHOIS) as they arrive. Pass `--no-enrich` to skip the lookups on a bulk
load, `--case "Title"` to attach everything to a case.

**While the TUI is running**, files dropped into the watched folder are picked up automatically:

```bash
console-ir --ingest-dir ./incoming    # default is ./incoming
```

**Over HTTP** *(experimental)* — POSTed payloads are written into the watched folder and ingested
from there. Localhost by default; a bearer token is required on non-loopback binds:

```bash
console-ir --http-ingest-enable --http-ingest-bind 127.0.0.1:8081
```

See [internal/ingest/](internal/ingest/) for the implementations.

## Enrichment & plugins

**GeoIP and WHOIS are built in** and run in-process, with no configuration and no external services.

Threat-intel integrations (**MISP, OpenCTI, IntelOwl**) run as optional external plugins over
Redis Streams for distributed deployments. They're disabled by default; enable one with an
`.enabled` marker next to its executable (e.g. `plugins/misp/misp.enabled`). See
[`docs/plugins.md`](docs/plugins.md).

## Configuration

### Where your data lives

Console-IR keeps its database, config and logs in stable per-user directories, so it opens the
same cases whichever folder you launch it from. Run `console-ir version` to see the resolved paths.

| | Linux / BSD | macOS | Windows |
|---|---|---|---|
| Database | `$XDG_DATA_HOME/console-ir` → `~/.local/share/console-ir` | `~/Library/Application Support/console-ir` | `%LOCALAPPDATA%\console-ir` |
| Config | `$XDG_CONFIG_HOME/console-ir` → `~/.config/console-ir` | `~/Library/Application Support/console-ir` | `%APPDATA%\console-ir` |
| Logs | `$XDG_STATE_HOME/console-ir` → `~/.local/state/console-ir` | `~/Library/Logs/console-ir` | `%LOCALAPPDATA%\console-ir\logs` |

`XDG_*` environment variables are honoured on every platform. Override individually with
`--data-dir`, `--config-dir`, `--log-dir` (or `--db` for the database file itself), or pass
`--portable` to keep everything beside the working directory — useful on a USB stick or a jump box
you don't want to leave traces on.

Logs go to a single `console-ir.log`, rotated at 5 MB with three older generations kept (20 MB
maximum). Every line carries a level and the subsystem that emitted it, so failures are greppable:

```
2026-07-30 17:15:21 WARN  [whois] lookup failed example.bd: no whois server found
```

`--log-level debug|info|warn|error` sets the threshold (default `info`). `debug` adds keystrokes and
query timings; `warn` keeps only failures.

The watched drop folder is the exception: it stays relative to where you launch (`./incoming`),
because a landing zone buried under `~/.local/share` is one you can't drop files into. Point it
anywhere with `--ingest-dir`.

### Other settings

- **LLM provider** (optional): set the provider/model/API key from the TUI's LLM Settings
  (Shift+L), or copy [`config/llm_settings.sample.json`](config/llm_settings.sample.json) into your
  config directory as `llm_settings.json`. With no config, Console-IR defaults to a local Ollama
  model.
- **Redis** (optional): pass `--redis redis://host:6379` only to enable distributed mode.
  The default is standalone with no external services.
- **Themes**: press `t` to cycle, `T` for high-contrast, `C` for colourblind-safe. Five ship —
  `dark` (default), `light`, `gruvbox`, `high-contrast` and `cb-safe`. Your choice is remembered.
  The accessibility themes matter more than they look: severity is colour-coded, so red/green
  confusion is a correctness problem here, not a preference.

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
  findings. Press `A` for all events, or drop `examples/sample-events.jsonl` into `./incoming/`
  for a sample that includes one. Note the queue hides already-triaged findings by default —
  press `o` to show everything.
- **Empty event list?** Run `console-ir demo` to see the tool with data in it, or
  `console-ir ingest examples/sample-events.jsonl` to load the shipped sample into your own database.
- **Dropped a file in and nothing happened?** The watched folder is `./incoming` (relative to where
  you launched). Check with `console-ir --help`, or point it elsewhere with `--ingest-dir`.
- **Cases missing after upgrading?** v0.2.0 moved the database to a per-user directory and printed
  the move. Run `console-ir version` to see where it is now.
- **TUI won't start?** Use a native terminal; it needs a real TTY. (`--no-tui` is experimental and does not ingest.) `console-ir list` works anywhere.
- **Enrichment missing?** Lookups are asynchronous, but the open event refreshes itself when they
  land. If a card never appears, the lookup failed — check the log (`console-ir version` prints its
  path). `r` still forces a reload.
- **Build issues?** Run `go mod download` then `make build`.
- **Redis errors?** You don't need Redis unless you explicitly pass `--redis ...`.

### Upgrading from v0.1.x

**Your database moves.** v0.1.x kept it at `./data/console-ir.db`, relative to wherever you
happened to launch the binary. On first run v0.2.0 moves that file — plus `config/llm_settings.json`,
which can hold a plaintext API key — into the per-user directories above, and prints each move.
Nothing happens silently, and nothing is moved if a database is already at the destination. Pass
`--portable` to keep the old layout instead.

**The database itself migrates in place**: OCSF identity columns are added and backfilled from the
stored raw events, observables are extracted, and `event_type` is rewritten to OCSF category slugs
(`system`, `findings`, `iam`, `network`, …) — replacing the incorrect values earlier versions
produced. Nothing is lost, and the migration is safe to re-run.

**Downgrading afterwards is not clean.** A v0.1.x binary reads the migrated database but only offers
its old five type filters, none of which match the new values, so filtering appears to return
nothing. Back up the database (`console-ir version` prints its path) before you upgrade if you may
need to roll back.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for workflow, coding standards, and local checks.
Quick version: fork, branch, add tests, run `make check`, open a PR.

## Security

Do **not** commit API keys or secrets. Use the TUI or the sample config; real settings live in
your per-user config directory (mode 0700), not in the repo. See [`SECURITY.md`](SECURITY.md) to report vulnerabilities.

## License

[AGPLv3](LICENSE).

## Support

- Issues: <https://github.com/Ashfaaq98/ocsf-console-ir/issues>
- Discussions: <https://github.com/Ashfaaq98/ocsf-console-ir/discussions>
