<div align="center">

<img src="assets/logo.png" alt="OCSF Console IR logo" width="200" />

<h1>OCSF Console IR</h1>

<p><b>Incident response for the terminal</b></p>

<p>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/releases"><img src="https://img.shields.io/github/v/release/Ashfaaq98/ocsf-console-ir?display_name=tag" alt="Release" /></a>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml"><img src="https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/go-%E2%89%A51.23-00ADD8?logo=go&logoColor=white" alt="Go" /></a>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/releases"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platforms" /></a>
  <a href="https://schema.ocsf.io/"><img src="https://img.shields.io/badge/OCSF-native-6f42c1" alt="OCSF" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPLv3-blue.svg" alt="License" /></a>
</p>

</div>

<div align="center">
  <img src="assets/demo.gif" alt="Console-IR in use: working the findings queue, opening a detection, and escalating it into a case" width="900" />
</div>

## Overview

Console-IR is a **terminal-first, OCSF-native** incident-response workspace. It ingests
[OCSF](https://schema.ocsf.io/) detections and events, enriches indicators, and gives an analyst a
keyboard-driven place to triage, investigate and document incidents. You open it to a ranked queue of **findings**, the detections your SIEM or EDR actually flagged. Raw events stay one keystroke away as the corroboration layer. Everything runs from a single binary backed by SQLite. 

> **Found a bug? Please [open an issue](https://github.com/Ashfaaq98/ocsf-console-ir/issues/new).**
> Include what you ran, what you expected and what happened; `console-ir version` prints the build
> and resolved paths. Bug reports on early software are the most useful thing you can send.

## Install

```bash
# Homebrew (macOS)
brew install --cask Ashfaaq98/tap/console-ir

# curl (Linux / macOS)
curl -sSfL https://raw.githubusercontent.com/Ashfaaq98/ocsf-console-ir/main/scripts/install.sh | bash

# Scoop (Windows)
scoop bucket add ashfaaq98 https://github.com/Ashfaaq98/scoop-bucket
scoop install console-ir

# From source (Go >= 1.23)
git clone https://github.com/Ashfaaq98/ocsf-console-ir.git
cd ocsf-console-ir && make build
```

Prebuilt archives for Linux, macOS and Windows — Intel and ARM on all three — are on the
[releases page](https://github.com/Ashfaaq98/ocsf-console-ir/releases), with checksums and an SBOM.
More in [docs/installation.md](docs/installation.md).

## Quick start

```bash
console-ir demo
```

Loads a working week of four cases in different states, a few hundred events, one intrusion still
being worked into a throwaway database and opens the TUI. It never touches your real data.

Then point it at your own:

```bash
console-ir ingest events.jsonl   # a file, a directory, or - for stdin
console-ir                       # open the TUI
```

<div align="center">
  <img src="assets/findings.png" alt="The findings queue: a risk-ranked list on the left, the selected finding's evidence, indicators and ATT&amp;CK mapping on the right" width="900" />
</div>

Press `?` anywhere for the keys that apply to the screen you are on.
[docs/getting-started.md](docs/getting-started.md) walks through a first investigation.

## Why Console-IR?

Most IR tooling assumes you have already deployed it: a backend, a browser, a database to operate.
That holds in the SOC and breaks everywhere else: on a jump box mid-incident, on an IR laptop in a
datacentre, in an airgapped lab, over SSH on a host you were handed ten minutes ago. Console-IR assumes the opposite: one binary you can copy anywhere, storage in a file, an interface
that works over SSH. Ingesting, triaging and writing up a case need no network at all; only the
optional enrichment and LLM features reach outside the machine.


## What it does

**Ingest.** OCSF records from a file, a directory, stdin, or over HTTP — with or without a terminal.
Indicators are extracted and indexed on the way in. Console-IR *reads* OCSF and does not convert to
it: map at the source, which most SIEMs and EDRs can do directly.

**Triage.** Open to a queue ranked by risk, not a wall of log lines. Set status and verdict from the
keyboard, filter and search the queue, escalate a finding into a case with one key.

**Investigate.** Pivot on any indicator — "everything touching this address" is an indexed lookup,
not a text scan. Raw events stay one keystroke away as the corroboration layer, with GeoIP and WHOIS
attached in-process.

**Document.** A case holds findings as *members* and events as *evidence*, with a timeline, a
decision log, and an audit trail of who did what.

**Hand over.** Write the case up as Markdown from inside it, keep every report written, or produce
the same document from the command line for a pipeline.

### Underneath

- **One SQLite file** with full-text search; nothing leaves the machine except the optional
  enrichment and copilot lookups
- **The `activity_id` lifecycle honoured** — one detection reported five times stays one row, and a
  producer update never overwrites your verdict
- **A vendored OCSF 1.9.0 registry** decides what each record is, rather than hand-written guesses:

| Arrives as | Becomes |
|---|---|
| Findings category, `class_uid` 2001–2008 | a **finding** |
| Activity class with `is_alert: true` | **both** a finding and an event |
| Any other activity class | an **event** |

## Where it stands

⚗ marks something shipped but not settled. *Planned* means on the roadmap, not scheduled.

| | Now | Planned |
|---|---|---|
| **Ingest** | Files, directories, stdin, folder watch, HTTP receiver — with or without a terminal | Read from an OCSF data lake; emit Incident Findings back out |
| **Triage** | Risk-ranked queue, status and verdict, filters, search, escalation to a case | — |
| **Investigate** | Indicator pivot, indicators across the whole database | View the raw record; activity around an event; a page per host and per account; count by any field |
| **Cases** | Findings as members, events as evidence, timeline, decision log, audit trail | Write the briefing from the interface — statement, hypotheses, next actions |
| **Reporting** | Case report from the app or the command line, kept in the Reports screen | Weekly and monthly summaries |
| **Enrichment** | GeoIP, WHOIS — in-process, no service to run | Offline GeoIP; VirusTotal |
| **Plugins** | MISP, OpenCTI, IntelOwl ⚗ — separate processes over Redis | The same three in-process, with no broker to run |
| **Copilot** | ⚗ Case summaries and per-case chat; Ollama, OpenRouter, Groq | A configurable request timeout; natural language to a hunt filter |
| **Install** | Linux, macOS, Windows — Intel and ARM. Homebrew cask, Scoop, curl, source | winget, `go install` |
| **Themes** | Six palettes, severity colours proven distinct in every one ⚗ — high-contrast and colourblind are not yet verified screen by screen | — |

## Architecture


Records flow **ingest → OCSF parser → router → SQLite → TUI**. The router reads `class_uid` and
`is_alert` to decide what arrived, and indicators are indexed on the way through, which is what makes
the pivot a single lookup rather than a scan. Enrichment runs on an in-process worker queue, and the
open pane redraws when a result lands.

Full detail in [docs/architecture.md](docs/architecture.md).

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | First run, keys, a worked investigation |
| [Installation](docs/installation.md) | Every install method, verification, building from source |
| [Ingestion](docs/ingestion.md) | Files, directories, stdin, watch mode, HTTP |
| [Configuration](docs/configuration.md) | Paths, logging, LLM providers, themes, Redis |
| [Architecture](docs/architecture.md) | How records flow, the storage model, enrichment |
| [Migration](docs/migration.md) | Upgrading from v0.1.x |
| [Troubleshooting](docs/troubleshooting.md) | When something does not appear |
| [Plugins](docs/plugins.md) | Writing and enabling external plugins |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before writing code — Console-IR is single-author for now.
**Bug reports and feature requests are very welcome** and carry none of that overhead:
[open an issue](https://github.com/Ashfaaq98/ocsf-console-ir/issues/new).

Do **not** commit API keys or secrets. Real settings live in your per-user config directory, not in
the repo. See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[AGPLv3](LICENSE)

- Issues: <https://github.com/Ashfaaq98/ocsf-console-ir/issues>
- Discussions: <https://github.com/Ashfaaq98/ocsf-console-ir/discussions>
