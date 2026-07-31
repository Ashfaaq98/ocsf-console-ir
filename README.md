<div align="center">

<img src="assets/logo.png" alt="OCSF Console IR logo" width="200" />

<h1>OCSF Console IR</h1>

<p><b>Incident response for the terminal, not another platform to deploy.</b></p>

<p>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/releases"><img src="https://img.shields.io/github/v/release/Ashfaaq98/ocsf-console-ir?display_name=tag" alt="Release" /></a>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml"><img src="https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/go-%E2%89%A51.23-00ADD8?logo=go&logoColor=white" alt="Go" /></a>
  <a href="https://github.com/Ashfaaq98/ocsf-console-ir/releases"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platforms" /></a>
  <a href="https://schema.ocsf.io/"><img src="https://img.shields.io/badge/OCSF-native-6f42c1" alt="OCSF" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPLv3-blue.svg" alt="License" /></a>
</p>

</div>

<!-- VISUAL 1: demo GIF (~15s, 100x30 terminal): open on the findings queue,
     Enter a finding, v to set a verdict, e to escalate into a case, 2 for the
     case's Findings tab. Belongs here, immediately below the badges. -->

## Overview

Console-IR is a **terminal-first, OCSF-native** incident-response workspace. It ingests
[OCSF](https://schema.ocsf.io/) detections and events, enriches indicators, and gives an analyst a
keyboard-driven place to triage, investigate and document incidents.

You open it to a ranked queue of **findings**, the detections your SIEM or EDR actually flagged,
rather than a wall of log lines. Raw events stay one keystroke away as the corroboration layer.

Everything runs from a single binary backed by SQLite. No broker, no server, no cloud.

```bash
console-ir demo     # a full sample incident, in a throwaway database
```

> **Status:** early and evolving (v0.2.x). The TUI workflow is the supported path today; headless
> mode is experimental and the external threat-intel plugins are optional.

## Why Console-IR?

Most IR tooling assumes you have already deployed it: a backend, a browser, a database to operate.
That holds in the SOC and breaks everywhere else: on a jump box mid-incident, on an IR laptop in a
datacentre, in an airgapped lab, over SSH on a host you were handed ten minutes ago.

Console-IR assumes the opposite: one binary you can copy anywhere, storage in a file, an interface
that works over SSH.

|  | Console-IR | Traditional IR platform |
|---|---|---|
| Interface | Terminal, works over SSH | Browser |
| Backend | None | Application server, queue, workers |
| Database | Embedded SQLite | Postgres or Elasticsearch to operate |
| Install | One static binary | Deployment |
| Offline | Yes, fully | Rarely |
| Schema | OCSF native | Vendor schema, OCSF via mapping |
| Multi-user | No, single analyst | Yes, with RBAC |

That last row is a limitation, not a feature. Console-IR complements the tools you already run: your
SIEM and EDR collect and detect, MISP and OpenCTI hold threat intel, and Console-IR is the focused
investigation layer once relevant OCSF records exist.

## Core features

- **Findings-first triage.** A queue ranked by risk; status and verdict set from the keyboard
- **Real OCSF semantics.** The `activity_id` lifecycle is honoured, so one alert reported five times stays one row
- **Indicator pivot.** Observables are indexed, so "everything touching this IP" is a lookup, not a scan
- **Cases that match the schema.** Findings as *members*, events as *evidence*, many-to-many
- **Built-in enrichment.** GeoIP and WHOIS in-process, no external services
- **Local SQLite storage.** Full-text search, and your data never leaves the machine

Also inside: stdin and folder ingestion, timelines, notes, IOC extraction, optional LLM summaries and
Redis-backed threat-intel plugins.

### What "OCSF-native" means here

A vendored **OCSF 1.8.0** registry decides what each record is, rather than hand-written guesses:

| Arrives as | Becomes |
|---|---|
| Findings category, `class_uid` 2001–2008 | a **finding** |
| Activity class with `is_alert: true` | **both** a finding and an event |
| Any other activity class | an **event** |

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

Prebuilt archives for Linux, macOS and Windows are on the
[releases page](https://github.com/Ashfaaq98/ocsf-console-ir/releases), with checksums and an SBOM.
More in [docs/installation.md](docs/installation.md).

## Quick start

```bash
console-ir demo
```

Loads a sample incident (phishing attachment, encoded PowerShell, credential access, C2 beaconing)
into a throwaway database and opens the TUI. It never touches your real data.

Then point it at your own:

```bash
console-ir ingest events.jsonl   # a file, a directory, or - for stdin
console-ir                       # open the TUI
```

<!-- VISUAL 2: static screenshot of the findings queue with the detail pane
     open on a critical finding. Belongs here, so a reader who skipped the GIF
     still sees the tool before reaching the key table. -->

From the findings queue:

| Key | Does |
|---|---|
| `Enter` | Open the finding: evidence, source events, indicators |
| `s` / `v` | Set status / verdict |
| `e` | Escalate into a case |
| `A` | Switch to all events |
| `?` | Every other key |

[docs/getting-started.md](docs/getting-started.md) walks through a first investigation.

## Architecture

<!-- VISUAL 3: architecture diagram. Records flow ingest -> OCSF parser -> router
     -> SQLite -> TUI, with the router branching three ways on class_uid and
     is_alert (finding / finding+event / event). An ASCII version of this flow is
     in docs/architecture.md if it is useful as a reference. -->

Records flow **ingest → OCSF parser → router → SQLite → TUI**. The router reads `class_uid` and
`is_alert` to decide what arrived, and indicators are indexed on the way through, which is what makes
the pivot a single lookup rather than a scan. Enrichment runs on an in-process worker queue, and the
open pane redraws when a result lands.

Full detail in [docs/architecture.md](docs/architecture.md).

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | First run, keys, a worked investigation |
| [Installation](docs/installation.md) | Every install method, verification, from source |
| [Ingestion](docs/ingestion.md) | Files, directories, stdin, watch mode, HTTP |
| [Configuration](docs/configuration.md) | Paths, logging, LLM providers, themes, Redis |
| [Architecture](docs/architecture.md) | How records flow, the storage model, enrichment |
| [Migration](docs/migration.md) | Upgrading from v0.1.x |
| [Troubleshooting](docs/troubleshooting.md) | When something does not appear |
| [Plugins](docs/plugins.md) | Writing and enabling external plugins |
| [Building](docs/build.md) | Cross-compilation and platform notes |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Quick version: fork, branch, add tests, run `make check`,
open a PR.

Do **not** commit API keys or secrets. Real settings live in your per-user config directory, not in
the repo. See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[AGPLv3](LICENSE)

- Issues: <https://github.com/Ashfaaq98/ocsf-console-ir/issues>
- Discussions: <https://github.com/Ashfaaq98/ocsf-console-ir/discussions>
