# OCSF Console IR

**Incident response for the terminal, not another platform to deploy.**

[![Release](https://img.shields.io/github/v/release/Ashfaaq98/ocsf-console-ir?display_name=tag)](https://github.com/Ashfaaq98/ocsf-console-ir/releases)
[![CI](https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml/badge.svg)](https://github.com/Ashfaaq98/ocsf-console-ir/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fashfaaq98%2Fconsole--ir-2496ED?logo=docker&logoColor=white)](https://github.com/Ashfaaq98/ocsf-console-ir/pkgs/container/console-ir)
[![Go](https://img.shields.io/badge/go-%E2%89%A51.23-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platforms](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](https://github.com/Ashfaaq98/ocsf-console-ir/releases)
[![OCSF](https://img.shields.io/badge/OCSF-native-6f42c1)](https://schema.ocsf.io/)
[![License](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)


Console-IR is a **terminal-first, OCSF-native** incident-response workspace. It ingests
[OCSF](https://schema.ocsf.io/) events, enriches indicators, and gives a security analyst
a fast, keyboard-driven place to triage, investigate, and document incidents, all from a
**single binary backed by SQLite, with no broker, no server, and no cloud dependency**.

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

- **OCSF-native ingestion:** JSON/JSONL files, stdin, folder drop-in, and an optional HTTP endpoint
- **Keyboard-first TUI:** cases, events, timelines, evidence, notes, IOC views, and full-text search
- **Built-in enrichment:** GeoIP and WHOIS run in-process, with no external services
- **AI-assisted analysis:** case summaries and a copilot via pluggable LLM providers (Ollama, OpenRouter, Groq, and more); fully optional
- **Local SQLite storage:** full-text search, and your data never leaves the machine
- **Runs fully offline:** one static binary, with no broker, no database server, and no cloud
- **Optional distributed mode:** enable Redis and threat-intel plugins (MISP, OpenCTI, IntelOwl) when you want them

> **Status:** early and evolving (v0.1.x). The TUI workflow is the supported path today.
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

In the TUI: select **ALL EVENTS**, open an event, and you'll see **GeoIP/WHOIS enrichment**
attached (press `r` to refresh as async lookups land). To ingest your own data, drop OCSF
`.jsonl` files into `data/incoming/`, either before launch or while running.

[![TUI walkthrough](assets/demo.gif)](assets/demo.mp4)

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

Events flow **ingest, then OCSF parser, then SQLite**, with enrichment applied in-process via a
worker queue. The TUI reads from SQLite, and the LLM subsystem powers summaries and the copilot.
Redis is an *optional* transport for distributed/external plugins, not a requirement.

## Troubleshooting

- **Empty event list?** Drop `examples/sample-events.jsonl` into `data/incoming/` and press `r`.
- **TUI won't start?** Use a native terminal; it needs a real TTY. (`--no-tui` is experimental and does not ingest.)
- **Enrichment missing?** It's asynchronous, so press `r` to refresh an event's detail once WHOIS/GeoIP lookups complete.
- **Build issues?** Run `go mod download` then `make build`.
- **Redis errors?** You don't need Redis unless you explicitly pass `--redis ...`.

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
