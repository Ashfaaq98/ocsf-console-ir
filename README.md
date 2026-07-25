# OCSF Console IR

[![Release](https://img.shields.io/github/v/release/Ashfaaq98/ocsf-console-ir?display_name=tag)](https://github.com/Ashfaaq98/ocsf-console-ir/releases)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fashfaaq98%2Fconsole--ir-2496ED?logo=docker&logoColor=white)](https://github.com/Ashfaaq98/ocsf-console-ir/pkgs/container/console-ir)

![Console IR Landing](assets/landing.png)


## **Overview**

OCSF Console IR is a terminal-first incident response manager designed for security analysts. It leverages the OCSF (Open Cybersecurity Schema Framework) standard to provide a unified platform for event ingestion, case management, and AI-assisted analysis.

## **Features**

- OCSF-native event ingestion
- Keyboard-first TUI for cases & events
- AI assisted Case Management
- Plugin-based enrichment via Redis Streams
- SQLite storage with FTS
- Pluggable LLM providers for summaries and copilot

## **Installation**

### Homebrew (macOS / Linux)

```bash
brew install Ashfaaq98/tap/console-ir
```

### curl installer (Linux / macOS)

```bash
curl -sSfL https://raw.githubusercontent.com/Ashfaaq98/ocsf-console-ir/main/scripts/install.sh | bash
```

### Docker

```bash
docker run --rm -it ghcr.io/ashfaaq98/console-ir:latest --help
```

```bash
# Start the headless runtime with HTTP ingest on port 8080 and persistent data
docker run --rm -it -p 8080:8080 -v $(pwd)/data:/data ghcr.io/ashfaaq98/console-ir:latest
```

### Build from source

```bash
git clone https://github.com/Ashfaaq98/ocsf-console-ir.git
cd ocsf-console-ir
make build
./bin/console-ir serve
```

### Demo - Short walkthrough

A quick tour of the TUI.

[![TUI walkthrough](assets/demo.gif)](assets/demo.mp4)


## **Quick Start**

### **Prerequisites**

- Go ≥ 1.23
- Docker (optional, for Redis)
- Git

### **Clone**

```bash
git clone https://github.com/Ashfaaq98/ocsf-console-ir.git
cd ocsf-console-ir

```

### **Build**

```bash
make build
```

### **Run TUI**

```bash
./bin/console-ir serve
```

Or headless:

```bash
./bin/console-ir serve --no-tui
```

## Ingesting events

#### 1. CLI file ingest

Run a JSONL file directly: `./bin/console-ir ingest <file>` — see [cmd/ingest.go](cmd/ingest.go).

#### 2. Folder drop-in

Drop files into `data/incoming`; the folder watcher ingests new files automatically (see [internal/ingest/folder.go](internal/ingest/folder.go)).

#### 3. HTTP ingestion

Enable the optional HTTP endpoint to POST events into the pipeline (see [internal/ingest/http_ingest.go](internal/ingest/http_ingest.go)).

#### 4. Live / stream ingestion

Real-time OCSF inputs and adapters publish to Redis Streams for processing (see [internal/ingest/live.go](internal/ingest/live.go) and [internal/ingest/ocsf.go](internal/ingest/ocsf.go)).

## **Plugins**

External plugins run as separate processes and consume/publish via Redis Streams. See [`docs/plugins.md`](docs/plugins.md).

By default external plugins are disabled; enable explicitly by creating an enable marker next to the executable (e.g., `plugins/misp/misp.enabled`) or start plugins manually.

## **Devcontainer & Debug**

Development is supported via [`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json) and debug settings in [`.vscode/launch.json`](.vscode/launch.json).

## **Architecture**

![Architecture](assets/architecture.png)

## **Troubleshooting**

- Ensure Redis is reachable at the configured URL.
- If TUI fails, run with --no-tui or use a native terminal.
- Build issues: run `go mod download` and `make build`.
- Docker image runs the app in headless mode and enables HTTP ingest on `0.0.0.0:8080` by default.

## **Contributing**

- See the full contribution guide in [CONTRIBUTING.md](CONTRIBUTING.md) for workflow, coding standards, and local checks.
- Quick steps: fork the repo, create a branch, add tests, run `make check`, open a PR.

## **Security**

Do NOT commit API keys or secrets. Use the TUI or edit [`config/llm_settings.sample.json`](config/llm_settings.sample.json) and keep [`config/llm_settings.json`](config/llm_settings.json) ignored. See [`SECURITY.md`](SECURITY.md) for disclosure guidance.

## **License**

AGPLv3 - see [`LICENSE`](LICENSE)

## **Support**

- Issues: https://github.com/Ashfaaq98/ocsf-console-ir/issues
- Discussions: https://github.com/Ashfaaq98/ocsf-console-ir/discussions
