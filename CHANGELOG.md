# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- RBAC / multi-user support
- PostgreSQL backend option
- Scapy/pcap ingestion plugin
- Web UI companion (opt-in)

## [0.1.0] - 2026-03-28

### Added

- OCSF-native ingestion via batch JSONL, HTTP ingest, folder watcher, and Redis Streams
- Keyboard-first TUI built on `tview`/`tcell` for cases, events, evidence, and analyst workflows
- AI-assisted case management with pluggable LLM providers for summaries and copilot flows
- Plugin architecture over Redis Streams with GeoIP, Whois, LLM, IntelOwl, MISP, and OpenCTI integrations
- SQLite storage with FTS5-backed search support and local-first persistence
- Cross-platform binaries for Linux amd64/arm64, macOS amd64/arm64, and Windows amd64
- Multi-arch Docker image distribution via GHCR using a distroless runtime image
- Homebrew tap distribution for macOS and Linux users
- Headless runtime mode with `--no-tui`
- Devcontainer and VS Code debug configuration for contributors

[Unreleased]: https://github.com/Ashfaaq98/ocsf-console-ir/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ashfaaq98/ocsf-console-ir/releases/tag/v0.1.0
