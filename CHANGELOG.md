# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Emit and ingest OCSF Incident Findings (class_uid 2005) for SIEM round-trip
- Headless / server-mode ingestion + enrichment
- Threat-intel enrichment (MISP, OpenCTI, IntelOwl) embedded in-process

## [0.2.0] - 2026-07-28

Findings become a first-class entity. Console-IR now opens on a triage queue of detections rather
than a wall of log lines, and models what OCSF actually says about investigation.

### Upgrading from 0.1.x

Opening an existing database migrates it in place: OCSF identity columns are added and backfilled
from stored raw events, observables are extracted into an indexed table, and `event_type` is
rewritten to OCSF category slugs. Nothing is lost and the migration is safe to re-run.

**Downgrading afterwards is not clean.** A 0.1.x binary reads the migrated database but offers only
its old five type filters, none of which match the new values, so filtering appears to return
nothing. Back up `data/console-ir.db` first if you may roll back.

### Added

- **Findings triage queue.** OCSF Findings classes (`class_uid` 2001–2008) and any event flagged
  `is_alert` are routed to a dedicated queue ranked by risk. Press `D`; set status with `s`, verdict
  with `v`, escalate to a case with `e`, toggle open-only with `o`. The app lands here on startup
  when findings are waiting, and on ALL EVENTS otherwise.
- **Finding lifecycle.** `activity_id` Create/Update/Close is honoured against a stable
  `finding_info.uid`, so a finding reported repeatedly stays one record. An analyst's verdict is not
  overwritten by producer updates.
- **Observables are persisted and indexed** on `(type_id, value)`, making the indicator pivot a
  single indexed lookup. Indicators are marked *asserted* (supplied by the source) or *derived*
  (inferred by Console-IR).
- **Many-to-many case membership.** Cases hold findings as *members* and events as *evidence*; the
  same finding can belong to several cases. Cases gained OCSF status, verdict, priority, impact,
  suspected-breach, and external ticket links.
- Class-level filtering (`EventFilter`, `FindingFilter`) and a `Keys` reference in the README.
- `scripts/gen-ocsf-classes.sh` regenerates the vendored OCSF registry.

### Fixed

- **OCSF class mapping was wrong.** `class_uid` 2001–2005 — the entire Findings category, including
  Detection Finding (2004) and Incident Finding (2005) — was classified as `file` activity. `1001`
  (File System Activity) was reported as `process` while Process Activity (`1007`) fell through to
  `unknown`, and roughly 30 further classes were unreachable. Class and category now resolve through
  a vendored OCSF 1.8.0 registry.
- **Foreign keys were never enforced on shipped builds.** The DSN used the CGO driver's parameter
  spelling, which the pure-Go driver silently ignores, so every `ON DELETE` rule was inert on
  release binaries. DSN parameters are now driver-specific, with a regression test.
- `observable.reputation` is decoded as an object; it was typed as an integer, so the conversion
  failed silently and the value was dropped.
- `severity_id` now covers the full enum — `0 Unknown`, `6 Fatal` and `99 Other` previously all
  collapsed to `unknown`.
- `SearchEvents` selected a stale column list on the full-text path, which failed only on the shipped
  pure-Go driver.

### Changed

- `events.event_type` stores the OCSF category slug (`system`, `findings`, `iam`, `network`,
  `discovery`, `application`, `remediation`, `unmanned`) instead of five hand-picked labels.
- The IOC view reads persisted observables; regex text-scraping remains only as a fallback for
  events that carry none, and anything found that way is labelled derived.
- Case status gained **Resolved** and maps to OCSF incident `status_id`.
- The shipped sample (`examples/sample-events.jsonl`) now includes a realistic Detection Finding;
  it previously used `class_uid` 2001, deprecated in OCSF 1.1.0.

## [0.1.1] - 2026-07-25

### Changed

- Enrichment now runs **in-process**: GeoIP and WHOIS are embedded in the binary and need no Redis broker or subprocess.
- Redis is now **opt-in**. The default is standalone with no external services; pass `--redis` to enable distributed mode.
- Folder ingestion resumes from persisted offsets, so files staged in `data/incoming/` before launch are ingested on startup and not re-ingested on restart.

### Added

- Shipped sample at `examples/sample-events.jsonl` and an empty-state onboarding hint in the TUI.
- CI now builds and tests the shipped `CGO_ENABLED=0` (modernc) SQLite driver, runs `go vet` and race tests, and executes the plugin-module test suites.

### Removed

- The redundant external `llm` plugin (built-in LLM providers are unaffected) and the external `geoip`/`whois` plugins (now built in).

### Fixed

- `console-ir ingest` no longer aborts on JSONL lines larger than 64 KB.
- Enrichment plugin logs no longer corrupt the TUI screen.
- In-memory SQLite databases are pinned to a single connection so the shipped pure-Go driver behaves correctly.

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

[Unreleased]: https://github.com/Ashfaaq98/ocsf-console-ir/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Ashfaaq98/ocsf-console-ir/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Ashfaaq98/ocsf-console-ir/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Ashfaaq98/ocsf-console-ir/releases/tag/v0.1.0
