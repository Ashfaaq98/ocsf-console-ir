# Architecture

```
   SIEM · EDR · JSONL · stdin · HTTP · ./incoming
                      │
                      ▼
                 OCSF parser
                      │
                      ▼
       router  ── reads class_uid and is_alert
         │
         ├─ Findings category 2001-2008 ──▶ finding
         ├─ activity class, is_alert     ──▶ finding + event
         └─ activity class               ──▶ event
                      │
                      ▼
        observables extracted and indexed
        GeoIP + WHOIS enriched in-process
                      │
                      ▼
                    SQLite
                      │
                      ▼
                 Terminal UI
        triage · cases · pivot · export
```

## The router

Class handling is driven by a vendored **OCSF 1.8.0** registry
([`internal/ocsf/classes.json`](../internal/ocsf/classes.json)), embedded with `go:embed`, so
classes are named and categorised the way the schema defines them rather than by hand-written
guesses.

One record can produce two rows. An activity-class event flagged `is_alert: true` is both something
to triage *and* something to query later, so it becomes a finding **and** an event.

## Findings and events

Findings are the analyst's unit of work; events are corroboration.

`activity_id` Create/Update/Close is honoured against a stable `finding_info.uid`, so a detection
reported repeatedly as it is revised stays one row rather than accumulating duplicates. An analyst's
verdict is not overwritten by a producer update.

## Cases

A case holds **findings as members** (what it is about) and **events as evidence** (what supports
it). The same finding can belong to more than one case, which a single foreign key could not express,
so membership lives in a `case_members` join table.

Case status maps to OCSF incident `status_id`, and cases carry `verdict_id`, `priority_id`,
`impact_id` and `is_suspected_breach`.

## Observables

Indicators are extracted into an `observables` table indexed on `(type_id, value)` as records are
ingested, which is what makes "every event and finding touching this IP" a single indexed lookup
rather than a text scan.

Each indicator is labelled **asserted** (the source supplied it) or **derived** (Console-IR inferred
it). Regex scraping survives only as a fallback for records that carry no observables of their own,
and anything found that way is marked derived. Provenance is never guessed at silently.

## Enrichment

GeoIP and WHOIS run **in-process** via a bounded worker queue. No broker, no subprocess, no
configuration.

Enrichment is asynchronous, so the store notifies subscribers once an enrichment is durable and the
open detail pane redraws itself. Notifications are filtered to the event on screen and dropped rather
than queued when the UI is behind, so an enrichment worker is never blocked by the terminal.

## Storage

One SQLite database. Full-text search over events uses FTS5. The shipped binary is built with
`CGO_ENABLED=0` against the pure-Go `modernc.org/sqlite` driver; a CGO build using `mattn/go-sqlite3`
is available behind the `sqlite_cgo` tag, and the test suite runs against both.

## Optional pieces

Redis is an *optional* transport for external threat-intel plugins, not a requirement. The LLM
subsystem powers case summaries and the copilot and is entirely optional; with no configuration it
defaults to a local Ollama model.

## Layout

| Package | Holds |
|---|---|
| `internal/ocsf` | Vendored schema registry, event and finding types |
| `internal/ingest` | Parser, router, folder watcher, HTTP receiver |
| `internal/store` | SQLite schema, migrations, queries |
| `internal/enrich` | In-process GeoIP and WHOIS |
| `internal/ui` | tview/tcell terminal interface |
| `internal/plugins` | Plugin manager and the external plugin bridge |
| `internal/paths` | Per-user directory resolution |
| `internal/logging` | Levelled, rotating log |
