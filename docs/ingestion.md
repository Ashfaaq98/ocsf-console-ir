# Ingestion

Console-IR accepts OCSF records as JSON or JSONL. One command covers files, directories and stdin;
the path decides what happens, the way `cp` and `tar` work.

```bash
console-ir ingest events.jsonl        # a file
console-ir ingest ./incoming          # every matching file in a directory
console-ir ingest ./incoming --watch  # ...and keep tailing it
cat events.json | console-ir ingest - # stdin
```

## Flags

| Flag | Effect |
|---|---|
| `--watch` | Keep tailing a directory instead of exiting after one pass |
| `--no-enrich` | Skip GeoIP/WHOIS lookups. Use for bulk loads |
| `--case "Title"` | Attach everything ingested to a case |
| `--skip-invalid` | Continue past records that fail to parse or are not OCSF, and exit 0 |

Records are enriched as they arrive. One-shot ingestion enriches **synchronously and waits**, so the
command does not exit with lookups still in flight.

## The watched folder

While the TUI is running, files dropped into the watched folder are picked up automatically:

```bash
console-ir --ingest-dir ./incoming    # default is ./incoming
```

The drop folder stays relative to where you launch, unlike the database and config. A landing zone
buried under `~/.local/share` is one you cannot drop files into.

Folder ingestion records per-file offsets, so files staged before launch are ingested once and are
not re-ingested on restart.

## Over HTTP (experimental)

POSTed payloads are written into the watched folder and ingested from there.

```bash
console-ir --http-ingest-enable --http-ingest-bind 127.0.0.1:8081
```

| Flag | Default | Notes |
|---|---|---|
| `--http-ingest-bind` | `127.0.0.1:8081` | A bearer token is required on non-loopback binds |
| `--http-ingest-token` | `$INGEST_TOKEN` | Required unless bound to loopback |
| `--http-ingest-rps` | `10` | Requests per second |
| `--http-ingest-burst` | `20` | Rate limiter burst |
| `--http-ingest-dir` | `--ingest-dir` | Where payloads are written |

> **HTTP ingestion requires the TUI.** The receiver writes files into the drop folder, and the
> folder watcher that ingests them only starts alongside the TUI. Combining
> `--http-ingest-enable` with `--no-tui` is refused rather than accepted, because it would return
> `202 Accepted` and never store the events. Headless HTTP ingestion is planned; until then
> `console-ir ingest <dir> --watch` is the fully headless path.

## What happens to a record

The router reads `class_uid` and `is_alert` to decide what arrived:

| Arrives as | Becomes |
|---|---|
| Findings category, `class_uid` 2001–2008 | A **finding** |
| Any activity class with `is_alert: true` | **Both** a finding and an event |
| Any other activity class | An **event** |

Indicators are extracted into an indexed `observables` table on the way through, which is what makes
the pivot fast. See [architecture.md](architecture.md).

## Records that are not OCSF

A record with no usable `class_uid` is **not** an OCSF event: there is no class to interpret its
fields against, so every field would read as absent and the row would land with no host, no message
and no severity. Those records are refused and counted:

```
$ console-ir ingest sysmon.jsonl
Ingested 0 of 2 events in 0s.
  2 not recognised as OCSF
     no class_uid, so there is no OCSF class to read these as.
     first was: {"EventID":1,"Image":"C:\\Windows\\System32\\cmd.exe", ...}
     Console-IR reads OCSF and does not convert to it — map your
     source to OCSF first, or pass --skip-invalid to ingest the rest.
```

The exit status reflects it, so a pipeline step fails rather than reporting success on data that was
never stored. `--skip-invalid` ingests whatever *is* OCSF and exits 0.

Console-IR consumes OCSF and does not convert to it. Map at the source — most SIEMs and EDRs can emit
OCSF directly, and the OCSF project publishes mappings for common formats.

A malformed line is reported separately from one that is simply not OCSF: being told to convert a
file that is actually truncated sends you the wrong way.

## Implementation

See [`internal/ingest/`](../internal/ingest/) for the parser, folder watcher and HTTP receiver.
