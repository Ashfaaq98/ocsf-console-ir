# Troubleshooting

## Nothing appears

**No findings?** Your data may contain no detections. Findings come from OCSF Findings classes
(`class_uid` 2001–2008) or events flagged `is_alert`. Plain telemetry produces events, not findings.
Press `A` for all events, or run `console-ir demo` for a sample that includes several.

Note the queue hides already-triaged findings by default; press `o` to show everything.

**Empty event list?** Run `console-ir demo` to see the tool with data in it, or
`console-ir ingest examples/sample-events.jsonl` from a source checkout to load the shipped sample
into your own database.

**Told your file is "not recognised as OCSF"?** The records carry no `class_uid`, so there is no OCSF
class to read them as. Console-IR consumes OCSF and does not convert to it — map at the source, or
pass `--skip-invalid` to ingest whatever *is* OCSF and exit 0. See [ingestion.md](ingestion.md).

**Dropped a file in and nothing happened?** The watched folder is `./incoming`, relative to where you
launched. The TUI's empty state names the folder it is actually watching. Point it elsewhere with
`--ingest-dir`.

**Cases missing after upgrading?** v0.2.0 moved the database to a per-user directory and printed the
move when it did. Run `console-ir version` to see where it is now. See [migration.md](migration.md).

## Enrichment

**Enrichment missing?** Lookups are asynchronous, but the open event refreshes itself when they land.
If a card never appears, the lookup failed; check the log (`console-ir version` prints its path):

```bash
grep WARN "$(console-ir version | awk '/logs/{print $2}')"
```

Common causes: no outbound network, a rate-limited GeoIP provider (`ipapi status=429`), or a TLD with
no public WHOIS server.

**Enrichment for an indicator you did not expect?** Indicators come from the record's own
`observables` when it has them, and from a bounded scan of known host-bearing fields otherwise.
Anything inferred is labelled *derived* rather than *asserted*.

## Terminal

**TUI won't start?** It needs a real TTY. Use a native terminal rather than a pipe or a CI runner.
`console-ir list` works anywhere, including over SSH with no TTY.

`--no-tui` is experimental and does not ingest.

**Colours look wrong?** Press `t` to cycle themes. Console-IR detects true-colour support; a
16-colour terminal falls back automatically.

**Layout clipped?** The TUI targets 80×24 as a minimum. Wider terminals get more columns.

## HTTP ingestion

**`--http-ingest-enable` refuses to start with `--no-tui`.** That is deliberate. The receiver writes
POSTed payloads into the drop folder, and the watcher that ingests them only runs alongside the TUI,
so headless it would answer `202 Accepted` and never store anything. Use
`console-ir ingest <dir> --watch`, which is fully headless.

## Other

**Redis errors?** You do not need Redis unless you explicitly pass `--redis ...`. The default is
standalone with no external services.

**Build issues?** Run `go mod download` then `make build`. See [build.md](build.md).

**Where is everything?** `console-ir version` prints the resolved database, config and log paths
along with the build and OCSF schema versions.

## Reporting a problem

Include the output of `console-ir version` and the relevant lines from the log. Run with
`--log-level debug` to capture keystrokes and query timings when a UI problem is hard to describe.

Issues: <https://github.com/Ashfaaq98/ocsf-console-ir/issues>
