# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-08-15

The case screen becomes a place to work, and settings become one place. Every screen owns its keys,
dialogs float over what they act on, cases can be written up and kept, and the interface runs
headless. Colour carries meaning throughout: severity, status, and the kind of thing a value is.

Windows is a first-class platform for the first time — tested in CI, published to Scoop, built for
ARM, and no longer rendering its entire interface in ASCII.

### Upgrading from 0.2.x

**The letter shortcuts are gone.** `A`, `C`, `I`, `D` and `R` jumped between screens without being
documented anywhere, and two of them collided with keys the screen underneath already used. The
digits `1`–`5` are now the only way between screens, and they mean the same thing everywhere.

**Cases and Events swapped places.** `1` Triage · `2` Cases · `3` Events · `4` Indicators ·
`5` Reports. A case is where a finding goes next, so it sits beside the queue.

**Nothing to do to your database.** No schema change in this release.

**On Windows, the config directory's `0700` never protected anything.** Windows uses access control
lists rather than Unix mode bits, so the mode we ask for has no effect — and `llm_settings.json` can
hold a plaintext API key. This is now documented rather than implied to work everywhere; supply the
key through an environment variable on a shared Windows machine.

### Added

- **Reports.** `E` inside a case writes it up as Markdown, the Reports screen keeps every report
  written, and `console-ir report <case>` produces the same document on stdout for a pipeline. A
  case can be resolved by id, by unique id prefix, or by title.
- **Headless HTTP ingest.** `--http-ingest-enable` now works with `--no-tui`: the folder watcher
  that reads posted payloads back in runs in both modes. Previously the receiver answered
  `202 Accepted` and left the events unread on disk.
- **One settings panel**, on `,` from every screen including inside a case. Six categories —
  General, Appearance, Ingestion, Copilot, Plugins, System — with search across all of them and an
  explanation of every row. It replaced four unconnected places: a two-item panel, a provider form
  reachable only from inside a case, a theme key, and a set of flags nothing surfaced.
  - **Every row names where its value came from** — default, config file, flag, chosen here, or
    detected. With four layers of configuration the useful question is not what can be changed but
    why a value is what it is.
  - A row a flag has already decided is shown and explains itself, rather than accepting a change it
    could not keep.
  - **Your analyst name is settable.** It goes into the audit trail, case ownership, notes and
    reports, and was taken from `$USER` — wrong on a shared machine.
  - `Shift+L` opens the panel on Copilot, where the provider form now lives.
- **Semantic colour for entities.** Hosts, users, addresses and artifacts each get a colour taken
  from their OCSF observable type, on **every** screen that shows one — the queue, findings, events,
  the timeline, indicators, notes, the briefing and the copilot's answers. The palettes were chosen
  by searching each theme for the most vivid set that stays distinguishable under three kinds of
  colour blindness, and that is enforced by test. Inside prose, entities are found by shape — dotted
  quads, hashes, endpoint file extensions — because colouring a guess is worse than colouring
  nothing.
- **A theme picker** on the settings panel, replacing blind cycling. Six palettes ship.
- **OCSF 1.9.0.** The vendored registry moves from 1.8.0, gaining five classes — **User Management**
  and **Role Management**, which an account-compromise investigation is largely made of, plus
  Clipboard Activity, Device Power State Activity and Startup Item Query — and two observable types
  for IAM roles. Nothing was renamed or removed. A weekly CI job now compares the vendored version
  against `schema.ocsf.io`, so falling behind is noticed in days rather than by a user whose records
  arrive as `Class 3007`.
- **Windows on ARM**, and publishing to Scoop, so Windows has an install path better than a zip.
- **CI runs on macOS and Windows**, not only Linux. Before this, "supports three platforms" rested
  on cross-compilation alone.
- **Notes on the case timeline**, so what an analyst wrote sits beside what happened.
- **`o` takes ownership of a case.** The header had told analysts to press it since the prompt was
  written and nothing handled it; `assigned_to` was set once at escalation and never again.

### Changed

- **Every screen owns its keys.** A key means one thing on the screen that advertises it, and the
  status bar describes where you are standing rather than showing a fixed list.
- **Dialogs float over the screen they act on.** Filters, pickers and confirmations no longer
  replace the page, so you can see what you are narrowing while you narrow it.
- **The case header** shows the case id — the prefix `console-ir report` accepts — the owner, when
  it opened and when it last changed. It no longer prints a verdict field nothing can write, or
  counts that could disagree with the tab strip beside them.
- **The case tab strip is a bar** with a count on each tab, so how full a case is reads without
  pressing Tab seven times.
- **Both SQLite drivers and both other platforms are tested in CI.** macOS and Windows now build and
  run the suite; previously "supports three platforms" rested on cross-compilation alone.

### Fixed

- **The whole interface rendered in ASCII on every Windows terminal.** Unicode support was decided
  by reading `LC_ALL`, `LC_CTYPE` and `LANG` — a Unix convention Windows never sets — so the answer
  was always no. Frames drew as `+---+`, scrollbars as pipes, the sparkline as `_.-#-._`, on a
  platform whose default terminal has rendered UTF-8 for years. Windows now asks the console for its
  output code page, and trusts Windows Terminal outright.
- **A leaked log file handle.** Closing the log left its `sync.Once` fired, so the package still
  believed it was open, handed out a closed file, and every write after a close went nowhere
  silently. Unix lets you delete an open file, which is why only Windows noticed.
- **Arrowing an empty pane hung the application.** An empty tab draws unselectable cells in a
  selectable table, and tview searches for somewhere to land forever. Every tab was affected.
- **Pressing `2` at start-up deadlocked the event loop**, as did `s` on the cases screen: both
  queued a repaint from the handler that the loop was waiting on.
- **Three data races on the loading paths**, found once the loads became observable.
- **Focus was lost when a modal closed** — arrow keys did nothing until you changed screens.
- **The findings pane and the copilot ignored the theme.** Three copilot widgets had never been in
  the theming pass at all, so the drawer had black bands on every palette.
- **Two analyst names.** The case screen attributed an action to the case's *owner*, everything else
  to `$USER` — so working someone else's case signed your notes and audit entries with their name.
- Screens no longer advertise keys they do not handle, or data they cannot source.

### Removed

- **`docs/build.md`**, whose content duplicated `installation.md` and `CONTRIBUTING.md`. Its
  Windows and cross-compilation notes moved into `installation.md`.
- **The release playbook moved out of `docs/`** to `.github/`, so a maintainer runbook stops
  shipping inside every release archive.

## [0.2.0] - 2026-08-03

Findings become a first-class entity. Console-IR now opens on a dashboard of what needs attention
rather than a wall of log lines, and models what OCSF actually says about investigation.

### Upgrading from 0.1.x

**Your database moves.** 0.1.x resolved every path against the current working directory, so an
installed binary opened a different, empty database per directory — indistinguishable from having
lost every case. Paths are now per-user. On first run an existing `./data/console-ir.db` and
`./config/llm_settings.json` are moved into the new locations and each move is printed; nothing is
moved if a database already exists at the destination. `console-ir version` prints the resolved
paths, and `--portable` keeps the old layout.

**The CLI changed.** `console-ir serve` becomes plain `console-ir`. `ingest-folder` is gone —
`console-ir ingest <path>` takes a file, a directory, or `-` for stdin. The watched drop folder
moved from `data/incoming/` to `./incoming/`; move anything staged there, or pass
`--ingest-dir data/incoming`.

**The database migrates in place** when opened: OCSF identity columns are added and backfilled from
stored raw events, observables are extracted into an indexed table, and `event_type` is rewritten to
OCSF category slugs. Nothing is lost and the migration is safe to re-run.

**Ingest now fails on input that is not OCSF.** A file whose records carry no `class_uid` used to
report success and store unusable rows; it now reports how many were not recognised and exits
non-zero. If you pipe non-OCSF data through `console-ir ingest`, that step will start failing — pass
`--skip-invalid` to keep the old exit behaviour, or map your source to OCSF first.

**Downgrading afterwards is not clean.** A 0.1.x binary reads the migrated database but offers only
its old five type filters, none of which match the new values, so filtering appears to return
nothing. Back up the database first if you may roll back.

### Added

- **Findings triage queue.** OCSF Findings classes (`class_uid` 2001–2008) and events flagged
  `is_alert` land in a risk-ranked queue. Press `D`; `s` sets status, `v` verdict, `e` escalates to a
  case, `o` toggles open-only.
- **Finding lifecycle.** `activity_id` Create/Update/Close updates a finding in place against a
  stable `finding_info.uid`, so one alert reported five times stays one record. An analyst's verdict
  is not overwritten by producer updates.
- **Observables are persisted and indexed** on `(type_id, value)`, making the indicator pivot a
  single lookup. Each is labelled *asserted* (supplied by the source) or *derived*.
- **Many-to-many case membership.** Cases hold findings as *members* and events as *evidence*, and a
  finding can belong to several cases. Cases gained OCSF status, verdict, priority, impact,
  suspected-breach and external ticket links.
- **A welcome screen on first run.** With no database, Console-IR offers to create one, load the demo
  investigation, import a file or watch a folder — and creates nothing until you choose. Previously a
  fresh install opened an empty application, which reads as a broken one.
- **Startup is deterministic.** No database opens the welcome screen; a database opens Analyst Home.
  The first screen used to depend on whether the database held findings, then cases, then events, so
  there was no screen to learn and no stable place to return to.
- **Stable per-user runtime paths.** Database, config and logs resolve to XDG locations
  (`~/Library` on macOS, `%LOCALAPPDATA%` on Windows) instead of the working directory. Override with
  `--data-dir`, `--config-dir`, `--log-dir` or `--db`; `--portable` restores the old layout.
- **The detail pane refreshes itself when enrichment arrives**, instead of showing what was true when
  the event was opened until `r` is pressed.
- **`console-ir demo`** opens a working week in a throwaway database: four cases in different states
  — one being worked, one unassigned, one closed as a true positive, one as a false positive — inside
  several hundred ordinary events. The story is shifted onto today's calendar as it loads, so ages
  and filters describe a live investigation whenever you run it. The data is embedded in the binary,
  so it works on a fresh install and never touches your own database.
- **`console-ir list findings`**, and findings are now the default listing. Works over SSH with no
  TTY, or from a script.
- **Analyst Home.** Every session opens on a dashboard: open findings, active cases and today's
  evidence as metric cards, a risk-ranked priority queue, recent cases and a live event pulse.
- **A navigation rail.** Five numbered destinations — Triage, Events, Cases, Indicators, Reports —
  reachable from anywhere with `1`–`5`. `Esc` returns Home, `:` opens a command palette, `?` help.
- **Triage filters and saved views.** Filter chips for status, severity, age and indicators, a search
  bar, multi-select for bulk status and verdict changes, and views you can save and recall.
- **Event clustering, search and pivoting.** Events on one host inside a short window collapse into a
  single row that expands on `Enter`; full-text search over messages; and any observable pivots to
  everywhere else it appears.
- **The case management room.** Seven tabs behind `Tab` — Briefing, Findings, Events, Timeline,
  Indicators, Notes, Activity — under a header carrying status, owner, age and counts, plus a prompt
  naming the next action when a case has no owner, no note or no recent activity. The briefing holds
  an incident statement, scope, working hypotheses and next actions; the timeline merges events,
  findings and audit into one narrative; indicators carry their provenance. `Space` pins decisive
  evidence, which then surfaces on the briefing and survives a restart.
- **A copilot drawer inside cases.** `]` opens it beside the case and `[` closes it, so it costs no
  space until asked for. Its suggested questions are built from the open case, and generated text is
  marked as generated — it enters the record only when you accept it into the notes.

- **The findings a case is about have their own tab.** Escalation always recorded them as case
  members, but nothing read that back, so an escalated finding disappeared from view the moment the
  case was opened. Press `2` in a case.
- **`console-ir version`** prints the resolved database, config and log paths, plus the commit, build
  time, Go version and the OCSF schema version the binary was built against.
- **`make release-check`** dry-runs the whole release pipeline — archives, checksums, SBOMs, Homebrew
  formula and container images — without pushing a tag. CI runs it on every pull request.
- `--ingest-dir` makes the watched drop folder configurable; it was hardcoded.
- Class-level filtering (`EventFilter`, `FindingFilter`), and a Keys reference in the README.
- `scripts/gen-ocsf-classes.sh` regenerates the vendored OCSF registry.

### Changed

- **Running the bare binary opens the TUI.** `console-ir serve` implied a daemon, which this is not.
- **Ingest refuses records that are not OCSF.** A record with no usable `class_uid` is reported
  rather than stored: the summary counts them, names the cause once and quotes the first offender,
  and the exit status reflects it. Previously any valid JSON was accepted, so a Sysmon or CEF export
  reported `Ingested 500 of 500` and produced 500 rows with no host, message or severity.
  `--skip-invalid` still ingests what it can and exits 0.
- **`ingest` and `ingest-folder` are one command.** `console-ir ingest <path>` resolves a file, a
  directory (`--watch` to tail), or `-` for stdin.
- **`ingest` enriches by default** and waits for the lookups to finish. It previously skipped
  GeoIP/WHOIS silently while the TUI's watcher enriched. Use `--no-enrich` for bulk loads.
- **Enrichment is grouped one card per indicator**, replacing the flat alphabetical key list. Keys
  matching no known indicator are kept in a separate card rather than dropped.
- **Logging has levels and component tags.** `--log-level debug|info|warn|error` now does something —
  it was declared, bound to config and never read. Every line carries a level and the subsystem that
  wrote it (`WARN  [whois] lookup failed …`), so failures are greppable and keystroke tracing can be
  turned off.
- **Ingest prints its result plainly** rather than as a log record. `Ingested 5 of 5 events in 4ms.`
  goes to stdout; the timestamped detail stays in the log file.
- **Three themes, and the choice is remembered.** `dark` (default), `gruvbox` and `light`. The neon,
  Claude and Gemini palettes were dropped, and the theme now persists between sessions instead of
  resetting on every launch.
- **The header shows the OCSF schema version** alongside the tool version, and is built in one place
  instead of two that had diverged.
- **One rotating log instead of three.** Everything writes to `console-ir.log`, rotated at 5 MB
  keeping three older generations — 20 MB maximum. Logs previously grew without bound.
- **LLM settings are read from the per-user config directory**, so an API key is written to one known
  place rather than wherever the binary was launched from.
- **Container distribution is dropped.** The image had no working purpose: its default command was
  `--help`, and its one documented use — `serve --no-tui --http-ingest-enable` — is the combination
  that is now refused because it accepted events and never stored them. It also declared
  `VOLUME /data` while the database had moved to a per-user directory, so mounting it as documented
  would have discarded the database on every restart. `Dockerfile`, `.dockerignore`, the GoReleaser
  `dockers:`/`docker_manifests:` sections and the QEMU/buildx/GHCR release steps are gone; the
  release dry-run went from over 20 minutes to 11 seconds. Reconsider when headless ingest exists.
- `events.event_type` stores the OCSF category slug (`system`, `findings`, `iam`, `network`, …)
  instead of five hand-picked labels.
- The IOC view reads persisted observables; regex text-scraping remains only as a fallback for events
  carrying none, and anything found that way is labelled derived.
- Case status gained **Resolved**, mapped to OCSF incident `status_id`.
- `--redis` and `--plugins-dir` appear only on the commands that use them.
- The shipped sample (`examples/sample-events.jsonl`) includes a realistic Detection Finding; it
  previously used `class_uid` 2001, deprecated in OCSF 1.1.0.

### Deprecated

- `console-ir ingest -f/--file` — pass the path as a positional argument instead.
- `console-ir serve` — run `console-ir` with no arguments. It still works, but is now hidden.

### Removed

- **The `T` and `C` theme shortcuts**, which only ever jumped to the two removed palettes.
- **MCP scaffolding.** `internal/ui/config/mcp_settings.json` was tracked, carried an `api_key`
  field, and was read by no code at all. `MCPMode` was set by every LLM provider and read by none.

### Fixed

- **Ingest could silently drop records when writing concurrently.** Ingest and enrichment write at
  the same time and no busy timeout was set, so a write that arrived while the database was locked
  failed instead of waiting: three ingests of the same 15-event file gave 15, 14 and 15. Writers now
  wait, and transactions take their write lock up front.
- **Cases could be missing from the case list**, and the list shared a screen with events. Cases now
  have their own screen and nothing is filtered out of it.
- **An empty "Ingested Events" case appeared** for anyone who merely configured a watch folder. It is
  created when the first record lands in it.
- **A supplied creation time was discarded** when adding a case or a note, so anything carried in
  from elsewhere was stamped with the moment it was imported.

- **Enrichment failures were invisible while the TUI ran.** Plugin logs were routed to `io.Discard`
  so they could not corrupt the screen — a guard that stopped being necessary when logs moved to a
  file, and which silenced every failed GeoIP and WHOIS lookup along with the noise.
- **HTTP ingestion accepted events it never stored.** Run headless, the receiver answered `202
  Accepted`, wrote each POST to the drop folder, and left it there: the folder watcher that ingests
  those files only starts alongside the TUI. A pipeline would have looked healthy while losing
  everything. The combination now refuses to start; headless HTTP ingest is still to come.
- **Switching theme emptied the findings queue**, and `r` reloaded events over it. Both shared
  refresh paths assumed the events list was showing.
- **First-run hints named files a downloaded binary does not have.** The empty state pointed at
  `examples/sample-events.jsonl`, which ships only in the source tree, and at `data/incoming/`, which
  stopped being the watched folder. They now name `console-ir demo` and the folder actually being
  watched.
- **`console-ir demo` left stale instructions on the terminal** after quitting, and orphaned its
  temporary directory when killed rather than quit.
- **A runtime error printed the entire flag list after it** — 38 lines burying the one line that
  explained the failure.
- **OCSF class mapping was wrong.** `class_uid` 2001–2005 — the entire Findings category — was
  classified as `file` activity, `1001` was reported as `process`, Process Activity (`1007`) fell
  through to `unknown`, and around 30 further classes were unreachable. Class and category now
  resolve through a vendored OCSF 1.8.0 registry.
- **WHOIS treated OCSF field names as domains.** The domain scan read the raw JSON *text*, so
  `process.name`, `user.name` and `file.name` were looked up — and because `.name` is a real TLD
  those lookups succeeded, storing an unrelated registry's details as event enrichment. Extraction
  now walks parsed values by key, honours observable types, and skips filenames and reserved TLDs.
- **Foreign keys were never enforced on shipped builds.** The DSN used the CGO driver's parameter
  spelling, which the pure-Go driver silently ignores, so every `ON DELETE` rule was inert on release
  binaries.
- **The Homebrew formula was frozen at v0.1.0.** A `skip_upload: "true"` guard, added before the tap
  repository existed, was never lifted — so v0.1.1 shipped while `brew install` still served v0.1.0.
- **Release archives shipped without their documentation.** The bundled glob was `docs/**/*`, which
  requires a subdirectory; `docs/` is flat, so every archive since v0.1.0 omitted the docs.
- `observable.reputation` is decoded as an object; it was typed as an integer, so the conversion
  failed silently and the value was dropped.
- `severity_id` covers the full enum — `0 Unknown`, `6 Fatal` and `99 Other` previously collapsed to
  `unknown`.
- `SearchEvents` selected a stale column list on the full-text path, which failed only on the shipped
  pure-Go driver.

## [0.1.1] - 2026-07-25

### Added

- Shipped sample at `examples/sample-events.jsonl` and an empty-state onboarding hint in the TUI.
- CI now builds and tests the shipped `CGO_ENABLED=0` (modernc) SQLite driver, runs `go vet` and race tests, and executes the plugin-module test suites.

### Changed

- Enrichment now runs **in-process**: GeoIP and WHOIS are embedded in the binary and need no Redis broker or subprocess.
- Redis is now **opt-in**. The default is standalone with no external services; pass `--redis` to enable distributed mode.
- Folder ingestion resumes from persisted offsets, so files staged in `data/incoming/` before launch are ingested on startup and not re-ingested on restart.

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

[Unreleased]: https://github.com/Ashfaaq98/ocsf-console-ir/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Ashfaaq98/ocsf-console-ir/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Ashfaaq98/ocsf-console-ir/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Ashfaaq98/ocsf-console-ir/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Ashfaaq98/ocsf-console-ir/releases/tag/v0.1.0
