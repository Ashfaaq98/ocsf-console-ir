# Getting Started

## Try it with sample data

```bash
console-ir demo
```

This loads a sample incident into a **throwaway database** and opens the TUI. It never touches your
real data, so it is safe to run first and safe to run again.

The sample is one coherent incident: a phishing attachment leads to encoded PowerShell, credential
access, and C2 beaconing on a single host. That gives the findings queue, the case model and the
indicator pivot something real to show.

## Load your own data

```bash
console-ir ingest events.jsonl   # a file
console-ir ingest ./incoming     # a directory
console-ir                       # open the TUI
```

Ingesting first is usually better than dropping files while the TUI runs: `ingest` enriches
synchronously and waits for the lookups, so the TUI opens with GeoIP and WHOIS data already attached,
and any parse errors appear on the terminal where you will read them.

See [ingestion.md](ingestion.md) for every input path, including stdin and HTTP.

## The first screen

Console-IR opens on the **findings queue** whenever detections are waiting, and on ALL EVENTS
otherwise. From the queue:

- **Enter** opens the finding: evidence artifacts, the events it came from, and its indicators
- **`s`** sets status, **`v`** sets verdict, **`e`** escalates it into a case
- **`A`** switches to ALL EVENTS. Open one to see GeoIP/WHOIS enrichment attached, grouped one card
  per indicator and updating in place as async lookups land

## Commands

```
console-ir                    open the TUI
console-ir ingest <path|->    a file, a directory, or stdin  (--watch, --no-enrich)
console-ir demo               sample incident in a throwaway database
console-ir list               findings | cases | events   (works without a TTY)
console-ir reset              clear the database
console-ir version            version, build info and resolved paths
```

`console-ir list` works over SSH with no TTY and from scripts.

## Keys

Press **`?`** in the app for the full list. The ones that matter most:

| Key | Does |
|---|---|
| `D` | Findings queue (detections awaiting triage) |
| `A` | All events |
| `Enter` | Open the selected item |
| `Tab` | Move focus between the sidebar and the list |
| `r` | Reload |
| `f` / `F` | Filter events / clear filters |
| `t` | Cycle theme |
| `?` | Help |
| `q` | Quit |

In the findings queue:

| Key | Does |
|---|---|
| `s` | Set status (New, In Progress, Suppressed, Resolved, Archived) |
| `v` | Set verdict (True/False Positive, Suspicious, Benign, …) |
| `e` | Escalate into a new or existing case |
| `o` | Toggle between open findings and all findings |

Inside a case, `1`–`7` select the tabs: Overview, Findings, Events, Timeline, Artifacts/IOCs, Notes,
Activity Log.

Navigation follows vim conventions: `j`/`k` move, `h`/`l` change pane, `g`/`G` jump to top/bottom,
`J`/`K` page.

## A first investigation

1. `D` to open the findings queue. The highest-risk unresolved detection is at the top.
2. `Enter` to inspect it: what fired, which events support it, which indicators it carries.
3. `v` to record a verdict, or `e` to escalate it into a case.
4. `Tab` to the Cases sidebar and `Enter` to open it. Inside, `2` shows the findings the case is
   about and `3` shows the events attached as evidence.
5. `A` to search the raw telemetry around it.

## Next

- [ingestion.md](ingestion.md): every way to get data in
- [configuration.md](configuration.md): where files live, logging, LLM providers, themes
- [troubleshooting.md](troubleshooting.md): when something does not appear
