# Getting Started

## Try it with sample data

```bash
console-ir demo
```

This loads a sample incident into a **throwaway database** and opens the TUI. It never touches your
real data, so it is safe to run first and safe to run again.

The sample is a working week in a small estate: a phishing-led intrusion still being worked, an
account compromise nobody has picked up, a cryptominer closed as a true positive, and a scanner's
findings closed as false positives — inside several hundred ordinary events. The story is moved onto
today's calendar as it loads, so ages and filters read the way they would in a live console.

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

With no database yet, Console-IR opens on a **welcome screen**: create an empty database, load the
demo investigation, import a file, or point it at a folder to watch. It creates nothing until you
pick one, and quitting leaves the disk untouched.

Once a database exists it opens on **Analyst Home**, which answers "what needs my attention?":
open findings, active cases, evidence seen today, and a priority queue of the highest-risk
detections. Keys `1`–`5` reach the other screens from there.

From the findings queue (`1`):

- **Enter** opens the finding: evidence artifacts, the events it came from, and its indicators
- **`s`** sets status, **`v`** sets verdict, **`e`** escalates it into a case
- **`3`** switches to Events. Open one to see GeoIP/WHOIS enrichment attached, grouped one card
  per indicator and updating in place as async lookups land

## Commands

```
console-ir                    open the TUI
console-ir ingest <path|->    a file, a directory, or stdin  (--watch, --no-enrich)
console-ir demo               sample incident in a throwaway database
console-ir list               findings | cases | events   (works without a TTY)
console-ir report <case>      write a case up as Markdown, to stdout by default
console-ir reset              clear the database
console-ir version            version, build info and resolved paths
```

`console-ir list` works over SSH with no TTY and from scripts.

## Keys

Press **`?`** in the app for the full list. The ones that matter most:

| Key | Does |
|---|---|
| `1`–`5` | Triage, Cases, Events, Indicators, Reports — from anywhere |
| `Enter` | Open the selected item |
| `Esc` | Back to Analyst Home |
| `Tab` | Cycle panels |
| `:` | Command palette |
| `r` | Reload |
| `f` / `F` | Filter / clear filters |
| `t` | Cycle theme |
| `,` | Settings |
| `?` (or `h`) | Help |
| `q` | Quit |

Each screen names its own keys in the bar at the bottom, and `?` lists everything that applies
where you are standing. There are no hidden letter shortcuts that jump between screens — the digits
are the only way, so they mean one thing everywhere.

In the findings queue:

| Key | Does |
|---|---|
| `s` | Set status (New, In Progress, Suppressed, Resolved, Archived) |
| `v` | Set verdict (True/False Positive, Suspicious, Benign, …) |
| `e` | Escalate into a new or existing case |
| `o` | Toggle between open findings and all findings |
| `Space` | Select findings for a bulk action |
| `/` | Search titles |

Inside a case, **`Tab`** and **`Shift+Tab`** move between the seven tabs — Briefing, Findings, Events,
Timeline, Indicators, Notes, Activity. Digits are reserved for the destinations above and do not
change tabs. `]` opens the copilot beside the case and `[` closes it.

| Key | Does (inside a case) |
|---|---|
| `Space` | Pin the event under the cursor as evidence |
| `p` | Pin from the timeline |
| `n` | Write a note · `T` from a template |
| `o` | Take ownership of the case |
| `s` / `S` | Set status · cycle it |
| `E` | Write the case up as a report |
| `J` / `e` | Export the whole case · just the pinned evidence, as JSON |
| `h` / `l` | Move left to the tab, right to the copilot |
| `Esc` | Leave the case |

Navigation follows vim conventions: `j`/`k` move, `h`/`l` change pane, `g`/`G` jump to top/bottom,
`J`/`K` page.

## A first investigation

1. `1` for the findings queue. The highest-risk unresolved detection is at the top.
2. `Enter` to inspect it: what fired, which events support it, which indicators it carries.
3. `v` to record a verdict, or `e` to escalate it into a case.
4. `2` for Cases, `Enter` to open one. It opens on **Briefing** — the statement, scope, working
   hypotheses and next actions. `Tab` to Findings for what the case is about, again for the events
   attached as evidence.
5. `Space` on the events that prove it — pinned evidence surfaces on the briefing and in the report.
6. `E` writes the case up. `5` keeps every report you have written.
7. `3` for Events, or `4` for Indicators and `Enter` to pivot on one, to search the telemetry
   around it.

## Next

- [ingestion.md](ingestion.md): every way to get data in
- [configuration.md](configuration.md): where files live, logging, LLM providers, themes
- [troubleshooting.md](troubleshooting.md): when something does not appear
