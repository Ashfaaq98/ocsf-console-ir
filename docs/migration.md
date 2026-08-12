# Migration

## Upgrading from v0.1.x

### Your database moves

v0.1.x kept the database at `./data/console-ir.db`, relative to wherever you happened to launch the
binary. That meant running Console-IR from two directories opened two different, empty databases,
indistinguishable from having lost every case.

On first run, v0.2.0 moves that file, plus `config/llm_settings.json` (which can hold a plaintext API
key), into the per-user directories and **prints each move**:

```
Moved data/console-ir.db -> /home/you/.local/share/console-ir/console-ir.db
Moved config/llm_settings.json -> /home/you/.config/console-ir/llm_settings.json
```

Nothing happens silently. Nothing is moved if a database already exists at the destination. A file
that cannot be moved is left where it is and reported, so a failed migration never destroys data.

Pass `--portable` to keep the old working-directory layout instead. See
[configuration.md](configuration.md) for the resolved locations.

### The database migrates in place

Opening an existing database upgrades its schema:

- OCSF identity columns (`class_uid`, `category_uid`, `type_uid`) are added and backfilled from the
  stored raw events
- Observables are extracted into an indexed table
- `event_type` is rewritten to OCSF category slugs (`system`, `findings`, `iam`, `network`, …),
  replacing the incorrect values earlier versions produced
- Case membership moves to a `case_members` join table, backfilled from the old single foreign key

Nothing is lost, and the migration is safe to re-run.

### Downgrading is not clean

A v0.1.x binary reads the migrated database but offers only its old five type filters, none of which
match the new category slugs, so filtering appears to return nothing.

**Back up the database before upgrading if you may need to roll back.** `console-ir version` prints
its path.

### The CLI changed

| v0.1.x | v0.2.0 |
|---|---|
| `console-ir serve` | `console-ir` (the old name still works, hidden) |
| `console-ir ingest-folder <dir>` | `console-ir ingest <dir> --watch` |
| `console-ir ingest -f file.jsonl` | `console-ir ingest file.jsonl` |
| Drop folder `data/incoming/` | `./incoming/` (or `--ingest-dir`) |

`ingest` now enriches by default and waits for the lookups. Pass `--no-enrich` for bulk loads.

### Removed in v0.2.0

- **Container images.** The published image had no working purpose and declared a volume that no
  longer matched where the database lived. Headless ingestion exists now, so an image has something
  to do again; it is on the roadmap rather than in this release.
- **The `T` and `C` theme shortcuts.** Press `t` to cycle. Six palettes ship, including the
  high-contrast and colourblind-safe ones — see [configuration.md](configuration.md).
