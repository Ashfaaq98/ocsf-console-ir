# Configuration

## Where your data lives

Console-IR keeps its database, config and logs in stable per-user directories, so it opens the same
cases whichever folder you launch it from. Run `console-ir version` to see the resolved paths.

| | Linux / BSD | macOS | Windows |
|---|---|---|---|
| Database | `$XDG_DATA_HOME/console-ir` → `~/.local/share/console-ir` | `~/Library/Application Support/console-ir` | `%LOCALAPPDATA%\console-ir` |
| Config | `$XDG_CONFIG_HOME/console-ir` → `~/.config/console-ir` | `~/Library/Application Support/console-ir` | `%APPDATA%\console-ir` |
| Logs | `$XDG_STATE_HOME/console-ir` → `~/.local/state/console-ir` | `~/Library/Logs/console-ir` | `%LOCALAPPDATA%\console-ir\logs` |

`XDG_*` environment variables are honoured on every platform.

| Flag | Overrides |
|---|---|
| `--data-dir` | Where the database lives |
| `--config-dir` | Where settings live |
| `--log-dir` | Where logs live |
| `--db` | The database file itself |
| `--portable` | All three, beside the working directory |

`--portable` is useful on a USB stick, or a jump box you do not want to leave traces on.

Config directories are created mode `0700`, because `llm_settings.json` can hold a plaintext API key.

The watched drop folder is deliberately *not* per-user: it stays relative to where you launch
(`./incoming`). Point it anywhere with `--ingest-dir`.

## Logging

Everything goes to a single `console-ir.log`, rotated at 5 MB with three older generations kept, so
logs are capped at 20 MB. Every line carries a level and the subsystem that emitted it:

```
2026-07-30 17:15:21 WARN  [whois] lookup failed example.bd: no whois server found
```

`--log-level debug|info|warn|error` sets the threshold (default `info`).

| Level | Adds |
|---|---|
| `debug` | Keystrokes, query timings, cache hits |
| `info` | Lifecycle: startup, ingestion, plugin registration |
| `warn` | Failed lookups and recoverable problems |
| `error` | Database and plugin failures |

Rotation happens *before* a write, so a record is never split across two files.

## Configuration file

Console-IR reads `console-ir.yaml` from the config directory, falling back to `~/.console-ir.yaml`
or `./.console-ir.yaml`. Pass `--config <path>` to name one explicitly.

```yaml
database:
  path: /custom/path/console-ir.db
log:
  level: info
redis:
  url: ""
plugins:
  dir: ./plugins
```

Flags take precedence over the config file, which takes precedence over defaults.

## LLM provider (optional)

Case summaries and the copilot are optional. Set the provider, model and API key from the TUI's LLM
Settings (`Shift+L`), or copy [`config/llm_settings.sample.json`](../config/llm_settings.sample.json)
into your config directory as `llm_settings.json`.

With no configuration, Console-IR defaults to a local Ollama model. Nothing is sent anywhere unless
you configure a remote provider.

Supported: Ollama, OpenRouter, Groq, and other OpenAI-compatible endpoints.

## Themes

Press `t` to cycle. Three ship:

| Theme | |
|---|---|
| `dark` | Default |
| `gruvbox` | The published gruvbox dark palette |
| `light` | For bright rooms and projectors |

Your choice is saved to `ui_settings.json` in the config directory and restored on the next launch.

## Redis (optional)

Console-IR is standalone by default with no external services. Pass `--redis redis://host:6379` only
to enable distributed mode for the external threat-intel plugins. See [plugins.md](plugins.md).
