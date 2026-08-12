# Contributing to OCSF Console IR

Thanks for your interest in contributing!

This document explains the workflow, coding standards, and how to run checks locally so your changes land smoothly.

## Quick start

1. Fork the repo and create a feature branch
2. Develop and keep changes focused and small
3. Run local checks
4. Open a Pull Request (PR) against `main`

## Project layout

- CLI and commands: `cmd/`
- Core packages: `internal/`
- Plugins: `plugins/`
- Docs: `docs/`

## Prerequisites

- Go ≥ 1.23 (see [docs/installation.md](docs/installation.md) for building from source)
- Docker (optional — only for the experimental Redis-based threat-intel plugins)
- Make

## One-time setup

```bash
make setup-dev
```

This runs `go mod download/tidy` and prepares build directories.

## Build

```bash
make build           # main binary
make build-plugins   # all plugins
make build-all       # main + plugins
```

## Run

- TUI (auto-detects terminal support):
```bash
./bin/console-ir
```

- Load the shipped sample, then explore it in the TUI:
```bash
./bin/console-ir ingest examples/sample-events.jsonl
./bin/console-ir
```

- Headless (`--no-tui`) is experimental and does not currently ingest.

### Keeping development data out of your real database

The database, config and logs live in per-user directories (`console-ir version` prints them), so
running from a checkout writes to the same database as an installed binary. Use `--portable` to keep
everything inside the working directory instead:

```bash
./bin/console-ir --portable
```

Note that a plain first run will *move* an existing `./data/console-ir.db` into the per-user
location, printing what it moved — that is the upgrade path for real users. Either use `--portable`
from the start, or `--db ./data/dev.db` to pin a scratch database.

## Code style

- Format with `gofmt -s` and `goimports`
- Keep changes focused per PR
- Prefer small, composable functions
- Be defensive on boundaries (I/O, network, parsing) and return contextual errors

## Tests

- Unit tests:
```bash
go test -race ./...
```

- Full check suite:
```bash
make check   # fmt + vet + lint + tests
```

If you add a new package or public API, add tests where practical.

## Linting

We use `golangci-lint`:
```bash
golangci-lint run ./...
```

If not installed, see their docs or run:
```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Commits and PRs

- Branch naming: `feature/...`, `fix/...`, `docs/...`, `chore/...`
- Commit messages: short imperative subject, optional body with context
- PR checklist:
  - Tests added/updated when applicable
  - `make check` passes locally
  - Docs updated (README or docs/*) if behavior changes
  - Clear description and scope

## Security

Do not include secrets in code, configs, tests, or logs. See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Enrichment & plugins

GeoIP and WHOIS enrichment are built in and run in-process — see
[internal/enrich/](internal/enrich/). To add a new in-process enrichment,
implement the `CorePlugin` interface (see [internal/plugins/interface.go](internal/plugins/interface.go))
and register it in [cmd/serve.go](cmd/serve.go).

The threat-intel integrations under [plugins/](plugins/) (MISP, OpenCTI, IntelOwl)
are optional external Go modules that communicate over Redis Streams; see
[docs/plugins.md](docs/plugins.md). Build them with:
```bash
make build-plugins
```
or:
```bash
cd plugins/<name> && go build
```

## Communication

Open a GitHub Issue for bugs, questions and feature requests. Be respectful and follow our
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

For code, please read the next section first — it will save you writing a patch that cannot be
merged yet.

## Licensing and contributions

Console-IR is [AGPLv3](LICENSE), and every line of it is currently written by one person. That is
deliberate while the project is young: holding the copyright in one place keeps its licensing
options open.

**Bug reports, feature requests, questions and design feedback are very welcome.** Open an issue.
A reproduction, the relevant log lines and the output of `console-ir version` are the most useful
things you can send, and none of it raises a licensing question.

**Trivial fixes are welcome as pull requests** — typos, broken links, an obviously wrong constant.
Changes at that size do not meaningfully carry copyright.

**For anything larger, please open an issue before writing code.** If we agree the change is right,
one of two things will happen: either you will be asked to sign a short Contributor License
Agreement, or the change will be implemented from your description with credit to you.

This is not a judgement on your patch. Merging substantial code without a CLA would permanently
remove the option to offer Console-IR under any licence other than AGPLv3 — there is no way to undo
it later without tracking down every contributor — and that is not a decision worth making by
accident in a pull request.

If that position changes, this file changes with it.

## Releasing

Maintainers only. The step-by-step checklist — validating the pipeline before tagging, the tap and
bucket repos, the required secrets, and the rollback plan — is in
[.github/release-playbook.md](.github/release-playbook.md). It lives there rather than in `docs/`
because `docs/*` ships inside every release archive, and a runbook about pushing tags is not
documentation for someone who downloaded a binary.
