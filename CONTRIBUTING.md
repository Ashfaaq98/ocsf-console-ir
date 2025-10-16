# Contributing to OCSF Console IR

Thanks for your interest in contributing!

This document explains the workflow, coding standards, and how to run checks locally so your changes land smoothly.

## Quick start

1. Fork the repo and create a feature branch
2. Develop and keep changes focused and small
3. Run local checks
4. Open a Pull Request (PR) against `main`

## Project layout

- CLI and commands: [cmd/](cmd/README.md:1)
- Core packages: [internal/](internal/README.md:1)
- Plugins: [plugins/](plugins/README.md:1)
- Docs: [docs/](docs/README.md:1)

## Prerequisites

- Go ≥ 1.23 (see [docs/build.md](docs/build.md:7))
- Docker (optional, for Redis/quick demo)
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
./bin/console-ir serve
```

- Headless:
```bash
./bin/console-ir serve --no-tui
```

- Demo (builds everything, starts Redis, ingests sample data):
```bash
make demo
```

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

Do not include secrets in code, configs, tests, or logs. See [SECURITY.md](SECURITY.md:1) for reporting vulnerabilities.

## Plugins

Each plugin is a standalone Go module under [plugins/](plugins/README.md:1). Build with:
```bash
make build-plugins
```
or:
```bash
cd plugins/<name> && go build
```

## Communication

Open a GitHub Issue for bugs/requests and a PR for proposed changes. Be respectful and follow our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

By contributing, you agree your contributions will be licensed under AGPLv3 (see [LICENSE](LICENSE)).