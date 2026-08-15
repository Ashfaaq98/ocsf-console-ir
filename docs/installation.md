# Installation

Console-IR is a single static binary with no runtime dependencies. There is nothing to deploy and
nothing to configure before first use.

## Homebrew (macOS)

```bash
brew install --cask Ashfaaq98/tap/console-ir
```

A cask rather than a formula. Casks are Homebrew's macOS mechanism, and while the generated one
carries Linux URLs, **the supported Linux path is the curl installer or an archive below** — that is
what the release notes point at and what is tested.

## Scoop (Windows)

```pwsh
scoop bucket add ashfaaq98 https://github.com/Ashfaaq98/scoop-bucket
scoop install console-ir
```

## curl (Linux and macOS)

```bash
curl -sSfL https://raw.githubusercontent.com/Ashfaaq98/ocsf-console-ir/main/scripts/install.sh | bash
```

Installs to `/usr/local/bin` by default; set `INSTALL_DIR` to change it. The script is deliberately
Unix-only and refuses to run elsewhere — on Windows use Scoop or an archive.

## Manual download

Grab an archive from [Releases](https://github.com/Ashfaaq98/ocsf-console-ir/releases) and extract
the binary onto your `PATH`.

| Platform | Archive |
|---|---|
| Linux | `console-ir_<version>_Linux_amd64.tar.gz`, `_arm64` |
| macOS | `console-ir_<version>_macOS_amd64.tar.gz`, `_arm64` |
| Windows | `console-ir_<version>_windows_amd64.zip`, `_arm64` |

Every platform gets both architectures: Intel/AMD and ARM, including Apple Silicon and Windows on
ARM.

Every release publishes `checksums.txt` and an SBOM per archive.

```bash
sha256sum -c checksums.txt --ignore-missing
```

## From source

Requires Go 1.23 or newer.

```bash
git clone https://github.com/Ashfaaq98/ocsf-console-ir.git
cd ocsf-console-ir
make build          # produces bin/console-ir
```

The shipped build uses `CGO_ENABLED=0` and the pure-Go SQLite driver, so it cross-compiles without a
C toolchain — no C compiler, no headers, nothing to install first.

### On Windows

`make` is not required. A PowerShell script builds the same binaries:

```pwsh
.\scripts\build.ps1 windows      # this machine
.\scripts\build.ps1 linux
.\scripts\build.ps1 macos
.\scripts\build.ps1 macos-arm64
.\scripts\build.ps1 all
```

Or use `make` through WSL or Git Bash.

### Cross-compiling by hand

Go needs only `GOOS` and `GOARCH`; every combination we publish builds from any host.

```bash
GOOS=linux   GOARCH=amd64 go build -o bin/console-ir main.go
GOOS=linux   GOARCH=arm64 go build -o bin/console-ir main.go
GOOS=darwin  GOARCH=arm64 go build -o bin/console-ir main.go   # Apple Silicon
GOOS=windows GOARCH=amd64 go build -o bin/console-ir.exe main.go
GOOS=windows GOARCH=arm64 go build -o bin/console-ir.exe main.go
```

Release archives are built by GoReleaser rather than by hand; see
[`.goreleaser.yaml`](../.goreleaser.yaml).

### If you see `undefined: syscall.SYS_IOCTL`

You are building Unix code for Windows, or the reverse. Terminal handling is split by platform —
`cmd/terminal_unix.go` and `cmd/terminal_windows.go`, and likewise for the pseudo-terminal fallback —
so check `GOOS` is what you meant.

## Verify

```bash
console-ir version
```

Prints the version, commit, build time, the OCSF schema version it was built against, and the
resolved database, config and log paths.

## Next

Run [`console-ir demo`](getting-started.md) to see it working before pointing it at your own data.
