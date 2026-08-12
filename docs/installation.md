# Installation

Console-IR is a single static binary with no runtime dependencies. There is nothing to deploy and
nothing to configure before first use.

## Homebrew (macOS and Linux)

```bash
brew install Ashfaaq98/tap/console-ir
```

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
C toolchain. See [build.md](build.md) for cross-compilation and platform notes.

## Verify

```bash
console-ir version
```

Prints the version, commit, build time, the OCSF schema version it was built against, and the
resolved database, config and log paths.

## Next

Run [`console-ir demo`](getting-started.md) to see it working before pointing it at your own data.
