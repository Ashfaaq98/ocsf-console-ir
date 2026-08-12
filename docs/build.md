# Build and Release Guide

This document explains how to build and run **Console-IR** on different platforms. It is a single
static binary with no runtime dependencies.

---

## 📦 Prerequisites
- **Go ≥ 1.23** → [Download Go](https://golang.org/dl/). Building from source without
  cross-compiling is covered in [installation.md](installation.md).
- **Git**
- **Make** (Linux/macOS, optional)  
- **PowerShell** (Windows, recommended)

---


## 🚀 Build Methods

You can build Console-IR in different ways depending on your OS:

### Method 1 — Using Make (Linux/macOS)

```bash
make build          # build main binary
make build-all      # build binary + plugins
make build-plugins  # build plugins only
```

### Method 2 — Using PowerShell (Windows, recommended)

```pwsh
# Build for current platform (Windows)
.\scripts\build.ps1 windows

# Build for Linux, macOS, Apple Silicon
.\scripts\build.ps1 linux
.\scripts\build.ps1 macos
.\scripts\build.ps1 macos-arm64

# Build all platforms at once
.\scripts\build.ps1 all

```

### Method 3 — Manual cross-compilation

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o bin/console-ir-linux main.go

# macOS Intel (amd64)
GOOS=darwin GOARCH=amd64 go build -o bin/console-ir-macos main.go

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o bin/console-ir-macos-arm64 main.go

# Windows amd64 and ARM64
GOOS=windows GOARCH=amd64 go build -o bin/console-ir.exe main.go
GOOS=windows GOARCH=arm64 go build -o bin/console-ir-arm64.exe main.go

# Reset environment (back to host OS)
unset GOOS
unset GOARCH

```

---

## 📂 Build Outputs

After successful builds, executables are placed in bin/:

 - bin/console-ir.exe → Windows

 - bin/console-ir-linux → Linux x64

 - bin/console-ir-macos → macOS Intel

 - bin/console-ir-macos-arm64 → macOS ARM64/Apple Silicon

 - bin/misp, bin/opencti, bin/intelowl → external threat-intel plugins (if built)

GeoIP and WHOIS are **not** plugins — they run in-process inside the binary. See
[architecture.md](architecture.md).

---

## 🛠️ Troubleshooting

### 1. Go toolchain problems

`go: command not found`, module download failures and build permission errors belong to Go rather
than to us. Install Go from [golang.org/dl](https://golang.org/dl/), then
`go clean -modcache && go mod download`.

---

### 2. make: command not found (Windows)

Use PowerShell and `scripts\build.ps1`, or install make via WSL or Git Bash.

---

### 3. Windows-specific syscall errors

If you see errors like undefined: syscall.SYS_IOCTL:

- These are Unix syscalls not available on Windows.

- Console-IR provides platform-specific files:

  - cmd/terminal_windows.go → Windows API

  - cmd/terminal_unix.go → Linux/macOS

- Make sure you are building with the right GOOS

---

## ✅ CI and Release Builds

For continuous integration or release packaging:

```bash
goreleaser check
goreleaser release --snapshot --clean
```

Tagged releases are published by GitHub Actions via `.github/workflows/release.yml`.
For the step-by-step release checklist, see `docs/release-playbook.md`.

---

## 🔎 Notes

- On Linux/macOS, run ./bin/console-ir

- On Windows, run .\bin\console-ir.exe

- For development:

    - Run make check before commits

    - Use gofmt / goimports for formatting
