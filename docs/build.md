# Build and Release Guide

This document explains how to build and run **Console-IR** on different platforms. It is a single
static binary with no runtime dependencies.

---

## 📦 Prerequisites
- **Go ≥ 1.23** → [Download Go](https://golang.org/dl/)
- **Git**
- **Make** (Linux/macOS, optional)  
- **PowerShell** (Windows, recommended)

---


## 🖥️ Installing Go on Windows

If you don’t have Go installed:

1. **Download Go**  
   - Visit [https://golang.org/dl/](https://golang.org/dl/)  
   - Download the Windows `.msi` installer (64-bit is typical)  

2. **Install Go**  
   - Run the installer with default settings  
   - Go will be installed to `C:\Program Files\Go`  

3. **Verify installation**  
   ```pwsh
   go version
   ```

4. **Fix PATH if needed**
    ```pwsh
    $env:PATH += ";C:\Program Files\Go\bin"
    [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\Go\bin", [EnvironmentVariableTarget]::User)
    ```
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

### Method 3 — Using Go directly

```bash
# Build for current platform
go build -o bin/console-ir main.go

# Build an external threat-intel plugin (example: MISP)
cd plugins/misp && go build -o ../../bin/misp .
```

### Method 4 — Manual Cross-Compilation

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o bin/console-ir-linux main.go

# macOS Intel (amd64)
GOOS=darwin GOARCH=amd64 go build -o bin/console-ir-macos main.go

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o bin/console-ir-macos-arm64 main.go

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

 - bin/geoip.exe → Example plugin (if built)

---

## 🛠️ Troubleshooting

### 1. go: command not found / ‘go’ is not recognized

 - Go is not installed or not in your PATH.

 - Verify with:

    ```pwsh
    Test-Path "C:\Program Files\Go\bin\go.exe"
    ```

 - Add it to PATH as shown above.

---

### 2. Module download issues

```bash
go clean -modcache
go mod download
```

--- 

### 3. Build permission errors

```pwsh
# Run PowerShell as Administrator
# Or check write permissions on the bin/ directory
```

--- 

### 4. make: command not found (Windows)

 - Use PowerShell and build.ps1 instead.

 - Or install make via WSL / Git Bash.

---

### 5. Windows-specific syscall errors

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
