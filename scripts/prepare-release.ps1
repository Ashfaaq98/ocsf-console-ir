# GitHub Release Preparation Script for Console-IR
# This script prepares binaries for GitHub release upload

param(
    [string]$Version = "v1.0.0",
    [string]$ReleaseNotes = "Cross-platform release with Windows, Linux, and macOS support"
)

$ErrorActionPreference = "Stop"

Write-Host "Console-IR Release Preparation" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Yellow
Write-Host ""

# Ensure all binaries exist
$RequiredBinaries = @(
    "bin/console-ir.exe",
    "bin/console-ir-linux", 
    "bin/console-ir-macos",
    "bin/console-ir-macos-arm64",
    "bin/geoip"
)

Write-Host "Checking for required binaries..." -ForegroundColor Yellow
$MissingBinaries = @()

foreach ($binary in $RequiredBinaries) {
    if (Test-Path $binary) {
        $size = (Get-Item $binary).Length
        $sizeStr = "{0:N0}" -f $size
        Write-Host "✓ Found $binary ($sizeStr bytes)" -ForegroundColor Green
    } else {
        Write-Host "✗ Missing $binary" -ForegroundColor Red
        $MissingBinaries += $binary
    }
}

if ($MissingBinaries.Count -gt 0) {
    Write-Host "`nMissing binaries detected. Building all platforms..." -ForegroundColor Yellow
    .\build.ps1 all
    
    # Check again
    foreach ($binary in $MissingBinaries) {
        if (!(Test-Path $binary)) {
            Write-Error "Failed to build $binary"
        }
    }
}

# Create release directory
$ReleaseDir = "release-$Version"
if (Test-Path $ReleaseDir) {
    Remove-Item $ReleaseDir -Recurse -Force
}
New-Item -ItemType Directory -Path $ReleaseDir | Out-Null

Write-Host "`nPreparing release assets..." -ForegroundColor Yellow

# Copy and rename binaries for release
$ReleaseAssets = @{
    "bin/console-ir.exe" = "console-ir-windows-amd64.exe"
    "bin/console-ir-linux" = "console-ir-linux-amd64"
    "bin/console-ir-macos" = "console-ir-darwin-amd64"
    "bin/console-ir-macos-arm64" = "console-ir-darwin-arm64"
    "bin/geoip" = "geoip-plugin-windows-amd64.exe"
}

foreach ($source in $ReleaseAssets.Keys) {
    $dest = "$ReleaseDir/$($ReleaseAssets[$source])"
    Copy-Item $source $dest
    $size = (Get-Item $dest).Length
    $sizeStr = "{0:N0}" -f $size
    Write-Host "✓ Created $($ReleaseAssets[$source]) ($sizeStr bytes)" -ForegroundColor Green
}

# Create checksums
Write-Host "`nGenerating checksums..." -ForegroundColor Yellow
$ChecksumFile = "$ReleaseDir/checksums.txt"
Get-ChildItem $ReleaseDir -File | Where-Object { $_.Name -ne "checksums.txt" } | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    $line = "$($hash.Hash.ToLower())  $($_.Name)"
    Add-Content $ChecksumFile $line
    Write-Host "✓ $($_.Name): $($hash.Hash.ToLower().Substring(0,8))..." -ForegroundColor Green
}

# Create release notes
$ReleaseNotesFile = "$ReleaseDir/RELEASE_NOTES.md"
$CurrentDate = Get-Date -Format "yyyy-MM-dd"

$ReleaseNotesContent = @"
# Console-IR $Version

Released: $CurrentDate

## Overview

$ReleaseNotes

## Features

- **Cross-Platform Support**: Native binaries for Windows, Linux, and macOS (Intel & Apple Silicon)
- **OCSF Event Processing**: Native support for Open Cybersecurity Schema Framework events
- **Terminal User Interface**: Rich TUI for case management and event analysis  
- **Plugin Architecture**: Extensible enrichment pipeline with Redis Streams
- **Local Storage**: SQLite database with full-text search capabilities
- **AI Integration**: Swappable LLM providers for case summarization and analysis

## Supported Platforms

| Platform | Architecture | Binary | Size |
|----------|-------------|--------|------|
| Windows | x64 | ``console-ir-windows-amd64.exe`` | $('{0:N0}' -f (Get-Item "$ReleaseDir/console-ir-windows-amd64.exe").Length) bytes |
| Linux | x64 | ``console-ir-linux-amd64`` | $('{0:N0}' -f (Get-Item "$ReleaseDir/console-ir-linux-amd64").Length) bytes |
| macOS | x64 (Intel) | ``console-ir-darwin-amd64`` | $('{0:N0}' -f (Get-Item "$ReleaseDir/console-ir-darwin-amd64").Length) bytes |
| macOS | ARM64 (Apple Silicon) | ``console-ir-darwin-arm64`` | $('{0:N0}' -f (Get-Item "$ReleaseDir/console-ir-darwin-arm64").Length) bytes |

## Installation

### Quick Install

**Windows:**
``````powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/Ashfaaq98/console-ir/releases/download/$Version/console-ir-windows-amd64.exe" -OutFile "console-ir.exe"

# Run
.\console-ir.exe --help
``````

**Linux:**
``````bash
# Download
curl -L -o console-ir "https://github.com/Ashfaaq98/console-ir/releases/download/$Version/console-ir-linux-amd64"

# Make executable
chmod +x console-ir

# Run
./console-ir --help
``````

**macOS:**
``````bash
# For Intel Macs
curl -L -o console-ir "https://github.com/Ashfaaq98/console-ir/releases/download/$Version/console-ir-darwin-amd64"

# For Apple Silicon Macs  
curl -L -o console-ir "https://github.com/Ashfaaq98/console-ir/releases/download/$Version/console-ir-darwin-arm64"

# Make executable
chmod +x console-ir

# Run
./console-ir --help
``````

### Prerequisites

- Docker and Docker Compose (for Redis and plugin support)
- Optional: Redis server for plugin architecture

### Verification

Verify the integrity of your download using the provided checksums:

``````bash
# Download checksums
curl -L -O "https://github.com/Ashfaaq98/console-ir/releases/download/$Version/checksums.txt"

# Verify (Linux/macOS)
sha256sum -c checksums.txt

# Verify (Windows PowerShell)
Get-Content checksums.txt | ForEach-Object {
    `$expected, `$file = `$_ -split '  '
    `$actual = (Get-FileHash `$file -Algorithm SHA256).Hash.ToLower()
    if (`$actual -eq `$expected) { Write-Host "✓ `$file" -ForegroundColor Green }
    else { Write-Host "✗ `$file" -ForegroundColor Red }
}
``````

## Usage

``````bash
# Start the TUI (requires Docker for Redis)
console-ir serve

# Ingest OCSF events
console-ir ingest events.jsonl

# List cases and events (works without dependencies)
console-ir list cases
console-ir list events --limit 10

# Show help
console-ir --help
``````

## What's New

- ✨ Cross-platform terminal handling with native Windows API support
- 🔧 Platform-specific build optimizations  
- 📦 Automated build pipeline for multiple architectures
- 🐛 Fixed Windows compilation issues with syscalls
- 📖 Enhanced documentation with Windows installation guide

## Known Issues

- TUI mode has limited support in VS Code integrated terminal (use `--no-tui` flag)
- Requires Redis for plugin functionality (use Docker Compose for easy setup)

## Support

- **Documentation**: [README.md](https://github.com/Ashfaaq98/console-ir#readme)
- **Issues**: [GitHub Issues](https://github.com/Ashfaaq98/console-ir/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Ashfaaq98/console-ir/discussions)

---

**Full Changelog**: https://github.com/Ashfaaq98/console-ir/commits/$Version
"@

Set-Content $ReleaseNotesFile $ReleaseNotesContent

Write-Host "`n✓ Release notes created: $ReleaseNotesFile" -ForegroundColor Green

# Create upload instructions
$UploadInstructions = "$ReleaseDir/UPLOAD_INSTRUCTIONS.md"
$UploadContent = @"
# GitHub Release Upload Instructions

## Method 1: Using GitHub Web Interface (Recommended)

1. **Go to Releases page**: https://github.com/Ashfaaq98/console-ir/releases

2. **Click "Create a new release"**

3. **Fill in release details**:
   - **Tag version**: ``$Version``
   - **Release title**: ``Console-IR $Version - Cross-Platform Release``
   - **Description**: Copy content from ``RELEASE_NOTES.md``

4. **Upload binary assets**: Drag and drop or click to upload these files:
   - ``console-ir-windows-amd64.exe`` (Windows x64)
   - ``console-ir-linux-amd64`` (Linux x64)  
   - ``console-ir-darwin-amd64`` (macOS Intel)
   - ``console-ir-darwin-arm64`` (macOS Apple Silicon)
   - ``geoip-plugin-windows-amd64.exe`` (GeoIP Plugin for Windows)
   - ``checksums.txt`` (File integrity verification)

5. **Publish the release**

## Method 2: Using GitHub CLI (if installed)

``````powershell
# Create release
gh release create $Version --title "Console-IR $Version - Cross-Platform Release" --notes-file RELEASE_NOTES.md

# Upload assets  
gh release upload $Version console-ir-windows-amd64.exe
gh release upload $Version console-ir-linux-amd64
gh release upload $Version console-ir-darwin-amd64  
gh release upload $Version console-ir-darwin-arm64
gh release upload $Version geoip-plugin-windows-amd64.exe
gh release upload $Version checksums.txt
``````

## Method 3: Using PowerShell with GitHub API

See the ``upload-release.ps1`` script for automated upload using REST API.

## Release Assets Summary

| File | Platform | Size |
|------|----------|------|
| ``console-ir-windows-amd64.exe`` | Windows x64 | $('{0:N0}' -f (Get-Item "$ReleaseDir/console-ir-windows-amd64.exe").Length) bytes |
| ``console-ir-linux-amd64`` | Linux x64 | $('{0:N0}' -f (Get-Item "$ReleaseDir/console-ir-linux-amd64").Length) bytes |
| ``console-ir-darwin-amd64`` | macOS Intel | $('{0:N0}' -f (Get-Item "$ReleaseDir/console-ir-darwin-amd64").Length) bytes |
| ``console-ir-darwin-arm64`` | macOS Apple Silicon | $('{0:N0}' -f (Get-Item "$ReleaseDir/console-ir-darwin-arm64").Length) bytes |
| ``geoip-plugin-windows-amd64.exe`` | Windows Plugin | $('{0:N0}' -f (Get-Item "$ReleaseDir/geoip-plugin-windows-amd64.exe").Length) bytes |
| ``checksums.txt`` | Verification | $('{0:N0}' -f (Get-Item "$ReleaseDir/checksums.txt").Length) bytes |

**Total Release Size**: $('{0:N0}' -f (Get-ChildItem $ReleaseDir -File | Measure-Object Length -Sum).Sum) bytes
"@

Set-Content $UploadInstructions $UploadContent

Write-Host "`n============================" -ForegroundColor Cyan
Write-Host "Release Preparation Complete!" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Release assets created in: $ReleaseDir" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review the release notes: $ReleaseNotesFile" -ForegroundColor White
Write-Host "2. Follow upload instructions: $UploadInstructions" -ForegroundColor White
Write-Host "3. Go to: https://github.com/Ashfaaq98/console-ir/releases/new" -ForegroundColor White
Write-Host ""
Write-Host "Assets to upload:" -ForegroundColor Cyan
Get-ChildItem $ReleaseDir -File | ForEach-Object {
    $sizeStr = "{0:N0}" -f $_.Length
    Write-Host "  $($_.Name) ($sizeStr bytes)" -ForegroundColor White
}
