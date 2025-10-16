# Cross-platform build script for Console-IR
# Usage: .\build.ps1 [platform]
# Platforms: windows, linux, macos, macos-arm64, all

param(
    [string]$Platform = "windows"
)

$ErrorActionPreference = "Stop"

# Ensure Go is in PATH
if (!(Get-Command "go" -ErrorAction SilentlyContinue)) {
    $env:PATH += ";C:\Program Files\Go\bin"
    if (!(Get-Command "go" -ErrorAction SilentlyContinue)) {
        Write-Error "Go is not installed or not found in PATH. Please install Go and try again."
    }
}

Write-Host "Console-IR Cross-Platform Build Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Ensure bin directory exists
if (!(Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

function Build-Platform {
    param($OS, $Arch, $OutputName)
    
    Write-Host "Building for $OS/$Arch..." -ForegroundColor Yellow
    
    $env:GOOS = $OS
    $env:GOARCH = $Arch
    
    # Use pure Go SQLite for better cross-platform compatibility
    # This avoids CGO dependencies and C compiler requirements
    $env:CGO_ENABLED = "0"
    Write-Host "  Using pure Go SQLite (modernc.org/sqlite) for cross-platform compatibility" -ForegroundColor Cyan
    
    $output = "bin/$OutputName"
    if ($OS -eq "windows") {
        $output = "$output.exe"
    }
    
    go build -o $output main.go
    
    if ($LASTEXITCODE -eq 0) {
        $size = (Get-Item $output).Length
        $sizeStr = "{0:N0}" -f $size
        Write-Host "✓ Successfully built $output ($sizeStr bytes)" -ForegroundColor Green
    } else {
        Write-Error "Failed to build for $OS/$Arch"
    }
}

switch ($Platform.ToLower()) {
    "windows" {
        Build-Platform "windows" "amd64" "console-ir"
    }
    "linux" {
        Build-Platform "linux" "amd64" "console-ir-linux"
    }
    "macos" {
        Build-Platform "darwin" "amd64" "console-ir-macos"
    }
    "macos-arm64" {
        Build-Platform "darwin" "arm64" "console-ir-macos-arm64"
    }
    "all" {
        Build-Platform "windows" "amd64" "console-ir"
        Build-Platform "linux" "amd64" "console-ir-linux"
        Build-Platform "darwin" "amd64" "console-ir-macos"
        Build-Platform "darwin" "arm64" "console-ir-macos-arm64"
    }
    default {
        Write-Error "Unknown platform: $Platform. Use: windows, linux, macos, macos-arm64, or all"
    }
}

# Reset environment
$env:GOOS = ""
$env:GOARCH = ""

Write-Host "`nBuild completed!" -ForegroundColor Green
Write-Host "Available binaries:" -ForegroundColor Cyan
Get-ChildItem bin/ | ForEach-Object {
    $size = "{0:N0}" -f $_.Length
    Write-Host "  $($_.Name) ($size bytes)" -ForegroundColor White
}
