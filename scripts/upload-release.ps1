# GitHub Release Upload Script using GitHub CLI
# Prerequisites: Install GitHub CLI (gh) and authenticate with 'gh auth login'

param(
    [string]$Version = "v1.0.0",
    [string]$ReleaseTitle = "Console-IR v1.0.0 - Cross-Platform Release"
)

$ErrorActionPreference = "Stop"

$ReleaseDir = "release-$Version"

if (!(Test-Path $ReleaseDir)) {
    Write-Error "Release directory $ReleaseDir not found. Run prepare-release.ps1 first."
}

Write-Host "Uploading Console-IR $Version to GitHub..." -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check if GitHub CLI is installed
try {
    gh --version | Out-Null
} catch {
    Write-Error "GitHub CLI (gh) is not installed. Please install it from https://cli.github.com/"
}

# Check if authenticated
try {
    gh auth status | Out-Null
} catch {
    Write-Error "Not authenticated with GitHub CLI. Run 'gh auth login' first."
}

Write-Host "Creating GitHub release..." -ForegroundColor Yellow

# Create the release
gh release create $Version `
    --title $ReleaseTitle `
    --notes-file "$ReleaseDir/RELEASE_NOTES.md" `
    --repo "Ashfaaq98/console-ir"

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create GitHub release"
}

Write-Host "✓ Release created successfully" -ForegroundColor Green

Write-Host "`nUploading release assets..." -ForegroundColor Yellow

# Upload each asset
$Assets = @(
    "console-ir-windows-amd64.exe",
    "console-ir-linux-amd64", 
    "console-ir-darwin-amd64",
    "console-ir-darwin-arm64",
    "geoip-plugin-windows-amd64.exe",
    "checksums.txt"
)

foreach ($asset in $Assets) {
    $assetPath = "$ReleaseDir/$asset"
    if (Test-Path $assetPath) {
        Write-Host "Uploading $asset..." -ForegroundColor White
        gh release upload $Version $assetPath --repo "Ashfaaq98/console-ir"
        
        if ($LASTEXITCODE -eq 0) {
            $size = (Get-Item $assetPath).Length
            $sizeStr = "{0:N0}" -f $size
            Write-Host "✓ Uploaded $asset ($sizeStr bytes)" -ForegroundColor Green
        } else {
            Write-Error "Failed to upload $asset"
        }
    } else {
        Write-Warning "Asset not found: $assetPath"
    }
}

Write-Host "`n✅ Release upload completed!" -ForegroundColor Green
Write-Host "Release URL: https://github.com/Ashfaaq98/console-ir/releases/tag/$Version" -ForegroundColor Cyan
