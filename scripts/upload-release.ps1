# Deprecated: release publishing is handled by GoReleaser in GitHub Actions.

Write-Host "upload-release.ps1 is deprecated." -ForegroundColor Yellow
Write-Host "Use the tagged GitHub Actions release workflow instead." -ForegroundColor Yellow
Write-Host "For local dry runs, use:" -ForegroundColor White
Write-Host "  goreleaser release --snapshot --clean" -ForegroundColor White
