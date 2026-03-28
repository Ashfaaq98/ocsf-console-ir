# Deprecated: release artifacts are now built by GoReleaser.

Write-Host "prepare-release.ps1 is deprecated." -ForegroundColor Yellow
Write-Host "Use the tagged GitHub Actions release workflow or run one of:" -ForegroundColor Yellow
Write-Host "  goreleaser check" -ForegroundColor White
Write-Host "  goreleaser release --snapshot --clean" -ForegroundColor White
Write-Host "  git tag v0.1.0 && git push origin v0.1.0" -ForegroundColor White
