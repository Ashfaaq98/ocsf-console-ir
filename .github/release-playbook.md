# Release Playbook

This document is the practical checklist for shipping `console-ir` releases.

## Before Any Tag: `make release-check`

A tag is close to irreversible. GitHub releases can be deleted, but a Go module version cannot —
`proxy.golang.org` and `sum.golang.org` cache the content hash permanently, so re-tagging the same
version with different code produces a checksum mismatch for anyone who fetches it.

So validate the pipeline *before* tagging:

```bash
# once, pinned to match CI
go install github.com/goreleaser/goreleaser/v2@v2.17.1

make release-check                # full snapshot, nothing published
```

This runs `goreleaser check` and then `goreleaser release --snapshot --clean`, building every
archive, checksum, SBOM, the Homebrew formula and the Scoop manifest locally, without publishing
anything.

It matters because the release workflow runs GoReleaser as a **single step** — one failing artifact
takes the whole release with it. The Homebrew step nearly broke this way at v0.1.1 and was only
caught because it had been disabled first.

CI runs the same target on every pull request.

## The Pre-Tag Checklist

Everything below must be true before the tag is pushed. Each one has failed a release somewhere.

- [ ] **`make release-check` is clean.** GoReleaser is not installed by default — see the command
      above.
- [ ] **`Ashfaaq98/homebrew-tap` exists**, and `HOMEBREW_TAP_TOKEN` is set.
- [ ] **`Ashfaaq98/scoop-bucket` exists**, and `SCOOP_BUCKET_TOKEN` is set. `skip_upload: auto`
      means a missing bucket breaks nothing until the first real tag — and then it breaks the
      release, at the last step, after the archives are already published. This is exactly how the
      Homebrew step nearly went at v0.1.1.
- [ ] **`CHANGELOG.md` has an entry for the version**, with an upgrade note for anything that
      changed under a user: keys that moved, commands that were removed, a database that migrates.
- [ ] **The suite passes both ways.** `go test ./...` and `CGO_ENABLED=0 go test ./...` — they select
      different SQLite drivers, and the shipped binary uses the second.
- [ ] **`-race` is clean** over `internal/ui`, `internal/store`, `internal/report`,
      `internal/ingest` and `cmd`.
- [ ] **CI is green on all three platforms.** The `cross-platform` job covers macOS and Windows;
      before it existed, three-platform support rested on cross-compilation alone.

## What Happens on a Release

1. Commit release-prep changes to `main`.
2. Push a tag like `v0.1.0`.
3. GitHub Actions runs [`.github/workflows/release.yml`](workflows/release.yml).
4. GoReleaser builds archives, checksums, SBOMs and Homebrew metadata.
5. GitHub publishes the release assets and release notes.

## Recommended First Release Flow

Use a release candidate first so we can validate the pipeline safely.

### 1. Commit the release work

Suggested commit message:

```text
chore: prepare console-ir for automated releases
```

### 2. Create the Homebrew tap and Scoop bucket repos

Create two public repositories: `Ashfaaq98/homebrew-tap` and `Ashfaaq98/scoop-bucket`.

Expected structure after the first release:

```text
homebrew-tap/
  Formula/
    console-ir.rb

scoop-bucket/
  console-ir.json
```

### 3. Add GitHub repository secrets

Add these secrets in `Ashfaaq98/ocsf-console-ir`:

- `HOMEBREW_TAP_TOKEN`
  Personal access token with permission to push to `Ashfaaq98/homebrew-tap`.
- `SCOOP_BUCKET_TOKEN`
  Personal access token with permission to push to `Ashfaaq98/scoop-bucket`. The bucket repo must
  exist before the first non-prerelease tag, exactly as the Homebrew tap must — `skip_upload: auto`
  keeps snapshots and prereleases from touching either.
- `GPG_PRIVATE_KEY`
  Optional. Only needed if you want signing.
- `GPG_PASSPHRASE`
  Optional. Passphrase for the GPG key if used.

### 4. Push a release candidate tag

If you want to exercise the real tag pipeline, use a stable semver tag only after you are ready for public assets.

Example:

```bash
git checkout main
git pull --ff-only
git tag v0.1.0
git push origin v0.1.0
```

If you want a lighter local check first:

```bash
goreleaser check
goreleaser release --snapshot --clean
```

## What To Verify After Tagging

### GitHub Release

Check that the release contains:

- Linux archives for `amd64` and `arm64`
- macOS archives for `amd64` and `arm64`
- Windows archives for `amd64` and `arm64`
- `checksums.txt`
- SBOM artifacts

### Version Output

Download one artifact and verify:

```bash
./console-ir --version
./console-ir version
```

Expected format:

```text
console-ir <version> (<commit>) built <date>
```

### Installer Script

Run:

```bash
curl -sSfL https://raw.githubusercontent.com/Ashfaaq98/ocsf-console-ir/main/scripts/install.sh | bash
```

Confirm:

- the correct archive is downloaded
- checksum verification passes
- `console-ir --help` works


### Homebrew

Verify the formula was created in `Ashfaaq98/homebrew-tap`, then test:

```bash
brew install Ashfaaq98/tap/console-ir
console-ir --version
```

### Scoop

Verify the manifest was created in `Ashfaaq98/scoop-bucket`, then test on Windows:

```pwsh
scoop bucket add ashfaaq98 https://github.com/Ashfaaq98/scoop-bucket
scoop install console-ir
console-ir --version
```

## Rollback Plan

If a tagged release is broken:

1. Delete the tag locally and on GitHub.
2. Fix the issue on `main`.
3. Re-tag with a new version.

Example:

```bash
git tag -d v0.1.0
git push origin :refs/tags/v0.1.0
```

Do not reuse the same version number after a public broken release. Prefer `v0.1.1`.

## Notes

- This file lives in `.github/` rather than `docs/` on purpose: `docs/*` is copied into every
  release archive, and a runbook about pushing tags is not documentation for someone who downloaded
  a binary.
- The release source of truth is [`.goreleaser.yaml`](../.goreleaser.yaml).
- The public install paths are documented in [README.md](../README.md).
