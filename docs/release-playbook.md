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
make release-check SKIP=docker    # skip the image build (no Docker daemon)
```

This runs `goreleaser check` and then `goreleaser release --snapshot --clean`, building every
archive, checksum, SBOM, Homebrew formula and container image locally. `docker_manifests` sets
`skip_push: auto`, so a snapshot never pushes.

It matters because the release workflow runs GoReleaser as a **single step** — if the Docker build
fails, the binaries and the Homebrew formula fail with it. The Homebrew step nearly broke this way at
v0.1.1 and was only caught because it had been disabled first.

CI runs the same target on every pull request.

## What Happens on a Release

1. Commit release-prep changes to `main`.
2. Push a tag like `v0.1.0`.
3. GitHub Actions runs [`.github/workflows/release.yml`](.github/workflows/release.yml).
4. GoReleaser builds archives, checksums, SBOMs, Homebrew metadata, and Docker images.
5. GitHub publishes the release assets and release notes.

## Recommended First Release Flow

Use a release candidate first so we can validate the pipeline safely.

### 1. Commit the release work

Suggested commit message:

```text
chore: prepare console-ir for automated releases
```

### 2. Create the Homebrew tap repo

Create a public repository named `Ashfaaq98/homebrew-tap`.

Expected structure after the first release:

```text
homebrew-tap/
  Formula/
    console-ir.rb
```

### 3. Add GitHub repository secrets

Add these secrets in `Ashfaaq98/ocsf-console-ir`:

- `HOMEBREW_TAP_TOKEN`
  Personal access token with permission to push to `Ashfaaq98/homebrew-tap`.
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
- Windows archive for `amd64`
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

### Docker

Check both:

```bash
docker run --rm -it ghcr.io/ashfaaq98/console-ir:latest --help
docker run --rm -it -p 8080:8080 -v "$(pwd)/data:/data" ghcr.io/ashfaaq98/console-ir:latest
```

Confirm the container starts in headless mode and exposes HTTP ingest on `0.0.0.0:8080`.

### Homebrew

Verify the formula was created in `Ashfaaq98/homebrew-tap`, then test:

```bash
brew install Ashfaaq98/tap/console-ir
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

- The Markdown files in `.github/` are in the right place. They are GitHub issue and PR templates, not product docs.
- The release source of truth is [`.goreleaser.yaml`](.goreleaser.yaml).
- The public install paths are documented in [README.md](README.md).
