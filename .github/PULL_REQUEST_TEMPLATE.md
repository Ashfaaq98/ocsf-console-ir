---
name: Pull Request
about: Propose changes to OCSF Console IR
title: ""
labels: ""
assignees: ""
---

> **Before you spend time on this:** Console-IR is single-author for now, and substantial code
> cannot be merged without a Contributor License Agreement — see
> [CONTRIBUTING.md](../CONTRIBUTING.md#licensing-and-contributions). Trivial fixes (typos, broken
> links) are fine as-is. For anything larger, an issue first will get you an answer faster than a
> patch will.

## Summary
Briefly describe what this PR changes and why.

## Type of change
- [ ] Feature
- [ ] Bug fix
- [ ] Docs update
- [ ] Refactor/Chore
- [ ] Other (describe):

## Checklist
- [ ] Code formatted (`gofmt`, `goimports`)
- [ ] Local checks pass (`make check` or `go test -race ./...`)
- [ ] Lint passes (`golangci-lint run ./...`) if available
- [ ] Tests added/updated when applicable
- [ ] Docs updated (README or docs/*) if behavior changes
- [ ] Backward compatibility considered

## How to test
Steps or commands to validate the change locally.

```bash
# example
make build
./bin/console-ir version
```

## Related issues
Link to related issues (e.g., Fixes #123).

## Additional context
Anything else reviewers should know (risks, rollout, screenshots, etc.).