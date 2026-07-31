// Package buildinfo normalises the version and build stamps for display.
//
// It exists because the two build paths disagree about what they hand the
// binary, and because more than one surface shows it. The TUI header and
// `console-ir version` previously formatted the same values independently and
// gave different answers to "what am I running".
//
//	GoReleaser  -X main.Version={{ .Version }}   → "0.2.0"
//	                        BuildTime={{ .Date }} → "2026-07-30T17:09:47Z"
//	Makefile    -X main.Version=$(git describe)  → "v0.1.1-21-ge5d5020-dirty"
//	                        BuildTime=$(date)     → "2026-07-30T17:09:47Z"
package buildinfo

import (
	"regexp"
	"strings"
	"time"
)

// describeSuffix matches the commits-since-tag and commit hash that
// `git describe` appends to a build made between releases.
var describeSuffix = regexp.MustCompile(`-\d+-g[0-9a-f]+(-dirty)?$`)

// Display returns the version to show a user.
//
// A raw `git describe` string ("v0.1.1-21-ge5d5020-dirty") is a precise
// identifier and an unreadable label, so a between-releases build is shown as
// "v0.1.1+dev" — SemVer build metadata, which exists for exactly this. The
// commit is reported separately by Commit(), where it can be read.
//
// A release build carries no suffix and is shown unchanged: v0.2.0 is v0.2.0.
func Display(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return "dev"
	}
	// TrimLeft rather than TrimPrefix: the header used to prepend a literal "v"
	// to a version that already had one, and a doubled prefix should collapse
	// rather than merely be reduced by one.
	v = "v" + strings.TrimLeft(v, "v")
	if base := describeSuffix.ReplaceAllString(v, ""); base != v {
		return base + "+dev"
	}
	return v
}

// IsDirty reports whether the build included uncommitted changes. That flag only
// ever appears in the describe string, so it has to be read before Display
// discards the suffix.
func IsDirty(version string) bool {
	return strings.HasSuffix(strings.TrimSpace(version), "-dirty")
}

// buildTimeLayouts are the formats the build stamps have used. RFC3339 is what
// both paths emit now; the underscore form is what older Makefile builds
// produced and is kept so an existing binary still prints a sensible date.
var buildTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02_15:04:05",
	"2006-01-02 15:04:05",
}

// BuildTime renders the build stamp in one readable form regardless of which
// layout the build supplied. Unparseable input is returned as-is: showing an
// odd string beats claiming a time we did not derive.
func BuildTime(stamp string) string {
	s := strings.TrimSpace(stamp)
	if s == "" {
		return "unknown"
	}
	for _, layout := range buildTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05 UTC")
		}
	}
	return s
}
