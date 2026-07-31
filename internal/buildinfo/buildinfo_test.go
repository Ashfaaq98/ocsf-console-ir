package buildinfo

import (
	"strings"
	"testing"
)

// The header rendered "vv0.1.1-16-gb359521-dirty": a literal "v" prepended to a
// version that already had one, and a describe string shown raw. Both build
// paths must come out readable, not whichever one happened to be tested.
func TestDisplay(t *testing.T) {
	cases := map[string]string{
		// Makefile: git describe --tags --always --dirty
		"v0.1.1-21-ge5d5020-dirty": "v0.1.1+dev",
		"v0.1.1-21-ge5d5020":       "v0.1.1+dev",
		"0.1.1-21-ge5d5020-dirty":  "v0.1.1+dev",
		// GoReleaser: {{ .Version }} — a release is shown exactly as it is
		"0.2.0":      "v0.2.0",
		"v0.2.0":     "v0.2.0",
		"0.2.1-next": "v0.2.1-next",
		"1.0.0-rc.1": "v1.0.0-rc.1",
		// Unset build
		"dev": "vdev",
		"":    "dev",
		"  ":  "dev",
	}
	for in, want := range cases {
		if got := Display(in); got != want {
			t.Errorf("Display(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDisplayNeverDoublesTheV(t *testing.T) {
	for _, in := range []string{"v1.2.3", "1.2.3", "vv1.2.3", "v0.1.1-9-gabc1234"} {
		if got := Display(in); strings.HasPrefix(got, "vv") {
			t.Errorf("Display(%q) = %q, which doubles the v", in, got)
		}
	}
}

// A prerelease tag is not a describe suffix and must survive intact — dropping
// "-rc.1" would make a release candidate claim to be the release.
func TestDisplayKeepsPrereleaseTags(t *testing.T) {
	for _, v := range []string{"v1.0.0-rc.1", "v1.0.0-beta", "v0.3.0-alpha.2"} {
		if got := Display(v); got != v {
			t.Errorf("Display(%q) = %q, want it unchanged", v, got)
		}
	}
}

// The dirty flag lives only in the describe suffix, so it has to be read before
// Display throws that suffix away.
func TestIsDirty(t *testing.T) {
	cases := map[string]bool{
		"v0.1.1-21-ge5d5020-dirty": true,
		"v0.1.1-21-ge5d5020":       false,
		"v0.2.0":                   false,
		"":                         false,
	}
	for in, want := range cases {
		if got := IsDirty(in); got != want {
			t.Errorf("IsDirty(%q) = %v, want %v", in, got, want)
		}
	}
}

// The two build paths used to emit different timestamp layouts; older binaries
// still carry the underscore form, so both must render the same way.
func TestBuildTime(t *testing.T) {
	want := "2026-07-30 17:09:47 UTC"
	for _, in := range []string{
		"2026-07-30T17:09:47Z", // RFC3339, both paths today
		"2026-07-30_17:09:47",  // older Makefile builds
		"2026-07-30 17:09:47",  // defensive
	} {
		if got := BuildTime(in); got != want {
			t.Errorf("BuildTime(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildTimeNormalisesToUTC(t *testing.T) {
	if got := BuildTime("2026-07-30T19:09:47+02:00"); got != "2026-07-30 17:09:47 UTC" {
		t.Errorf("BuildTime with an offset = %q, want it converted to UTC", got)
	}
}

// Inventing a timestamp we could not parse would be worse than showing the odd
// string we were handed.
func TestBuildTimePassesThroughUnparseableInput(t *testing.T) {
	if got := BuildTime("who knows"); got != "who knows" {
		t.Errorf("BuildTime(%q) = %q, want it passed through", "who knows", got)
	}
	if got := BuildTime(""); got != "unknown" {
		t.Errorf("BuildTime(\"\") = %q, want %q", got, "unknown")
	}
}
