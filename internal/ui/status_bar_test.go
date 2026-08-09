package ui

import (
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

// The one bar at the foot of the application carries the product name, and it
// is the only place that does.
//
// It used to be under the navigation rail as well, and in every screen's header
// — three "Console-IR"s on one screen, two of the rail's twenty-two columns
// spent on a version string, and two separate implementations of the same block
// that drifted apart the moment a theme was applied.
func newStatusUI() *UI {
	return &UI{theme: themeDark(), version: "v0.2.0"}
}

func TestStatusBarCarriesTheBrandAndVersions(t *testing.T) {
	got := stripTags(newStatusUI().composeStatus("Ready"))

	if !strings.Contains(got, "Console-IR v0.2.0") {
		t.Errorf("tool version is not next to the name:\n%s", got)
	}
	if strings.Contains(got, "vv") {
		t.Errorf("doubled v in the status bar:\n%s", got)
	}
	// The schema version is a credibility signal for an OCSF-native tool, and it
	// comes from the vendored registry rather than a hardcoded string.
	if !strings.Contains(got, "OCSF "+ocsf.SchemaVersion()) {
		t.Errorf("OCSF schema version missing (want %q):\n%s", ocsf.SchemaVersion(), got)
	}
	if !strings.Contains(got, "Ready") {
		t.Errorf("the message was lost:\n%s", got)
	}
}

// The brand leads the bar. Anything else there pushes the one fixed thing on
// the screen around as the message beside it changes length.
func TestStatusBarLeadsWithTheBrand(t *testing.T) {
	got := stripTags(newStatusUI().composeStatus("Ready"))

	if !strings.HasPrefix(strings.TrimSpace(got), "Console-IR") {
		t.Errorf("the bar does not start with the product name:\n%q", got)
	}
}

// Content, not colour, must survive a theme switch — the old header had two
// implementations and a theme change silently reverted one of them.
func TestStatusBarIsStableAcrossThemeChanges(t *testing.T) {
	ui := newStatusUI()
	before := stripTags(ui.composeStatus("Ready"))

	ui.theme = themeLight()
	after := stripTags(ui.composeStatus("Ready"))

	if before != after {
		t.Errorf("status bar content changed with the theme:\n  before %q\n  after  %q", before, after)
	}
}

// It is composed during construction and from input handlers, so a half-built
// UI must not panic.
func TestComposeStatusOnABareUI(t *testing.T) {
	(&UI{theme: themeDark()}).composeStatus("")
}

// The dashboard's bar advertises the dashboard's keys.
//
// The hints are otherwise scoped by which events widget has focus, and on Home
// none of them does — so it fell through to a list naming panels Home does not
// have, a filter key it does not bind, and "Page:1/15 Tot:712" underneath a
// screen with no pager.
func TestStatusBarOnHomeShowsHomesKeys(t *testing.T) {
	h, _ := newTestHome(t)
	h.ui.showAnalystHome()

	got := stripTags(h.ui.composeStatus("Analyst Home"))

	for _, want := range []string{"e escalate", "v verdict", "r refresh"} {
		if !strings.Contains(got, want) {
			t.Errorf("the dashboard's bar is missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"Page:", "Tot:", "all events", "panels"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("the dashboard's bar advertises %q, which belongs to the events screen:\n%s",
				unwanted, got)
		}
	}
}
