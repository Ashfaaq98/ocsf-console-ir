package ui

import (
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/rivo/tview"
)

// The header used to be written out in full in two places, so a change to one
// reverted as soon as a theme was applied. Assert it survives a theme switch.
func TestHeaderIsStableAcrossThemeChanges(t *testing.T) {
	ui := &UI{
		appTitle: tview.NewTextView().SetDynamicColors(true),
		theme:    themeDark(),
		version:  "0.2.0",
	}

	ui.renderHeader()
	before := ui.appTitle.GetText(true)

	ui.theme = themeLight()
	ui.renderHeader()
	after := ui.appTitle.GetText(true)

	if before != after {
		t.Errorf("header content changed with the theme:\n  before %q\n  after  %q", before, after)
	}
}

func TestHeaderCarriesVersionsAndDate(t *testing.T) {
	ui := &UI{
		appTitle: tview.NewTextView().SetDynamicColors(true),
		theme:    themeDark(),
		version:  "v0.2.0",
	}
	ui.renderHeader()
	got := ui.appTitle.GetText(true)

	if !strings.Contains(got, "Console-IR v0.2.0") {
		t.Errorf("tool version is not next to the name:\n%s", got)
	}
	if strings.Contains(got, "vv") {
		t.Errorf("doubled v in the header:\n%s", got)
	}
	// The schema version is a credibility signal for an OCSF-native tool, and it
	// comes from the vendored registry rather than a hardcoded string.
	if !strings.Contains(got, "OCSF "+ocsf.SchemaVersion()) {
		t.Errorf("OCSF schema version missing (want %q):\n%s", ocsf.SchemaVersion(), got)
	}
	if len(strings.Split(strings.TrimRight(got, "\n"), "\n")) != 2 {
		t.Errorf("header is not two lines:\n%q", got)
	}
}

// A nil widget happens during construction ordering; rendering must not panic.
func TestRenderHeaderWithNoWidget(t *testing.T) {
	(&UI{theme: themeDark()}).renderHeader()
}
