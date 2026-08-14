package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// openSettings opens the panel and returns it, so a test can drive it.
func openSettings(t *testing.T, ui *UI, category string) *settingsPanel {
	t.Helper()
	p := &settingsPanel{ui: ui, categories: settingsCatalog()}
	for i, c := range p.categories {
		if strings.EqualFold(c.name, category) {
			p.active = i
		}
	}
	p.build()
	t.Cleanup(func() {
		if ui.activeModal != nil {
			ui.closeModal()
		}
	})
	return p
}

// Settings are reachable from every screen, including inside a case.
//
// They were not: the case screen installs its own application-wide capture
// while it is open, so the comma never arrived — on the one screen where the
// copilot is in front of you, failing, and you want to change the provider.
func TestSettingsOpenFromEveryScreen(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)

	for _, dest := range []destinationID{destTriage, destCases, destEvents,
		destIndicators, destReports} {
		ui.enterScreen(dest)
		awaitIdle(t, ui)

		if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, ',', tcell.ModNone)) != nil {
			t.Errorf("the settings key was not claimed on %v", dest)
			continue
		}
		if ui.activeModal == nil {
			t.Errorf("the settings panel did not open on %v", dest)
		}
		ui.closeModal()
	}

	// And inside a case.
	cm := openCase(t, ui)
	if cm.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, ',', tcell.ModNone)) != nil {
		t.Fatal("the case screen did not claim the settings key")
	}
	if ui.activeModal == nil {
		t.Error("the settings panel did not open from inside a case")
	}
}

// Every row says where its value came from.
//
// With defaults, a config file, flags and choices made here, the useful
// question is not what can be changed but why a value is what it is.
func TestEveryRowNamesItsSource(t *testing.T) {
	ui, _ := newTestUI(t)

	for _, c := range settingsCatalog() {
		for _, s := range c.settings {
			if s.source == nil {
				t.Errorf("%s / %s has no source", c.name, s.name)
				continue
			}
			if label := s.source(ui).label(); label == "" {
				t.Errorf("%s / %s renders an empty source", c.name, s.name)
			}
			if s.value == nil || s.value(ui) == "" {
				t.Errorf("%s / %s renders no value", c.name, s.name)
			}
		}
	}
}

// A row a flag has already decided explains itself rather than accepting a
// change it cannot keep.
func TestLockedRowsExplainThemselves(t *testing.T) {
	for _, c := range settingsCatalog() {
		for _, s := range c.settings {
			if s.readOnly() && strings.TrimSpace(s.locked) == "" {
				t.Errorf("%s / %s cannot be changed and does not say why", c.name, s.name)
			}
			if !s.readOnly() && s.locked != "" {
				t.Errorf("%s / %s is editable but claims to be locked", c.name, s.name)
			}
		}
	}
}

// Enter on a locked row says why, on the status bar, rather than doing nothing.
func TestEnterOnALockedRowSaysWhy(t *testing.T) {
	ui, _ := newTestUI(t)
	p := openSettings(t, ui, "System")

	// Every System row is read-only.
	p.rows.Select(1, 0)
	p.activate()

	if got := stripTags(ui.statusBar.GetText(true)); strings.TrimSpace(got) == "" {
		t.Error("pressing Enter on a read-only row said nothing")
	}
}

// Search reaches across every category, because with six of them browsing
// stops being how you find a setting.
func TestSearchReachesEveryCategory(t *testing.T) {
	ui, _ := newTestUI(t)
	p := openSettings(t, ui, "General")

	p.search = "token"
	p.renderRows()

	if len(p.rowsFor) == 0 {
		t.Fatal("searching for a word in another category found nothing")
	}
	found := false
	for _, s := range p.rowsFor {
		if strings.Contains(strings.ToLower(s.name), "token") ||
			strings.Contains(strings.ToLower(s.search), "token") {
			found = true
		}
	}
	if !found {
		t.Errorf("the search returned rows that do not match: %v", p.rowsFor)
	}

	// A search that matches nothing says so rather than showing an empty table.
	p.search = "zzzznothing"
	p.renderRows()
	if got := p.rows.GetCell(1, 0); got == nil || !strings.Contains(got.Text, "Nothing matches") {
		t.Error("a search with no results does not say so")
	}
}

// A preference is written to disk the moment it changes — there is no Save
// button, because a panel with one has a state where the screen and the file
// disagree.
func TestChangingAPreferencePersists(t *testing.T) {
	ui, _ := newTestUI(t)

	ui.prefs.Analyst = "p.osei"
	ui.applyPreferences()

	if got := loadUISettings().Preferences.Analyst; got != "p.osei" {
		t.Errorf("the analyst name was not persisted: %q", got)
	}
	if got := ui.currentAnalyst(); got != "p.osei" {
		t.Errorf("the name in force is %q, want p.osei", got)
	}

	// And cleared, it falls back to the environment rather than to the empty
	// string.
	ui.prefs.Analyst = ""
	ui.applyPreferences()
	if got := ui.currentAnalyst(); got != environmentAnalyst() {
		t.Errorf("cleared, the name is %q, want the environment's %q", got, environmentAnalyst())
	}
}

// The Glyphs preference reaches the renderers, which ask a package-level funnel
// rather than holding a copy.
func TestGlyphPreferenceReachesTheRenderers(t *testing.T) {
	ui, _ := newTestUI(t)
	t.Cleanup(func() { setForceASCII(false) })

	ui.prefs.ASCII = true
	ui.applyRuntimePreferences()
	if supportsUnicode() {
		t.Error("ASCII was chosen and the renderers still report Unicode")
	}

	ui.prefs.ASCII = false
	ui.applyRuntimePreferences()
	// Back to whatever the environment says, whichever that is.
	setForceASCII(false)
}

// And the same for relative ages, which every list reads through one function.
func TestRelativeAgePreferenceReachesTheRenderers(t *testing.T) {
	ui, _ := newTestUI(t)
	t.Cleanup(func() { setAbsoluteAges(false) })

	when := time.Now().Add(-90 * time.Minute)

	ui.prefs.NoRelativeAges = false
	ui.applyRuntimePreferences()
	if got := renderRelativeTime(when); !strings.HasSuffix(got, "h") && !strings.HasSuffix(got, "m") {
		t.Errorf("with relative ages on, a time renders as %q", got)
	}

	ui.prefs.NoRelativeAges = true
	ui.applyRuntimePreferences()
	if got := renderRelativeTime(when); !strings.Contains(got, ":") {
		t.Errorf("with relative ages off, a time renders as %q, want a clock time", got)
	}
}

// Every category holds at least one row, and no two categories share a name.
func TestTheCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range settingsCatalog() {
		if len(c.settings) == 0 {
			t.Errorf("category %q is empty", c.name)
		}
		if c.blurb == "" {
			t.Errorf("category %q has no blurb", c.name)
		}
		if seen[c.name] {
			t.Errorf("category %q appears twice", c.name)
		}
		seen[c.name] = true

		names := map[string]bool{}
		for _, s := range c.settings {
			if names[s.name] {
				t.Errorf("%s has two rows called %q", c.name, s.name)
			}
			names[s.name] = true
			if len(s.detail) == 0 && s.detailFor == nil {
				t.Errorf("%s / %s explains nothing", c.name, s.name)
			}
		}
	}
}
