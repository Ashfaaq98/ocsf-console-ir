package ui

import (
	"os"
	"strings"
	"testing"
)

// The navigation model is one table read three ways. These tests exist because
// it used to be three tables: the rail advertised ALL EVENTS for a key that
// went to Triage, and (C) CASES for a key with no handler at all. Neither was
// a typo — both were copies that drifted.

func newNavUI(t *testing.T) *UI {
	t.Helper()
	withTempConfig(t)
	ui := &UI{theme: themeDark()}
	ui.navRail = ui.buildNavRail()
	return ui
}

// The keys are specified. Changing one is a product decision, not a refactor.
//
// The order follows the work — triage a finding, escalate it into a case, work
// the case — so Cases sits at 2 and Events, which is the corroboration surface
// you reach from a finding or a case, sits behind it.
func TestDestinationsMatchTheSpecifiedKeymap(t *testing.T) {
	want := []struct {
		key  rune
		name string
	}{
		{'1', "Triage"},
		{'2', "Cases"},
		{'3', "Events"},
		{'4', "Indicators"},
		{'5', "Reports"},
	}

	got := destinations()
	if len(got) != len(want) {
		t.Fatalf("%d destinations, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].key != w.key || got[i].name != w.name {
			t.Errorf("destination %d = %c %s, want %c %s",
				i, got[i].key, got[i].name, w.key, w.name)
		}
	}
}

// No key may mean two things, and every destination must be reachable.
func TestDestinationKeysDoNotCollide(t *testing.T) {
	seen := map[rune]string{}
	for _, d := range destinations() {
		if prev, clash := seen[d.key]; clash {
			t.Errorf("key %c is bound to both %s and %s", d.key, prev, d.name)
		}
		seen[d.key] = d.name

		if d.open == nil {
			t.Errorf("%s has no handler, so its key does nothing", d.name)
		}
		if strings.TrimSpace(d.desc) == "" {
			t.Errorf("%s has no description, so the palette and help cannot list it", d.name)
		}
	}
}

// Home is not a numbered destination, and must not quietly become one.
func TestHomeIsNotANumberedDestination(t *testing.T) {
	for _, d := range destinations() {
		if d.id == destHome {
			t.Fatalf("Home is bound to %c; it is reached with Esc", d.key)
		}
	}
	if h := homeDestination(); h.key != 0 {
		t.Errorf("Home has key %c, want none", h.key)
	}
}

// Every key the rail shows must dispatch. This is the exact failure the rail
// used to have: a label with nothing behind it.
func TestEveryRailKeyDispatches(t *testing.T) {
	ui := newNavUI(t)
	ui.renderNavRail()
	rail := ui.navRail.GetText(true)

	for _, d := range destinations() {
		if !strings.Contains(rail, d.name) {
			t.Errorf("the rail does not show %s", d.name)
		}
		if _, ok := lookupDestination(d.key); !ok {
			t.Errorf("the rail shows %c %s but no destination is bound to that key", d.key, d.name)
		}
	}

	// And nothing the rail shows is unreachable.
	for _, line := range strings.Split(rail, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		if fields[0] == "▸" {
			key = fields[1]
		}
		if len(key) != 1 || key[0] < '1' || key[0] > '9' {
			continue
		}
		if _, ok := lookupDestination(rune(key[0])); !ok {
			t.Errorf("the rail advertises key %s, which reaches nothing: %q", key, line)
		}
	}
}

// The palette and the help reference are generated, so they cannot disagree
// with the rail about where a key goes.
func TestPaletteAndHelpAgreeWithTheRail(t *testing.T) {
	ui := newNavUI(t)

	commands := ui.destinationCommands()
	byName := map[string]CommandItem{}
	for _, c := range commands {
		byName[c.Name] = c
	}

	for _, d := range destinations() {
		name := "go " + strings.ToLower(d.name)
		c, ok := byName[name]
		if !ok {
			t.Errorf("the palette does not offer %q", name)
			continue
		}
		if c.Shortcut != string(d.key) {
			t.Errorf("the palette lists %q for %s, the rail lists %c", c.Shortcut, d.name, d.key)
		}
	}

	// Home is reachable by name even though it has no digit.
	if _, ok := byName["go home"]; !ok {
		t.Error("the palette does not offer Home, which has no key of its own")
	}

	ref := ui.navKeyReference()
	for _, d := range destinations() {
		if !strings.Contains(ref, d.name) {
			t.Errorf("the key reference omits %s", d.name)
		}
	}
}

// The marker says where you are, with a glyph rather than only a colour.
func TestRailMarksTheCurrentDestination(t *testing.T) {
	ui := newNavUI(t)

	for _, d := range destinations() {
		ui.destination = d.id
		ui.renderNavRail()

		for _, line := range strings.Split(ui.navRail.GetText(true), "\n") {
			if !strings.Contains(line, d.name) {
				continue
			}
			if !strings.Contains(line, "▸") {
				t.Errorf("on %s the rail does not mark it: %q", d.name, line)
			}
		}
	}

	// Home is marked too, even though it is reached with Esc.
	ui.destination = destHome
	ui.renderNavRail()
	for _, line := range strings.Split(ui.navRail.GetText(true), "\n") {
		if strings.Contains(line, "Home") && !strings.Contains(line, "▸") {
			t.Errorf("on Home the rail does not mark it: %q", line)
		}
	}
}

// Exactly one marker at a time, or "you are here" answers twice.
func TestRailMarksExactlyOneDestination(t *testing.T) {
	ui := newNavUI(t)
	for _, id := range []destinationID{destHome, destTriage, destEvents, destCases, destIndicators, destReports} {
		ui.destination = id
		ui.renderNavRail()
		if n := strings.Count(ui.navRail.GetText(true), "▸"); n != 1 {
			t.Errorf("destination %d: %d markers on the rail, want 1", id, n)
		}
	}
}

// Case tabs move with Tab and Shift+Tab, and with nothing the global handler
// already claims.
//
// This is the binding that was broken twice. Digits route to destinations, so
// tabs bound to 1-7 never fired. Brackets route to the copilot drawer, so tabs
// bound to those did not fire either. The global capture runs before any
// screen's own handler, which is why both failures were silent.
func TestCaseTabsUseTabNotAGloballyClaimedKey(t *testing.T) {
	src := readSource(t, "case_management.go")

	if strings.Contains(src, `case '1', '2', '3', '4', '5', '6', '7':`) {
		t.Error("case tabs are bound to digits, which the global handler routes to destinations")
	}
	for _, want := range []string{"case tcell.KeyTab:", "case tcell.KeyBacktab:"} {
		if !strings.Contains(src, want) {
			t.Errorf("case tabs are not bound to %s", want)
		}
	}

	// And the global handler must let those two through, or the case never
	// sees them.
	global := readSource(t, "ui.go")
	if !strings.Contains(global, "case tcell.KeyTab, tcell.KeyBacktab:") {
		t.Error("the global handler does not pass Tab through to an open case, so the tabs cannot fire")
	}
}

// wrapTab has to wrap both ways, or Shift+Tab off the first tab indexes out of
// range.
func TestWrapTab(t *testing.T) {
	n := len(caseTabNames)
	if n == 0 {
		t.Skip("no tabs defined")
	}
	for _, tc := range []struct{ in, want int }{
		{0, 0}, {n - 1, n - 1}, {n, 0}, {-1, n - 1}, {n + 1, 1},
	} {
		if got := wrapTab(tc.in); got != tc.want {
			t.Errorf("wrapTab(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// readSource reads a file from this package, so a test can assert on bindings
// that live inside a closure and cannot be reached any other way.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
