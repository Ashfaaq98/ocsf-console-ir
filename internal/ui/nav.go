package ui

import (
	"fmt"

	"github.com/rivo/tview"
)

// Navigation is one table, rendered three ways.
//
// The rail, the command palette and the key reference used to be three
// hand-maintained lists, and they drifted: the rail advertised ALL EVENTS for a
// key that goes to Triage, and (C) CASES for a key with no handler at all. A
// destination that is not in this table does not exist — it cannot be shown, it
// cannot be dispatched, and it cannot be documented.

// destinationID identifies a top-level screen.
type destinationID int

const (
	// destHome is where the application lands and where Esc returns. It is not
	// a numbered destination: numbering it would imply it is somewhere you go
	// rather than the place you come back to.
	destHome destinationID = iota
	destTriage
	destEvents
	destCases
	destIndicators
	destReports
)

// destination is one entry in the navigation model.
type destination struct {
	id destinationID
	// key is the global shortcut. Empty for Home, which Esc reaches.
	key  rune
	name string
	// desc is one line, used by the command palette and the key reference.
	desc string
	open func(*UI)
}

// destinations is the single source of truth. Order is the rail's order.
//
// A function rather than a package variable: the handlers are methods that
// transitively read this table when they repaint the rail, and Go rejects that
// as an initialisation cycle at package level.
func destinations() []destination {
	return []destination{
		{destTriage, '1', "Triage", "Ranked queue of open findings", (*UI).jumpToFindings},
		{destEvents, '2', "Events", "Corroborating OCSF events", (*UI).switchToAllEvents},
		{destCases, '3', "Cases", "Investigations and briefings", (*UI).switchToCases},
		{destIndicators, '4', "Indicators", "Observables and watchlists", (*UI).switchToIndicators},
		{destReports, '5', "Reports", "Exports and case bundles", (*UI).switchToReports},
	}
}

// homeDestination is Home's entry, kept out of the numbered list but present in
// the palette and the key reference so it is never an undocumented screen.
func homeDestination() destination {
	return destination{destHome, 0, "Home", "What needs attention now", (*UI).showAnalystHome}
}

// lookupDestination returns the destination bound to a key.
func lookupDestination(key rune) (destination, bool) {
	for _, d := range destinations() {
		if d.key == key {
			return d, true
		}
	}
	return destination{}, false
}

// navigate opens a destination by key. It reports whether the key was one.
//
// This is the only place a digit turns into a screen. Adding a screen means
// adding a row to destinations, not editing a switch here, the rail there and
// the help text somewhere else.
func (ui *UI) navigate(key rune) bool {
	d, ok := lookupDestination(key)
	if !ok {
		return false
	}
	ui.setDestination(d.id)
	d.open(ui)
	return true
}

// setDestination records where the analyst now is, so the rail can mark it.
func (ui *UI) setDestination(id destinationID) {
	ui.destination = id
	ui.renderNavRail()
}

// ---------------------------------------------------------------------------
// The rail
// ---------------------------------------------------------------------------

// navRailWidth is the rail's width, including its border.
//
// 22, not the 45 it used to be. The old rail carried the Cases list underneath
// it, which is why it needed a third of a 140-column terminal and had to be
// hidden on the one screen that most needed to show its navigation. The Cases
// list now lives on the Cases screen, where it is the content rather than a
// permanent fixture.
const navRailWidth = 22

// buildNavRail creates the rail widget.
func (ui *UI) buildNavRail() *tview.TextView {
	rail := tview.NewTextView().SetDynamicColors(true)
	stylePanel(rail.Box, "CONSOLE-IR", PanelRoleRail, ui.theme)
	rail.SetBackgroundColor(ui.theme.Bg)
	return rail
}

// renderNavRail paints the rail for the current destination.
func (ui *UI) renderNavRail() {
	if ui.navRail == nil {
		return
	}
	t := ui.theme
	var b []byte

	b = append(b, '\n')
	for _, d := range destinations() {
		// The marker is a glyph, not just a colour: which screen you are on has
		// to survive a 16-colour terminal.
		marker, colour := " ", t.TagTextPrimary
		if d.id == ui.destination {
			marker, colour = "▸", t.TagAccent
		}
		// The name only. tview renders the shortcut gutter itself, and the
		// labels used to embed the number as well, giving "(1) 1. Triage".
		b = append(b, fmt.Sprintf(" [%s]%s[-:-:-] [%s]%c[-:-:-]  [%s]%s[-:-:-]\n",
			t.TagAccent, marker, t.TagAccent, d.key, colour, d.name)...)
	}

	b = append(b, fmt.Sprintf("\n [%s]%s[-:-:-]\n", t.TagMuted, "──────────────────")...)

	// Home is marked like any destination even though it has no digit. It is
	// where the application lands, so "you are here" has to be answerable on
	// the screen an analyst starts on.
	homeMarker, homeColour := " ", t.TagMuted
	if ui.destination == destHome {
		homeMarker, homeColour = "▸", t.TagAccent
	}
	b = append(b, fmt.Sprintf(" [%s]%s[-:-:-] [%s]Esc[-:-:-]  [%s]Home[-:-:-]\n",
		t.TagAccent, homeMarker, t.TagAccent, homeColour)...)

	for _, hint := range []struct{ key, label string }{
		{":", "Command"},
		{"?", "Help"},
	} {
		b = append(b, fmt.Sprintf("   [%s]%-3s[-:-:-] [%s]%s[-:-:-]\n",
			t.TagAccent, hint.key, t.TagMuted, hint.label)...)
	}

	ui.navRail.SetText(string(b))
}

// navRailVisible reports whether the rail should be drawn.
//
// Hidden below 80 columns, where 22 of them is more than a quarter of the
// screen and the keys still work. Shown everywhere else, including Home: an
// analyst who cannot see the destinations cannot learn them.
func (ui *UI) navRailVisible() bool {
	return ui.currentLayoutMode != LayoutCompact
}
