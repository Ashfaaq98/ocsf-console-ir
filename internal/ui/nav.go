package ui

import (
	"fmt"
	"strings"

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
	// Named for what it holds. It carried the product name, which the footer
	// also carried, and so did every screen's header — three of them on one
	// screen, and none of the three said what this panel was for.
	stylePanel(rail.Box, "NAVIGATION", PanelRoleRail, ui.theme)
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

	// Home leads the list of places rather than sitting under the divider with
	// the command palette and the help key. It is a destination — the one every
	// other destination returns to — and grouping it with the utilities made it
	// read as a shortcut rather than as somewhere you can be.
	b = append(b, ui.railRow(homeDestination(), "Esc")...)

	for _, d := range destinations() {
		b = append(b, ui.railRow(d, string(d.key))...)
	}

	b = append(b, fmt.Sprintf("\n [%s]%s[-:-:-]\n", t.TagMuted, strings.Repeat("─", navRailWidth-4))...)

	for _, hint := range []struct{ key, label string }{
		{":", "Command"},
		{"?", "Help"},
	} {
		b = append(b, fmt.Sprintf("   [%s]%-3s[-:-:-] [%s]%s[-:-:-]\n",
			t.TagAccent, hint.key, t.TagMuted, hint.label)...)
	}

	ui.navRail.SetText(string(b))
}

// railRow is one destination on the rail.
//
// The marker is a glyph, not just a colour: which screen you are on has to
// survive a 16-colour terminal. The name carries no number of its own — tview
// renders the shortcut gutter, and the labels used to embed the digit as well,
// giving "(1) 1. Triage".
func (ui *UI) railRow(d destination, key string) []byte {
	t := ui.theme
	marker, colour := " ", t.TagTextPrimary
	if d.id == ui.destination {
		marker, colour = "▸", t.TagAccent
	}
	return []byte(fmt.Sprintf(" [%s]%s[-:-:-] [%s]%-3s[-:-:-] [%s]%s[-:-:-]\n",
		t.TagAccent, marker, t.TagAccent, key, colour, d.name))
}

// navRailVisible reports whether the rail should be drawn.
//
// Hidden below 80 columns, where 22 of them is more than a quarter of the
// screen and the keys still work. Shown everywhere else, including Home: an
// analyst who cannot see the destinations cannot learn them.
func (ui *UI) navRailVisible() bool {
	return ui.currentLayoutMode != LayoutCompact
}

// destinationCommands renders the navigation model as command-palette entries.
//
// Home is included: it is not on the numbered list, so the palette is the only
// place it can be discovered by name.
func (ui *UI) destinationCommands() []CommandItem {
	all := append([]destination{homeDestination()}, destinations()...)

	out := make([]CommandItem, 0, len(all))
	for _, d := range all {
		d := d
		shortcut := "Esc"
		if d.key != 0 {
			shortcut = string(d.key)
		}
		out = append(out, CommandItem{
			Name:        "go " + strings.ToLower(d.name),
			Shortcut:    shortcut,
			Description: d.desc,
			Action:      func() { ui.setDestination(d.id); d.open(ui) },
		})
	}
	return out
}

// navKeyReference renders the navigation model for the help screen, so the key
// reference documents exactly what the keys do.
func (ui *UI) navKeyReference() string {
	var b strings.Builder
	for _, d := range destinations() {
		fmt.Fprintf(&b, "  %c        %s — %s\n", d.key, d.name, d.desc)
	}
	fmt.Fprintf(&b, "  Esc      Home — %s\n", homeDestination().desc)
	return b.String()
}

// onCases reports whether the Cases screen is the one currently showing.
//
// Derived from the widget tree rather than a flag, for the same reason onHome
// is: a flag has to be cleared by every other screen, and the one that forgets
// sends input to a screen that has already been replaced.
func (ui *UI) onCases() bool {
	if ui.casesPane == nil || ui.mainPanel == nil {
		return false
	}
	return ui.mainPanel.GetItemCount() > 0 && ui.mainPanel.GetItem(0) == ui.casesPane
}
