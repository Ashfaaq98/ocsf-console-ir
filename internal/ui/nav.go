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

	// hints are the keys this screen owns, for the status bar. They live here
	// with the rail's label and the palette's description so the three cannot
	// drift — and so a key can only be advertised by naming the screen that
	// handles it.
	//
	// Only keys that work. The bar used to pick its hints from which widget had
	// focus, and on three of the five screens nothing relevant did, so it fell
	// through to the same six every time — naming panels those screens do not
	// have and a filter key they do not bind.
	hints []keyHint

	// showFindings and showAll are the two flags that decide what the shared
	// events table is showing. They live here rather than being set by hand at
	// the top of each switchTo* function, where four copies could and did
	// disagree about what a screen is.
	showFindings bool
	showAll      bool

	open func(*UI)
}

// destinations is the single source of truth. Order is the rail's order.
//
// A function rather than a package variable: the handlers are methods that
// transitively read this table when they repaint the rail, and Go rejects that
// as an initialisation cycle at package level.
// The order follows the work: triage a finding, escalate it into a case, work
// the case. Events is the corroboration surface you reach from a finding or a
// case rather than the second place you go, so it sits behind Cases.
func destinations() []destination {
	return []destination{
		{destTriage, '1', "Triage", "Ranked queue of open findings",
			[]keyHint{{"Space", "select"}, {"e", "escalate"}, {"v", "verdict"},
				{"s", "status"}, {"f", "filter"}, {"/", "search"}, {"Tab", "detail"}},
			true, false, (*UI).jumpToFindings},
		{destCases, '2', "Cases", "Investigations and briefings",
			[]keyHint{{"⏎", "open"}, {"c", "new case"}, {"f", "filter"}, {"r", "refresh"}},
			false, false, (*UI).switchToCases},
		{destEvents, '3', "Events", "Corroborating OCSF events",
			[]keyHint{{"⏎", "expand"}, {"p", "pivot"}, {"z", "regroup"},
				{"f", "filter"}, {"N", "next"}, {"P", "prev"}, {"Tab", "detail"}},
			false, true, (*UI).switchToAllEvents},
		{destIndicators, '4', "Indicators", "Every observable in the database",
			[]keyHint{{"⏎", "pivot"}, {"/", "search"}, {"f", "type"}, {"r", "refresh"}},
			false, false, (*UI).switchToIndicators},
		{destReports, '5', "Reports", "Written-up cases, kept",
			[]keyHint{{"n", "new"}, {"⏎", "read"}, {"w", "to file"}, {"d", "delete"},
				{"Tab", "pane"}},
			false, false, (*UI).switchToReports},
	}
}

// lookupDestinationByID returns a destination by identity.
func lookupDestinationByID(id destinationID) (destination, bool) {
	if id == destHome {
		return homeDestination(), true
	}
	for _, d := range destinations() {
		if d.id == id {
			return d, true
		}
	}
	return destination{}, false
}

// homeDestination is Home's entry, kept out of the numbered list but present in
// the palette and the key reference so it is never an undocumented screen.
func homeDestination() destination {
	return destination{destHome, 0, "Home", "What needs attention now",
		[]keyHint{{"↑↓", "move"}, {"⏎", "open"}, {"e", "escalate"},
			{"v", "verdict"}, {"r", "refresh"}, {"t", "theme"}},
		false, false, (*UI).showAnalystHome}
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
	ui.enterScreen(d.id)
	return true
}

// enterScreen is the one way to arrive at a screen.
//
// Every route in — a digit, a letter shortcut, Esc, the command palette, a
// pivot, a cleared filter — goes through here, so none of them can forget to
// mark the rail or to clear what the previous screen left behind. Both were
// forgotten routinely: reaching Events with `A` left the rail marking Triage,
// and Events opened titled "FINDINGS · N of N" with the previous finding still
// in the inspector.
func (ui *UI) enterScreen(id destinationID) {
	d, ok := lookupDestinationByID(id)
	if !ok {
		return
	}
	ui.beginScreen(id)
	d.open(ui)
}

// beginScreen does everything except open the screen.
//
// Separate from enterScreen for the one caller that has to run its own load:
// pivotTo assigns the pivot it is about to display, and calling the destination's
// own open would immediately discard it.
func (ui *UI) beginScreen(id destinationID) {
	d, ok := lookupDestinationByID(id)
	if !ok {
		return
	}
	ui.leaveScreen()
	ui.showFindings = d.showFindings
	ui.showAll = d.showAll
	ui.selectedCaseID = ""
	ui.setDestination(id)
}

// leaveScreen clears everything the outgoing screen leaves in shared state.
//
// Triage and Events are one table and one detail pane wearing two names, and
// the switch used to reset four fields out of a dozen. Everything below either
// belongs to whichever of the two was last shown, or describes a query that no
// longer applies; a screen that inherits any of it is a screen describing the
// one before it.
func (ui *UI) leaveScreen() {
	if ui.eventDetail != nil {
		ui.eventDetail.SetTitle(" Details ")
		ui.eventDetail.SetText("")
	}
	if ui.eventList != nil {
		ui.eventList.SetTitle("")
	}

	// Triage's result set and its selection.
	ui.findings = nil
	ui.findingsErr = nil
	ui.findingsTotal = 0
	ui.findingsUnfiltered = 0
	ui.selectedFindingID = ""
	if ui.triageSel != nil {
		ui.triageSel.clear()
	}

	// The events page, its clustering, and the queries that produced it.
	ui.events = nil
	ui.selectedEventID = ""
	ui.selectedEventIDs = nil
	ui.eventClusters = nil
	ui.eventAtRow = nil
	ui.expandedCluster = ""
	ui.searchQuery = ""
	ui.pivot = nil
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
			Action:      func() { ui.enterScreen(d.id) },
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

// screenHints are the keys the current screen owns, plus help, which every
// screen has and which is the way to find everything not listed.
func (ui *UI) screenHints() []keyHint {
	d, ok := lookupDestinationByID(ui.destination)
	if !ok {
		return []keyHint{{"?", "help"}}
	}
	return append(append([]keyHint{}, d.hints...), keyHint{"?", "help"})
}

// hasEventsContext reports whether the screen showing is paged, filtered and
// selected over events. Only the Events screen is.
//
// The status bar's badges — the page counter, the total, the selection count —
// all describe that context, and were drawn everywhere: "Page:1/1 Tot:25" under
// the Cases list, and "Tot:0" under a Triage queue holding two hundred findings.
func (ui *UI) hasEventsContext() bool {
	return ui.destination == destEvents
}

// eventsListOnScreen says whether the shared events table is part of what is
// being drawn. On Cases and Indicators it is loaded but not shown, so nothing
// that loads it may take focus.
// onReports says whether the Reports screen is showing.
func (ui *UI) onReports() bool { return ui.destination == destReports }

func (ui *UI) eventsListOnScreen() bool {
	return ui.destination == destEvents || ui.activeCM != nil
}
