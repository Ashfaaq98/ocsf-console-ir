package ui

import (
	"fmt"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// renderEventInspector displays multi-card detailed evidence for a selected event.
func (ui *UI) renderEventInspector(event store.Event) string {
	var sb strings.Builder

	ip := event.SrcIP
	if ip == "" {
		ip = event.DstIP
	}

	// Header Card
	sb.WriteString(fmt.Sprintf("[%s:b]%s[-:-:-]\n", ui.theme.TagAccent, event.Message))
	sb.WriteString(fmt.Sprintf("[%s]Host: %s  ·  Time: %s  ·  Source: %s[-:-:-]\n\n",
		ui.theme.TagMuted, event.Host, event.Timestamp.Format("2006-01-02 15:04:05"), event.EventType))

	// Evidence & Class Card
	sb.WriteString(fmt.Sprintf("[%s:b]■ OCSF IDENTITY[-:-:-]\n", ui.theme.TagAccent))
	sb.WriteString(fmt.Sprintf("[%s]Class UID: %d  ·  Category: %d  ·  Severity: %s[-:-:-]\n\n",
		ui.theme.TagTextPrimary, event.ClassUID, event.CategoryUID, formatSeverityBadge(event.Severity, ui.theme)))

	// Quick Pivot hints
	sb.WriteString(fmt.Sprintf("[%s:b]■ PIVOT SHORTCUTS (Press 'p')[-:-:-]\n", ui.theme.TagAccent))
	sb.WriteString(fmt.Sprintf("[%s]Host: %s  ·  User: %s  ·  IP/Domain: %s[-:-:-]\n\n",
		ui.theme.TagAccent, event.Host, event.UserName, ip))

	return sb.String()
}

// pivotLimit bounds a pivot's result. A pivot is "where else did this appear?",
// which is a question about the first page, not about every row ever stored.
const pivotLimit = 200

// showPivotMenu opens the observable pivot for an event.
//
// Targets come from the indexed observables table rather than from the event's
// own columns, which is both what makes the lookup indexed and the only way to
// offer entities the parser derived rather than ones the schema has a column
// for. Selecting one filters Events to it and pushes a chip.
func (ui *UI) showPivotMenu(event store.Event) {
	observables, err := ui.store.GetObservablesByEvent(ui.ctx, event.ID)
	if err != nil {
		ui.logger.Warn("pivot: could not read observables for %s: %v", event.ID, err)
	}
	targets := pivotTargets(observables)

	list := tview.NewList().ShowSecondaryText(true)
	list.SetBackgroundColor(ui.theme.SurfaceRaised)
	list.SetMainTextColor(ui.theme.TextPrimary)
	list.SetSecondaryTextColor(ui.theme.TextMuted)
	list.SetSelectedBackgroundColor(ui.theme.SelectionBg)

	if len(targets) == 0 {
		// An empty menu that still opens is a dead end. Say why there is
		// nothing to pivot on, since the usual cause is that the record
		// carried no observables rather than that the key failed.
		list.AddItem("Nothing to pivot on",
			"This event carries no indicators. Enrichment may still be pending.",
			0, func() { ui.closeModal() })
	}

	for _, target := range targets {
		t := target
		list.AddItem(t.Label(), fmt.Sprintf("Find every event and finding carrying this %s", strings.ToLower(t.Kind)),
			0, func() {
				ui.closeModal()
				ui.pivotTo(t)
			})
	}
	list.AddItem("Cancel", "Close without pivoting", 'q', func() { ui.closeModal() })

	list.SetBorder(true).
		SetTitle(" PIVOT ").
		SetTitleColor(ui.theme.Header).
		SetBorderColor(ui.theme.FocusBorder)

	height := len(targets) + 4
	if height > 16 {
		height = 16
	}
	centered := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(list, height, 1, true).
			AddItem(nil, 0, 1, false), 60, 1, true).
		AddItem(nil, 0, 1, false)

	ui.rootModal(centered)
	ui.app.SetFocus(list)
}

// closeModal returns to the main layout.
func (ui *UI) closeModal() {
	// The whole root, not just the layout.
	//
	// SetRoot(ui.layout) drops the status bar, which lives in the flex above it
	// — so cancelling or choosing from the pivot menu left the application
	// without a status bar for the rest of the session.
	ui.restoreMainLayout()
}

// pivotTo shows every event carrying an observable, and says how many findings
// carry it too.
//
// One indexed lookup on (type_id, value). The count of findings is the answer
// to the question actually being asked — "have I seen this before?" — so it is
// shown even though the list holds events.
func (ui *UI) pivotTo(target pivotTarget) {
	// The screen change first, then the pivot.
	//
	// beginScreen clears what the outgoing screen left behind, and a pivot is
	// one of those things — assigned before the call it was wiped a line later,
	// and the events list loaded unfiltered.
	ui.beginScreen(destEvents)
	ui.pivot = &target

	ui.spawnLoad(func() {
		events, err := ui.store.FindEventsByObservable(ui.ctx, target.TypeID, target.Value, pivotLimit)
		if err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Pivot failed: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}
		findings, ferr := ui.store.CountFindingsByObservable(ui.ctx, target.TypeID, target.Value)
		if ferr != nil {
			ui.logger.Warn("pivot: could not count findings for %s: %v", target.Value, ferr)
		}

		ui.queueUpdate(func() {
			ui.events = events
			ui.restoreEventsView()
			ui.updateEventsList()
			ui.rememberPivot(target.Value)
			ui.setStatusDirect("[%s]%s %s · %d events · %d findings[-:-:-]",
				ui.theme.TagAccent, target.Kind, target.Value, len(events), findings)
		})
	})
}

// clearPivot drops the pivot and returns to the unfiltered event list.
func (ui *UI) clearPivot() {
	if ui.pivot == nil {
		return
	}
	ui.pivot = nil
	ui.enterScreen(destEvents)
}

// rememberPivot records a pivot for the Home screen's recent list.
func (ui *UI) rememberPivot(value string) {
	for _, p := range ui.recentPivots {
		if p == value {
			return
		}
	}
	ui.recentPivots = append([]string{value}, ui.recentPivots...)
	if len(ui.recentPivots) > 8 {
		ui.recentPivots = ui.recentPivots[:8]
	}
	ui.saveUISettings()
}
