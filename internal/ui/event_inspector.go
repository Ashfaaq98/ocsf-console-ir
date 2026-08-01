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

// showPivotMenu displays the one-keystroke observable pivot modal.
func (ui *UI) showPivotMenu(event store.Event) {
	list := tview.NewList()
	list.SetBackgroundColor(ui.theme.SurfaceRaised)

	ip := event.SrcIP
	if ip == "" {
		ip = event.DstIP
	}

	if event.Host != "" {
		list.AddItem("Pivot Host: "+event.Host, "Filter events by host", 'h', func() {
			ui.app.SetRoot(ui.layout, true)
		})
	}
	if event.UserName != "" {
		list.AddItem("Pivot User: "+event.UserName, "Filter events by user", 'u', func() {
			ui.app.SetRoot(ui.layout, true)
		})
	}
	if ip != "" {
		list.AddItem("Pivot IP: "+ip, "Filter events by IP address", 'i', func() {
			ui.app.SetRoot(ui.layout, true)
		})
	}
	list.AddItem("Cancel", "Close pivot menu", 'q', func() {
		ui.app.SetRoot(ui.layout, true)
	})

	list.SetBorder(true).
		SetTitle(" OBSERVABLE PIVOT ").
		SetTitleColor(ui.theme.Header).
		SetBorderColor(ui.theme.FocusBorder)

	centered := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(list, 10, 1, true).
			AddItem(nil, 0, 1, false), 50, 1, true).
		AddItem(nil, 0, 1, false)

	ui.app.SetRoot(centered, true)
	ui.app.SetFocus(list)
}
