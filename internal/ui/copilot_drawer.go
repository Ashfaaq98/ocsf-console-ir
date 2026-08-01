package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// toggleCopilotDrawer opens or closes the on-demand Copilot drawer.
// §6: Change the permanent right column into an on-demand drawer (] open, [ close).
func (ui *UI) toggleCopilotDrawer() {
	if ui.copilotOpen {
		// Close: restore the main panel to its previous state
		ui.copilotOpen = false
		if ui.mainPanel.GetItemCount() > 1 {
			ui.mainPanel.RemoveItem(ui.copilotPanel)
		}
		ui.copilotPanel = nil
		ui.setStatusDirect("[%s]Copilot drawer closed[-:-:-]", ui.theme.TagMuted)
		return
	}

	// Open: build and attach the drawer
	ui.copilotOpen = true

	drawer := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	drawer.SetBorder(true).
		SetTitle(" COPILOT ([ close) ").
		SetTitleColor(ui.theme.Header).
		SetBorderColor(ui.theme.FocusBorder).
		SetBackgroundColor(ui.theme.Surface)

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("[%s:b]COPILOT ASSISTANT[-:-:-]\n", ui.theme.TagAccent))
	sb.WriteString(fmt.Sprintf("[%s]Local AI · Mode: Contextual Evidence[-:-:-]\n\n", ui.theme.TagMuted))
	sb.WriteString(fmt.Sprintf("[%s:b]Contextual Prompts:[-:-:-]\n\n", ui.theme.TagAccent))
	sb.WriteString(fmt.Sprintf("  [%s]s[-:-:-]  [%s]Summarise selected evidence[-:-:-]\n", ui.theme.TagAccent, ui.theme.TagTextPrimary))
	sb.WriteString(fmt.Sprintf("  [%s]g[-:-:-]  [%s]What is the timeline gap?[-:-:-]\n", ui.theme.TagAccent, ui.theme.TagTextPrimary))
	sb.WriteString(fmt.Sprintf("  [%s]h[-:-:-]  [%s]Draft handoff note[-:-:-]\n", ui.theme.TagAccent, ui.theme.TagTextPrimary))
	sb.WriteString(fmt.Sprintf("  [%s]e[-:-:-]  [%s]Explain this indicator[-:-:-]\n\n", ui.theme.TagAccent, ui.theme.TagTextPrimary))
	sb.WriteString(fmt.Sprintf("[%s]Scope: case-only · Provider: local[-:-:-]\n", ui.theme.TagMuted))

	drawer.SetText(sb.String())

	// Esc from drawer closes it
	drawer.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape || ev.Rune() == '[' {
			ui.toggleCopilotDrawer()
			return nil
		}
		return ev
	})

	ui.copilotPanel = drawer
	ui.mainPanel.AddItem(drawer, 40, 0, true)
	ui.app.SetFocus(drawer)
	ui.setStatusDirect("[%s]Copilot drawer opened · [ or Esc to close[-:-:-]", ui.theme.TagAccent)
}
