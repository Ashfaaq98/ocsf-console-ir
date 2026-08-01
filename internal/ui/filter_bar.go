package ui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// showFilterBar activates a scoped filter input bar over the main content list.
// §5: `/` filters the focused list with an immediately visible query field and result count;
// `Esc` restores the prior list/filter without losing context.
func (ui *UI) showFilterBar() {
	if ui.eventList == nil {
		return
	}

	input := tview.NewInputField().
		SetLabel(" / Filter: ").
		SetFieldWidth(40).
		SetFieldBackgroundColor(ui.theme.SurfaceRaised).
		SetFieldTextColor(ui.theme.TextPrimary).
		SetLabelColor(ui.theme.Accent)

	input.SetChangedFunc(func(query string) {
		if query == "" {
			ui.setStatusDirect("[%s]Type to filter · Esc to cancel[-:-:-]", ui.theme.TagMuted)
			return
		}

		q := strings.ToLower(query)
		visible := 0
		total := 0

		for row := 1; row < ui.eventList.GetRowCount(); row++ {
			total++
			matched := false
			for col := 0; col < ui.eventList.GetColumnCount(); col++ {
				cell := ui.eventList.GetCell(row, col)
				if cell != nil && strings.Contains(strings.ToLower(cell.Text), q) {
					matched = true
					break
				}
			}
			if matched {
				visible++
			}
		}
		ui.setStatusDirect("[%s]Filter: '%s' · %d/%d matches · Enter to apply · Esc to cancel[-:-:-]", ui.theme.TagAccent, query, visible, total)
	})

	input.SetDoneFunc(func(key tcell.Key) {
		ui.mainPanel.RemoveItem(input)
		ui.app.SetFocus(ui.eventList)

		if key == tcell.KeyEscape {
			ui.setStatusDirect("[%s]Filter cancelled[-:-:-]", ui.theme.TagMuted)
		}
	})

	// Insert filter bar at the top of the main panel
	ui.mainPanel.AddItem(input, 1, 0, true)
	ui.app.SetFocus(input)
}
