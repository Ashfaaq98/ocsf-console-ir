package ui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// CommandItem represents an executable command palette action.
type CommandItem struct {
	Name        string
	Shortcut    string
	Description string
	Action      func()
}

// showCommandPalette opens a fuzzy modal command palette.
func (ui *UI) showCommandPalette() {
	// Destinations come from the table in nav.go rather than being listed
	// again here. They were listed again here, and the copies drifted: the
	// palette offered "go triage" for a key the rail labelled ALL EVENTS.
	commands := ui.destinationCommands()
	commands = append(commands,
		CommandItem{Name: "new case", Shortcut: "c", Description: "Create a new investigation case", Action: func() { ui.showCreateCaseModal() }},
		CommandItem{Name: "change theme", Shortcut: "t", Description: "Cycle the colour theme", Action: func() { ui.cycleTheme() }},
		CommandItem{Name: "show help", Shortcut: "?", Description: "Display keyboard shortcuts help", Action: func() { ui.showHelpModal() }},
	)

	input := tview.NewInputField().
		SetLabel(" : ").
		SetFieldWidth(40).
		SetFieldBackgroundColor(ui.theme.SurfaceRaised).
		SetFieldTextColor(ui.theme.TextPrimary)

	list := tview.NewList().
		ShowSecondaryText(true)
	list.SetBackgroundColor(ui.theme.SurfaceRaised)

	populate := func(filter string) {
		list.Clear()
		filter = strings.ToLower(filter)
		for _, cmd := range commands {
			if filter == "" || strings.Contains(strings.ToLower(cmd.Name), filter) || strings.Contains(strings.ToLower(cmd.Description), filter) {
				c := cmd
				list.AddItem(c.Name, c.Description, rune(0), func() {
					ui.app.SetRoot(ui.layout, true)
					c.Action()
				})
			}
		}
	}

	populate("")

	input.SetChangedFunc(func(text string) {
		populate(text)
	})

	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			ui.app.SetRoot(ui.layout, true)
		} else if key == tcell.KeyEnter {
			if list.GetItemCount() > 0 {
				idx := list.GetCurrentItem()
				main, _ := list.GetItemText(idx)
				for _, cmd := range commands {
					if cmd.Name == main {
						ui.app.SetRoot(ui.layout, true)
						cmd.Action()
						break
					}
				}
			}
		}
	})

	modal := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(input, 1, 0, true).
		AddItem(list, 10, 0, false)
	modal.SetBorder(true).
		SetTitle(" COMMAND PALETTE ").
		SetTitleColor(ui.theme.Header).
		SetBorderColor(ui.theme.FocusBorder).
		SetBackgroundColor(ui.theme.SurfaceRaised)

	centered := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(modal, 13, 1, true).
			AddItem(nil, 0, 1, false), 60, 1, true).
		AddItem(nil, 0, 1, false)

	ui.rootModal(centered)
	ui.app.SetFocus(input)
}
