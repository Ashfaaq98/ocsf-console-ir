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
// commandListRows is how many commands the palette shows at once.
const commandListRows = 10

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
					ui.closeModal()
					c.Action()
				})
			}
		}
	}

	populate("")

	input.SetChangedFunc(func(text string) {
		populate(text)
	})

	// Closed through closeModal, never with SetRoot.
	//
	// SetRoot(ui.layout) looks like it puts the screen back and does three
	// things wrong: it leaves ui.activeModal set, so the application still
	// believes a modal is open and isDialogActive suppresses every global key —
	// the palette closed and nothing worked afterwards, on any screen, for the
	// rest of the session. It also drops the status bar, which lives in the
	// flex above the layout, and it never gives focus back.
	input.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEscape:
			ui.closeModal()
		case tcell.KeyEnter:
			if list.GetItemCount() == 0 {
				return
			}
			name, _ := list.GetItemText(list.GetCurrentItem())
			for _, cmd := range commands {
				if cmd.Name == name {
					ui.closeModal()
					cmd.Action()
					return
				}
			}
		}
	})

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(input, 1, 0, true).
		AddItem(list, commandListRows, 0, false)

	ui.overlayModal(modalPanel(body, "COMMAND PALETTE", ui.theme),
		60, commandListRows+5)
	ui.app.SetFocus(input)
}
