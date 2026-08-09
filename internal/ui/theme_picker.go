package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The theme picker.
//
// `t` cycled blindly through the six themes in alphabetical order, and two of
// them — light and high-contrast — sit between gruvbox and midnight. So a
// couple of presses while exploring left the application on a palette nobody
// chose, the choice was saved, and every session after that opened on it with
// nothing on screen to say why or how to get back. Five more presses was the
// only way home.
//
// A list you can see, that previews as you move and puts back what you had if
// you change your mind.

// showThemePicker opens the theme list over the current screen.
func (ui *UI) showThemePicker() {
	was := ui.themeName

	list := tview.NewList().ShowSecondaryText(false)
	names := themeNames()

	list.SetSelectedFunc(func(int, string, string, rune) {
		// Keep it: setTheme has already applied and saved it.
		ui.closeModal()
	})

	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			// Put back what they came in with, saved, so cancelling is a real
			// cancel rather than a preview that stuck.
			ui.setTheme(was)
			ui.closeModal()
			return nil
		}
		return ev
	})

	current := 0
	for i, name := range names {
		list.AddItem(themeLabel(name, name == was, ui.theme), "", 0, nil)
		if name == was {
			current = i
		}
	}

	ui.styleThemeList(list)
	ui.overlayModal(modalPanel(list, "Theme", ui.theme), 40, len(names)+4)
	list.SetCurrentItem(current)

	// The preview is wired last, after the items and the starting position:
	// tview fires the changed handler while the list is being filled, and a
	// preview on an item that is not there yet indexes past the end of a list
	// of one.
	list.SetChangedFunc(func(i int, _, _ string, _ rune) {
		if i < 0 || i >= len(names) {
			return
		}
		ui.previewTheme(names[i], list)
	})
	ui.app.SetFocus(list)
}

// previewTheme applies a theme and restyles the picker in it.
//
// The picker is built from the theme it opened in, and nothing in applyTheme
// reaches a widget that is not part of the main layout — so without this the
// list stayed in the old palette while the screen behind it changed, which
// makes the preview hard to read and the modal look broken.
func (ui *UI) previewTheme(name string, list *tview.List) {
	if name == ui.themeName {
		return
	}
	ui.setTheme(name)

	for i, n := range themeNames() {
		list.SetItemText(i, themeLabel(n, n == ui.themeName, ui.theme), "")
	}
	ui.styleThemeList(list)
}

// styleThemeList paints the picker in the theme currently applied.
func (ui *UI) styleThemeList(list *tview.List) {
	t := ui.theme
	list.SetBackgroundColor(t.SurfaceRaised)
	list.SetMainTextColor(t.TextPrimary)
	list.SetSelectedBackgroundColor(t.SelectionBg)
	list.SetSelectedTextColor(t.SelectionFg)
}

// themeLabel names a theme and marks the one in force.
func themeLabel(name string, current bool, t Theme) string {
	if current {
		return fmt.Sprintf("%-16s [%s]in use[-:-:-]", name, t.TagAccent)
	}
	return name
}
