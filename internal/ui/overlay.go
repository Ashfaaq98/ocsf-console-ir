package ui

import (
	"github.com/rivo/tview"
)

// Modals that leave the screen behind them visible.
//
// rootModal replaces the application's root, so every dialog in this
// application read as a new page: the screen it interrupted vanished, and with
// it the queue the filter was about to narrow, the finding the form was about
// to escalate, and any sense of where the analyst was. A modal that hides its
// own context is a page with a border drawn round it.
//
// tview.Pages draws every visible page in order, so the layout underneath is
// painted first and the modal lands on top of it. The overlay page is a Flex,
// and a Flex does not clear its background — that is normally a trap, and here
// it is the mechanism: everything the modal does not cover shows through.

// mainRoot is the application's ordinary root: the layout with the status bar
// beneath it.
func (ui *UI) mainRoot() tview.Primitive {
	// Before the layout exists there is nothing to show through — a modal can
	// be raised during start-up, and a nil child in a Flex is a panic rather
	// than an empty background.
	if ui.layout == nil || ui.statusBar == nil {
		return tview.NewBox()
	}
	return tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ui.layout, 0, 1, true).
		AddItem(ui.statusBar, 1, 0, false)
}

// overlayModal centres a primitive over the current screen.
//
// The size is given rather than measured: tview reports a primitive's rect a
// frame late, so a modal that sized itself from its content would open at zero
// and correct itself on the next keypress.
func (ui *UI) overlayModal(p tview.Primitive, width, height int) {
	pages := tview.NewPages().
		AddPage("screen", ui.mainRoot(), true, true).
		AddPage("modal", centredModal(p, width, height), true, true)
	ui.rootModal(pages)
	ui.app.SetFocus(p)
}

// modalPanel frames a modal's body: a border, a title, and a background of its
// own so the screen behind does not show through the panel itself.
//
// A Frame rather than a bordered Flex. A Flex will not clear its background —
// SetBackgroundColor on one is a permanent no-op — so a Flex panel over a live
// screen is transparent between its children, and the rows underneath read
// straight through the gaps.
func modalPanel(body tview.Primitive, title string, theme Theme) *tview.Frame {
	// One row of padding above and below the body, one column either side: a
	// panel whose content starts against its own border reads as cramped.
	frame := tview.NewFrame(body).SetBorders(1, 1, 0, 0, 1, 1)
	frame.SetBorder(true).
		SetTitle(" " + title + " ").
		SetTitleAlign(tview.AlignLeft).
		SetTitleColor(theme.Accent).
		SetBorderColor(theme.FocusBorder).
		SetBackgroundColor(theme.SurfaceRaised)
	return frame
}

// overlayPrimitive puts a self-sizing primitive over the current screen.
//
// For tview.Modal, which measures the screen and centres itself: it draws only
// its own box, so the page beneath shows around it.
func (ui *UI) overlayPrimitive(p tview.Primitive) {
	pages := tview.NewPages().
		AddPage("screen", ui.mainRoot(), true, true).
		AddPage("modal", p, true, true)
	ui.rootModal(pages)
	ui.app.SetFocus(p)
}

// overlayForm centres a form at the height its own fields need.
//
// Measured rather than guessed: a form rooted on its own filled the terminal,
// and a form given a fixed height would clip the moment a field was added to
// it.
func (ui *UI) overlayForm(form *tview.Form, width int) {
	ui.overlayModal(form, width, formHeight(form))
}

// formHeight is the rows a form needs: each field and its padding, a row for
// the buttons, the border, and the two rows tview leaves around them.
//
// The two are measured, not assumed: tview draws the first field one row below
// the top of the inner rect and will not draw the buttons at all unless a row
// remains beneath them — so a form sized to the sum of its fields loses its
// Save and Cancel entirely, which is worse than a form that does not open.
func formHeight(form *tview.Form) int {
	h := 0
	for i := 0; i < form.GetFormItemCount(); i++ {
		field := form.GetFormItem(i).GetFieldHeight()
		if field <= 0 {
			field = tview.DefaultFormFieldHeight
		}
		h += field + 1
	}
	if form.GetButtonCount() > 0 {
		h++
	}
	return h + 4
}
