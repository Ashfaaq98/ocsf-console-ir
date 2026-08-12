package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// setBoxColors is a helper to set border and title colors on tview primitives
func (cm *CaseManagement) setBoxColors(p tview.Primitive, borderColor, titleColor tcell.Color) {
	if p == nil {
		return
	}
	type boxColors interface {
		SetBorderColor(color tcell.Color) *tview.Box
		SetTitleColor(color tcell.Color) *tview.Box
	}
	if b, ok := p.(boxColors); ok {
		b.SetBorderColor(borderColor)
		b.SetTitleColor(titleColor)
	}
}

// setBoxBg is a helper to set background color on tview primitives
func (cm *CaseManagement) setBoxBg(p tview.Primitive, bg tcell.Color) {
	if p == nil {
		return
	}
	type bgable interface {
		SetBackgroundColor(color tcell.Color) *tview.Box
	}
	if b, ok := p.(bgable); ok {
		b.SetBackgroundColor(bg)
	}
}

// setTextColor is a helper to set text color if supported
func (cm *CaseManagement) setTextColor(p tview.Primitive, fg tcell.Color) {
	if p == nil {
		return
	}
	type textColorable interface {
		SetTextColor(color tcell.Color)
	}
	type textColorableRet interface {
		SetTextColor(color tcell.Color) *tview.TextView
	}
	if c, ok := p.(textColorable); ok {
		c.SetTextColor(fg)
	} else if c, ok := p.(textColorableRet); ok {
		c.SetTextColor(fg)
	}
}

// setTableCursor turns a table's cursor on only when there is something to land
// on.
//
// tview walks the table for a selectable cell when an arrow key arrives, and if
// there is none it can search forever. A draw leaves the selected row one past
// the last row, and the backward walk the arrow then does is told to stop when
// it reaches that row — which it never can, because the walk wraps inside the
// rows that exist. It spins on the UI goroutine, and the application is gone.
//
// Every empty state here is a table of unselectable cells inside a selectable
// table, which is exactly that shape. Turning the cursor off while a pane has
// nothing in it is also what the pane means: there is nothing to move between.
func setTableCursor(table *tview.Table, hasRows bool) {
	if table == nil {
		return
	}
	table.SetSelectable(hasRows, false)
	if !hasRows {
		// So the cursor starts from the top when rows arrive, rather than from
		// wherever the last set left it.
		table.Select(0, 0)
	}
}
