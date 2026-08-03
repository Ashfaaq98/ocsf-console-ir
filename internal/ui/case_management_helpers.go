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
