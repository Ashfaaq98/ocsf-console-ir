package ui

import (
	"github.com/gdamore/tcell/v2"
)

// LayoutMode represents responsive layout tiers based on terminal dimensions.
type LayoutMode int

const (
	LayoutCompact  LayoutMode = iota // Width < 80
	LayoutStandard                   // Width 80–139
	LayoutWide                       // Width ≥ 140
)

// GetLayoutMode derives the active LayoutMode and short screen indicator.
func GetLayoutMode(width, height int) (LayoutMode, bool) {
	isShort := height < 24
	switch {
	case width < 80:
		return LayoutCompact, isShort
	case width >= 140:
		return LayoutWide, isShort
	default:
		return LayoutStandard, isShort
	}
}

// updateLayoutMode recalculates current layout mode and returns true if changed.
func (ui *UI) updateLayoutMode(screen tcell.Screen) bool {
	if screen == nil {
		return false
	}
	w, h := screen.Size()
	mode, isShort := GetLayoutMode(w, h)
	changed := mode != ui.currentLayoutMode || isShort != ui.isShortScreen
	ui.currentLayoutMode = mode
	ui.isShortScreen = isShort
	return changed
}
