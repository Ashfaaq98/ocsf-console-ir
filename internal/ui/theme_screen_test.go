package ui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
)

// The theme's background is the screen's default.
//
// tcell clears with the screen's default style — at Init, and on every screen
// switch — and that style starts as the terminal's own colours. So the
// application showed the terminal's background until a panel painted over it,
// and kept it anywhere no panel reached. On a light terminal profile that reads
// as the application starting light whichever theme is set.
func TestTheThemeIsTheScreensDefault(t *testing.T) {
	ui, _ := newTestUI(t)
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	defer screen.Fini()
	screen.SetSize(80, 24)

	// What tcell paints before anything else does: the terminal's own colours.
	screen.Clear()
	screen.Show()
	if cells, _, _ := screen.GetContents(); len(cells) > 0 {
		if _, bg, _ := cells[0].Style.Decompose(); bg != tcell.ColorDefault {
			t.Fatalf("the simulation started with %v, not the terminal default", bg)
		}
	}

	ui.adoptScreen(screen)
	screen.Clear()
	screen.Show()

	cells, w, h := screen.GetContents()
	for i := 0; i < w*h; i++ {
		_, bg, _ := cells[i].Style.Decompose()
		if bg != ui.theme.Canvas {
			t.Fatalf("cell %d cleared to %v, want the theme's canvas %v", i, bg, ui.theme.Canvas)
		}
	}
}

// The colour depth comes from the terminal, not from a guess at the
// environment.
//
// detectTrueColor reads COLORTERM and TERM before a screen is open, and
// terminals that set neither — kitty, alacritty and screen among them — were
// told they had no colour, so the chosen theme was silently replaced by the
// sixteen-colour fallback.
func TestAColourTerminalGetsTheChosenTheme(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.themeName = "gruvbox"
	ui.hasTrueColor = false
	ui.theme = themeBasic()
	ui.screenAdopted = false

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	defer screen.Fini()
	if screen.Colors() < 256 {
		t.Skipf("the simulation reports %d colours", screen.Colors())
	}

	ui.adoptScreen(screen)

	if ui.theme.Canvas != themeGruvbox().Canvas {
		t.Errorf("a 256-colour terminal got %v, want gruvbox's %v",
			ui.theme.Canvas, themeGruvbox().Canvas)
	}
}

// A terminal that genuinely cannot manage 256 colours keeps the fallback.
func TestAMonochromeTerminalKeepsTheFallback(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.hasTrueColor = false
	ui.theme = themeBasic()
	ui.screenAdopted = false

	// No screen at all is the same case: nothing to ask.
	ui.adoptScreen(nil)

	if ui.theme.Canvas != themeBasic().Canvas {
		t.Errorf("the fallback was replaced without a terminal to justify it")
	}
}
