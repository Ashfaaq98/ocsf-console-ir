package ui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// renderPrimitive draws p onto a simulation screen and returns what a terminal
// would actually show, one string per row with trailing blanks trimmed.
//
// Every other test in this file asserts on the strings handed to tview. This
// one asserts on the characters that reach the screen, which is where colour
// markup, escaping and width bookkeeping can still lose text that looked
// correct on the way in.
func renderPrimitive(t *testing.T, p tview.Primitive, width, height int) []string {
	t.Helper()

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("simulation screen: %v", err)
	}
	defer screen.Fini()
	screen.SetSize(width, height)

	p.SetRect(0, 0, width, height)
	p.Draw(screen)
	screen.Show()

	cells, w, h := screen.GetContents()
	lines := make([]string, 0, h)
	for y := 0; y < h; y++ {
		var row strings.Builder
		for x := 0; x < w; x++ {
			runes := cells[y*w+x].Runes
			if len(runes) == 0 {
				row.WriteRune(' ')
				continue
			}
			row.WriteRune(runes[0])
		}
		lines = append(lines, strings.TrimRight(row.String(), " "))
	}
	return lines
}

// frameBuffer is a simulation screen that survives across frames, so tests can
// assert on what a *sequence* of repaints leaves behind rather than on a single
// render into a blank buffer.
type frameBuffer struct {
	screen        tcell.SimulationScreen
	width, height int
}

func newFrameBuffer(t *testing.T, width, height int) *frameBuffer {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("simulation screen: %v", err)
	}
	t.Cleanup(screen.Fini)
	screen.SetSize(width, height)
	return &frameBuffer{screen: screen, width: width, height: height}
}

// paint draws one frame through the same preamble the application uses.
func (f *frameBuffer) paint(v *welcomeView) {
	v.beforeDraw(f.screen)
	v.root.SetRect(0, 0, f.width, f.height)
	v.root.Draw(f.screen)
	f.screen.Show()
}

func (f *frameBuffer) lines() []string {
	cells, w, h := f.screen.GetContents()
	out := make([]string, 0, h)
	for y := 0; y < h; y++ {
		var row strings.Builder
		for x := 0; x < w; x++ {
			runes := cells[y*w+x].Runes
			if len(runes) == 0 {
				row.WriteRune(' ')
				continue
			}
			row.WriteRune(runes[0])
		}
		out = append(out, strings.TrimRight(row.String(), " "))
	}
	return out
}

// Moving between states must replace the card, not draw a second one over it.
//
// The card's height changes with its state, and tview does not clear the screen
// between frames, so without an explicit clear the rows the previous card
// occupied keep its border and the screen ends up with two overlapping cards
// and a duplicated title.
func TestWelcomeLeavesNoStaleRowsBetweenStates(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{
		DBPath:  "/read-only/console-ir.db",
		Perform: func(WelcomeResult, func(string)) error { return errPermission },
	})
	fb := newFrameBuffer(t, 100, 30)

	// Menu, then the prompt, then the error card: the three heights this screen
	// has, in the order a failing import walks through them.
	fb.paint(v)
	press(v, '3')
	fb.paint(v)

	lines := fb.lines()
	if line, ok := findLine(lines, welcomeMessage); ok {
		t.Errorf("the menu card survived the switch to the prompt: %q\n%s",
			line, strings.Join(lines, "\n"))
	}

	v.input.SetText("/no/such/file.jsonl")
	v.promptDone(tcell.KeyEnter)
	fb.paint(v)

	lines = fb.lines()
	if line, ok := findLine(lines, "Path to a JSON"); ok {
		t.Errorf("the prompt survived the switch to the error card: %q\n%s",
			line, strings.Join(lines, "\n"))
	}

	// Exactly one card, so exactly one top border and one bottom border.
	var tops, bottoms, titles int
	for _, l := range lines {
		switch {
		case strings.Contains(l, "┌") || strings.Contains(l, "╔"):
			tops++
		case strings.Contains(l, "└") || strings.Contains(l, "╚"):
			bottoms++
		}
		if strings.Contains(l, welcomeTitleText) {
			titles++
		}
	}
	if tops != 1 || bottoms != 1 {
		t.Errorf("found %d card tops and %d bottoms, want 1 of each\n%s",
			tops, bottoms, strings.Join(lines, "\n"))
	}
	if titles != 1 {
		t.Errorf("the title is on screen %d times, want once\n%s", titles, strings.Join(lines, "\n"))
	}
}

// Resizing must repaint cleanly too: a wide card shrinking to a compact one
// leaves the widest rows behind if the screen is never cleared.
func TestWelcomeLeavesNoStaleRowsAfterResize(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})

	wide := newFrameBuffer(t, 140, 40)
	wide.paint(v)

	// Same view, smaller terminal.
	narrow := newFrameBuffer(t, 100, 24)
	narrow.paint(v)

	for i, l := range narrow.lines() {
		if len([]rune(l)) > 100 {
			t.Errorf("row %d is %d columns wide after shrinking", i, len([]rune(l)))
		}
	}
}

// findLine returns the first rendered row containing substr.
func findLine(lines []string, substr string) (string, bool) {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return l, true
		}
	}
	return "", false
}

// The action list is the whole point of the screen: it is how a first-time user
// learns which key does what. Colour markup must not bleed into it.
//
// This is a regression test for exactly that. tview reads "[q]" in dynamic
// colour text as a style tag, and its escape hatch keeps state across lines in
// a TextView, so an escaped action list rendered with one character of a
// neighbouring "[-:-:-]" leaking onto every subsequent row.
func TestWelcomeRendersTheActionListCleanly(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.relayout(100, 30)

	lines := renderPrimitive(t, v.root, 100, 30)
	joined := strings.Join(lines, "\n")

	for _, o := range welcomeOptions {
		want := string([]rune{'[', o.key, ']'}) + "  " + o.label
		if _, ok := findLine(lines, want); !ok {
			t.Errorf("the screen does not show %q\nrendered:\n%s", want, joined)
		}
	}

	// No fragment of a colour tag may reach the screen anywhere.
	for _, leak := range []string{"[-:-:-]", ":-]", "-:-", "[-:"} {
		if line, ok := findLine(lines, leak); ok {
			t.Errorf("colour markup %q leaked into the render: %q\nrendered:\n%s", leak, line, joined)
		}
	}
}

// Same guarantee for the error card, whose keys are the only way out of it.
func TestWelcomeRendersTheErrorCardCleanly(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{
		DBPath: "/read-only/console-ir.db",
		Perform: func(WelcomeResult, func(string)) error {
			return errPermission
		},
	})

	press(v, '1')
	v.relayout(100, 30)

	lines := renderPrimitive(t, v.root, 100, 30)
	joined := strings.Join(lines, "\n")

	for _, want := range []string{"[r]  Retry", "[q]  Quit", "permission denied", "/read-only/console-ir.db"} {
		if _, ok := findLine(lines, want); !ok {
			t.Errorf("the error card does not show %q\nrendered:\n%s", want, joined)
		}
	}
	for _, leak := range []string{"[-:-:-]", ":-]", "-:-"} {
		if line, ok := findLine(lines, leak); ok {
			t.Errorf("colour markup %q leaked: %q\nrendered:\n%s", leak, line, joined)
		}
	}
}

// The card must sit on the canvas, not overflow it, at every tier.
func TestWelcomeRendersWithinItsTerminal(t *testing.T) {
	for _, size := range [][2]int{{140, 40}, {100, 30}, {100, 24}, {80, 24}, {70, 20}} {
		v := newTestWelcome(t, WelcomeOptions{})
		v.relayout(size[0], size[1])

		lines := renderPrimitive(t, v.root, size[0], size[1])

		for i, l := range lines {
			if len([]rune(l)) > size[0] {
				t.Errorf("%dx%d: row %d is %d columns wide", size[0], size[1], i, len([]rune(l)))
			}
		}

		// The actions and the action bar survive every size.
		for _, o := range welcomeOptions {
			if _, ok := findLine(lines, o.label); !ok {
				t.Errorf("%dx%d dropped the action %q from the render:\n%s",
					size[0], size[1], o.label, strings.Join(lines, "\n"))
			}
		}
		if _, ok := findLine(lines, "q Quit"); !ok {
			t.Errorf("%dx%d dropped the action bar:\n%s", size[0], size[1], strings.Join(lines, "\n"))
		}
	}
}
