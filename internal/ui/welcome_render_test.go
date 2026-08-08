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

// Moving between states must replace the right-hand column, not draw a second
// one over it.
//
// tview does not clear the screen between frames and the column changes height
// with its state, so without the canvas being repainted every frame the rows the
// previous state occupied keep its text and the two read on top of each other.
func TestWelcomeLeavesNoStaleRowsBetweenStates(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{
		DBPath:  "/read-only/console-ir.db",
		Perform: func(WelcomeResult, func(string)) error { return errPermission },
	})
	fb := newFrameBuffer(t, 120, 34)

	// Menu, then the prompt, then the failure: the three shapes this screen has,
	// in the order a failing import walks through them.
	fb.paint(v)
	press(v, '3')
	fb.paint(v)

	lines := fb.lines()
	if line, ok := findLine(lines, welcomeOptions[0].label); ok {
		t.Errorf("the action list survived the switch to the prompt: %q\n%s",
			line, strings.Join(lines, "\n"))
	}

	v.input.SetText("/no/such/file.jsonl")
	v.promptDone(tcell.KeyEnter)
	fb.paint(v)

	lines = fb.lines()
	if line, ok := findLine(lines, "Path to a JSON"); ok {
		t.Errorf("the prompt survived the switch to the failure: %q\n%s",
			line, strings.Join(lines, "\n"))
	}

	// The brand is drawn once, not once per state that has been through here.
	marks := 0
	for _, l := range lines {
		if strings.Contains(l, wordmarkLines()[0]) {
			marks++
		}
	}
	if marks != 1 {
		t.Errorf("the wordmark is on screen %d times, want once\n%s",
			marks, strings.Join(lines, "\n"))
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

// screenColumnOf is the column substr starts at, counting screen cells.
//
// Not strings.Index, which counts bytes: the brand column is drawn in
// box-drawing characters at three bytes each, so a byte offset stopped being a
// column the moment the wordmark arrived.
func screenColumnOf(row, substr string) int {
	at := strings.Index(row, substr)
	if at < 0 {
		return -1
	}
	return len([]rune(row[:at]))
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
		want := keycapFor(o.key) + "  " + o.label
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

	for _, want := range []string{" r   Retry", " q   Quit", "permission denied", "/read-only/console-ir.db"} {
		if _, ok := findLine(lines, want); !ok {
			t.Errorf("the error state does not show %q\nrendered:\n%s", want, joined)
		}
	}
	for _, leak := range []string{"[-:-:-]", ":-]", "-:-"} {
		if line, ok := findLine(lines, leak); ok {
			t.Errorf("colour markup %q leaked: %q\nrendered:\n%s", leak, line, joined)
		}
	}
}

// Every cell on the screen is painted by the theme.
//
// This is a regression test for the screen rendering as horizontal stripes.
// tview.NewFlex sets dontClear on its Box, so the root's SetBackgroundColor was
// a no-op and only the widgets that set a background of their own painted
// anything; every other row showed the terminal's colours straight through. The
// gaps between widgets are the whole canvas, so sampling them is the test.
func TestWelcomePaintsTheWholeCanvas(t *testing.T) {
	for _, size := range [][2]int{{140, 40}, {100, 30}, {80, 24}} {
		v := newTestWelcome(t, WelcomeOptions{})
		fb := newFrameBuffer(t, size[0], size[1])
		fb.paint(v)

		cells, w, h := fb.screen.GetContents()
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				if _, bg, _ := cells[y*w+x].Style.Decompose(); bg == tcell.ColorDefault {
					t.Fatalf("%dx%d: cell %d,%d is the terminal's background, not the theme's",
						size[0], size[1], x, y)
				}
			}
		}
	}
}

// The page is two columns wherever they fit: the brand on the left, the choices
// on the right, sharing rows rather than stacking.
//
// The assertion is that a single rendered row carries both, because that is the
// only thing that distinguishes two columns from one.
func TestWelcomePageIsTwoColumns(t *testing.T) {
	for _, size := range [][2]int{{140, 40}, {100, 30}, {80, 24}} {
		v := newTestWelcome(t, WelcomeOptions{})
		v.relayout(size[0], size[1])

		lines := renderPrimitive(t, v.root, size[0], size[1])
		row, ok := findLine(lines, wordmarkLines()[0])
		if !ok {
			t.Fatalf("%dx%d: the wordmark is not on screen:\n%s", size[0], size[1], strings.Join(lines, "\n"))
		}
		if !strings.Contains(row, welcomeOptions[0].label) {
			t.Errorf("%dx%d: the page is stacked, not two columns — the wordmark row is %q",
				size[0], size[1], row)
		}
	}
}

// The right column has to line up. Padding computed from a colour-tagged string
// counts markup that is never drawn, and the actions come out on a ragged edge.
func TestWelcomeColumnsAlign(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.relayout(140, 40)
	lines := renderPrimitive(t, v.root, 140, 40)

	want := -1
	for _, o := range welcomeOptions {
		key := keycapFor(o.key)
		row, ok := findLine(lines, key+"  "+o.label)
		if !ok {
			t.Fatalf("the action %q is not on screen:\n%s", key, strings.Join(lines, "\n"))
		}
		at := screenColumnOf(row, key)
		if want == -1 {
			want = at
			continue
		}
		if at != want {
			t.Errorf("%q starts at column %d, but the first action starts at %d:\n%s",
				key, at, want, strings.Join(lines, "\n"))
		}
	}
}

// A terminal too narrow for two columns gets one, with every action still on
// it. Truncating the action list would remove the only way off the screen.
func TestWelcomeFallsBackToOneColumnWhenNarrow(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.relayout(70, 30)

	if v.splitFits(v.leftColumn(), v.rightColumn()) {
		t.Fatalf("a %d-column terminal claims to fit two columns", v.width)
	}

	lines := renderPrimitive(t, v.root, 70, 30)
	for _, o := range welcomeOptions {
		if _, ok := findLine(lines, keycapFor(o.key)+"  "+o.label); !ok {
			t.Errorf("the one-column fallback dropped %q:\n%s", o.label, strings.Join(lines, "\n"))
		}
	}
}

// The version belongs on the first screen: it is often the only one a bug
// report can be written from, and `console-ir version` needs a database this
// install does not have yet.
func TestWelcomeShowsTheVersion(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{Version: "0.2.0"})
	v.relayout(140, 40)

	lines := renderPrimitive(t, v.root, 140, 40)
	// In buildinfo's spelling, so the answer to "what am I running" is the same
	// word here as it is in the main header and in `console-ir version`.
	row, ok := findLine(lines, "v0.2.0")
	if !ok {
		t.Fatalf("the version is not on screen:\n%s", strings.Join(lines, "\n"))
	}
	// Beside the schema it speaks: the two facts a bug report needs.
	if !strings.Contains(row, "OCSF") {
		t.Errorf("the version is not beside the schema version: %q", row)
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

		// The actions and the navigation bar survive every size.
		for _, o := range welcomeOptions {
			if _, ok := findLine(lines, o.label); !ok {
				t.Errorf("%dx%d dropped the action %q from the render:\n%s",
					size[0], size[1], o.label, strings.Join(lines, "\n"))
			}
		}
		if _, ok := findLine(lines, "q Quit"); !ok {
			t.Errorf("%dx%d dropped the navigation bar:\n%s", size[0], size[1], strings.Join(lines, "\n"))
		}
	}
}
