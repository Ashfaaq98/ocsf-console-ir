package ui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// atFrame puts the view at one frame of the reveal. Every test here drives the
// counter directly: the frame is a pure function of it, so none of them sleeps.
func atFrame(v *welcomeView, frame int) {
	v.revealing = true
	v.frame = frame
	v.render()
}

// The page is the same shape in every frame of the reveal.
//
// This is the one that matters. A reveal that added rows as it went would move
// the page under the analyst and read as the screen failing to settle, so parts
// that have not arrived are drawn as blanks of their eventual width rather than
// left out.
func TestRevealNeverChangesTheLayout(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{
		Version: "0.2.0", DBPath: "/tmp/console-ir.db", DemoSummary: "727 events · 4 cases",
	})
	v.width, v.height = 140, 40

	v.revealing = false
	v.render()
	wantRows := len(v.pageRows())
	wantColumn := v.rightColumnAt()
	wantBrand := widestCell(v.leftColumn())

	for frame := 0; frame <= welcomeFrameCount(); frame++ {
		atFrame(v, frame)

		// The three numbers the whole layout is derived from. A masked cell
		// keeps its width and loses only its text, so none of them may move
		// while the page arrives — trailing blanks are not drawn, so an
		// unarrived row is simply a shorter string in the same place.
		if got := len(v.pageRows()); got != wantRows {
			t.Errorf("frame %d has %d rows, want %d", frame, got, wantRows)
		}
		if got := v.rightColumnAt(); got != wantColumn {
			t.Errorf("frame %d starts the right column at %d, want %d", frame, got, wantColumn)
		}
		if got := widestCell(v.leftColumn()); got != wantBrand {
			t.Errorf("frame %d makes the brand column %d wide, want %d", frame, got, wantBrand)
		}
	}
}

// And the same guarantee against the screen: the divider is drawn in the same
// column in every frame, so the two columns do not shift as the page arrives.
func TestRevealKeepsTheDividerStill(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{
		Version: "0.2.0", DBPath: "/tmp/console-ir.db", DemoSummary: "727 events · 4 cases",
	})
	v.width, v.height = 140, 40

	want := -1
	for frame := 0; frame <= welcomeFrameCount(); frame++ {
		atFrame(v, frame)

		lines := renderPrimitive(t, v.root, 140, 40)

		// Every row that has a divider, not just the first: a masked cell that
		// lost its width would only pull the rows below the mark out of line.
		found := 0
		for i, row := range lines {
			at := screenColumnOf(row, welcomeDividerRune())
			if at < 0 {
				continue
			}
			found++
			if want == -1 {
				want = at
				continue
			}
			if at != want {
				t.Fatalf("frame %d draws row %d's divider at column %d, want %d:\n%s",
					frame, i, at, want, strings.Join(lines, "\n"))
			}
		}
		if found == 0 {
			t.Fatalf("frame %d drew no divider:\n%s", frame, strings.Join(lines, "\n"))
		}
	}
}

// The last frame is the settled page, exactly. A reveal that ended somewhere
// other than where the screen lives would leave it subtly wrong forever.
func TestRevealEndsOnTheSettledPage(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{Version: "0.2.0", DBPath: "/tmp/console-ir.db"})
	v.width, v.height = 140, 40

	v.revealing = false
	v.render()
	want := strings.Join(v.pageRows(), "\n")

	atFrame(v, welcomeFrameCount())
	if got := strings.Join(v.pageRows(), "\n"); got != want {
		t.Errorf("the last frame is not the settled page:\n got %q\nwant %q", got, want)
	}
}

// The mark arrives left to right, and it is whole before anything below it.
func TestRevealSweepsTheWordmark(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.width, v.height = 140, 40
	full := len([]rune(wordmarkLines()[0]))

	last := -1
	for frame := 0; frame < welcomeSweepFrames; frame++ {
		atFrame(v, frame)

		// Runes, not bytes: the mark is box-drawing characters at three bytes
		// each, so len() on the string is not a count of characters.
		drawn := len([]rune(strings.TrimRight(stripTags(v.wordmarkCells()[0].text), " ")))
		if drawn <= last {
			t.Errorf("frame %d drew no more of the mark than frame %d did", frame, frame-1)
		}
		if drawn > full {
			t.Fatalf("frame %d drew %d characters, more than the mark has", frame, drawn)
		}
		last = drawn
	}

	atFrame(v, welcomeSweepFrames)
	if got := stripTags(v.wordmarkCells()[0].text); got != wordmarkLines()[0] {
		t.Errorf("the mark is not whole when the sweep ends: %q", got)
	}
}

// Nothing below the mark appears until the mark is whole, and the actions
// arrive one frame apart rather than all together.
func TestRevealOrdersThePage(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{Version: "0.2.0", DemoSummary: "727 events"})
	v.width, v.height = 140, 40

	atFrame(v, welcomeBrandFrame-1)
	if text := pageText(v); strings.Contains(text, welcomeDescription) {
		t.Error("the brand column arrived before the mark was whole")
	}

	atFrame(v, welcomeBrandFrame)
	if text := pageText(v); !strings.Contains(text, welcomeDescription) {
		t.Error("the brand column did not arrive with the finished mark")
	}

	for i, o := range welcomeOptions {
		atFrame(v, welcomeActionsFrame+i-1)
		if strings.Contains(pageText(v), o.label) {
			t.Errorf("the action %q arrived a frame early", o.label)
		}
		atFrame(v, welcomeActionsFrame+i)
		if !strings.Contains(pageText(v), o.label) {
			t.Errorf("the action %q had not arrived on its own frame", o.label)
		}
	}
}

// A key finishes the reveal and is still handled. Nobody waits on decoration.
func TestAKeyFinishesTheReveal(t *testing.T) {
	var got WelcomeResult
	v := newTestWelcome(t, WelcomeOptions{
		Perform: func(res WelcomeResult, _ func(string)) error {
			got = res
			return nil
		},
	})
	v.revealing = true
	v.frame = 0
	v.revealDone = make(chan struct{})

	press(v, '2')

	if v.revealing {
		t.Error("the reveal survived a keypress")
	}
	if got.Action != WelcomeDemo {
		t.Errorf("the key was swallowed by the animation: ran %v", got.Action)
	}
}

// Finishing twice must not close the same channel twice, which would panic on
// the first screen an install ever shows.
func TestFinishRevealIsIdempotent(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.revealing = true
	v.revealDone = make(chan struct{})

	v.finishReveal()
	v.finishReveal()
	v.stop()

	if v.frame != welcomeFrameCount() {
		t.Errorf("frame = %d after finishing, want the last frame %d", v.frame, welcomeFrameCount())
	}
}

// A settled screen renders as if the reveal had never existed, so a terminal
// that skips the animation is not a terminal with a half-drawn page.
func TestASettledPageIgnoresTheFrame(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.revealing = false
	v.frame = 0

	if !v.revealed(welcomeFrameCount()) {
		t.Error("a settled page reports part of itself as not yet arrived")
	}
	if v.sweepEdge(27) != -1 {
		t.Error("a settled page still has a sweep edge")
	}
}

// The sweep's leading edge is brighter than the accent it leaves behind, or the
// animation reads as text being typed rather than light crossing a surface.
func TestSweepEdgeIsBrighterThanTheAccent(t *testing.T) {
	for name, build := range themeBuilders {
		t.Run(name, func(t *testing.T) {
			v := newTestWelcome(t, WelcomeOptions{})
			v.theme = build()

			if luminance(v.glowColor()) <= luminance(v.theme.Accent) {
				t.Errorf("the glow %v is no brighter than the accent %v",
					v.glowColor(), v.theme.Accent)
			}
		})
	}
}

func TestGlowLeavesNonRGBColoursAlone(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.theme.Accent = tcell.ColorDefault

	if got := v.glowColor(); got != tcell.ColorDefault {
		t.Errorf("glowColor() = %v, want the colour untouched", got)
	}
}
