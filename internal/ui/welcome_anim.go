package ui

import (
	"os"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
)

// The reveal: a light sweep across the wordmark, then the page arriving behind
// it. It runs once, at startup, and takes about a third of a second.
//
// Three rules make it safe to have at all:
//
//   - A frame is a pure function of a counter. Nothing in the render path reads
//     a clock, so a test sets the frame and asserts on the result; there is no
//     sleeping in any test of this file.
//   - It never delays anybody. Any key finishes it immediately and is then
//     handled normally, so a fast typist is not made to watch it.
//   - It never changes the layout. A part of the page that has not arrived yet
//     is drawn as blanks of its eventual width, so the page is the same shape
//     in the first frame as in the last. An animation that reflowed would read
//     as the screen failing to settle.
//
// If it ever feels wrong on a real terminal, this file is deletable on its own:
// startReveal becomes a no-op and every frame is the last one.

// The schedule, in frames.
const (
	// welcomeFrameInterval is roughly 30fps. Fast enough to read as motion,
	// slow enough that a terminal over ssh keeps up.
	welcomeFrameInterval = 30 * time.Millisecond

	// welcomeSweepFrames is how long the light takes to cross the wordmark.
	welcomeSweepFrames = 7

	// welcomeBrandFrame is when the rest of the brand column arrives, once the
	// mark is whole.
	welcomeBrandFrame = welcomeSweepFrames + 1

	// welcomeActionsFrame is when the first action arrives; the rest follow one
	// frame apart.
	welcomeActionsFrame = welcomeBrandFrame + 1
)

// welcomeFrameCount is the frame at which everything is on screen. Derived from
// the action list rather than written down, so adding an action extends the
// reveal instead of leaving the last one to appear after it had finished.
func welcomeFrameCount() int { return welcomeActionsFrame + len(welcomeOptions) }

// welcomeGlow is how far the sweep's leading edge is lifted toward white. The
// edge has to be brighter than the accent or the sweep reads as text being
// typed rather than as light crossing a surface.
const welcomeGlow = 0.5

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// startReveal begins the animation, if this terminal should have one.
func (v *welcomeView) startReveal() {
	if v.app == nil || !animationWanted() {
		return
	}
	v.frame = 0
	v.revealing = true
	v.revealDone = make(chan struct{})
	go v.runReveal()
}

// runReveal advances the frame until the page is whole.
//
// The guard before each update is what keeps this goroutine from outliving the
// screen: tview's queued updates block until the event loop runs them, and a
// stopped application never will. The window between the guard and the send is
// microseconds wide, and the worst case on the other side of it is one parked
// goroutine in a process that is already leaving this screen.
func (v *welcomeView) runReveal() {
	ticker := time.NewTicker(welcomeFrameInterval)
	defer ticker.Stop()

	for {
		select {
		case <-v.revealDone:
			return
		case <-ticker.C:
			select {
			case <-v.revealDone:
				return
			default:
			}
			v.update(v.advanceFrame)
		}
	}
}

// advanceFrame moves the reveal on by one. It runs on the UI goroutine.
func (v *welcomeView) advanceFrame() {
	if !v.revealing {
		return
	}
	v.frame++
	if v.frame >= welcomeFrameCount() {
		v.finishReveal()
	}
	v.render()
}

// finishReveal puts the page in its settled state at once. Called when the
// reveal runs out and when a key arrives, so pressing anything is the same as
// having waited.
func (v *welcomeView) finishReveal() {
	if !v.revealing {
		return
	}
	v.revealing = false
	v.frame = welcomeFrameCount()
	close(v.revealDone)
}

// animationWanted reports whether this environment should see the reveal.
//
// Off when there is no terminal to draw it on, when the terminal has told us it
// cannot do better than plain text, and when the operator has said not to —
// a recording, a screenshot or a CI log does not want motion in it.
func animationWanted() bool {
	if os.Getenv("CONSOLE_IR_NO_ANIMATION") != "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return false
	}
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// ---------------------------------------------------------------------------
// What each frame shows
// ---------------------------------------------------------------------------

// revealed reports whether the part of the page scheduled for the given frame
// has arrived. A settled page has arrived at everything.
func (v *welcomeView) revealed(frame int) bool {
	return !v.revealing || v.frame >= frame
}

// sweepEdge is the character the light is on, or -1 once the mark is whole.
func (v *welcomeView) sweepEdge(width int) int {
	if !v.revealing || v.frame >= welcomeSweepFrames {
		return -1
	}
	// One past the last lit character, so frame 0 lights the first one and the
	// final sweep frame lights the last.
	return (v.frame+1)*width/welcomeSweepFrames - 1
}

// maskCells blanks the cells that this frame has not reached, keeping each
// one's width so the page does not change shape while it arrives.
func (v *welcomeView) maskCells(cells []welcomeCell, from int) []welcomeCell {
	if v.revealed(from) {
		return cells
	}
	out := make([]welcomeCell, len(cells))
	for i, c := range cells {
		// Blanks, not an empty string. Every cell's text has to occupy exactly
		// the columns its width claims — the row composer pads by the
		// difference between the two — so a masked cell that kept its width and
		// dropped its text would pull everything after it leftwards, and the
		// divider would go ragged while the page arrived.
		out[i] = welcomeCell{text: strings.Repeat(" ", c.width), width: c.width}
	}
	return out
}

// maskActions blanks the actions one at a time, so they arrive in a run rather
// than all at once.
func (v *welcomeView) maskActions(cells []welcomeCell, index int) []welcomeCell {
	return v.maskCells(cells, welcomeActionsFrame+index)
}

// glowColor is the accent lifted toward white, for the sweep's leading edge.
func (v *welcomeView) glowColor() tcell.Color {
	h := v.theme.Accent.Hex()
	if h < 0 {
		return v.theme.Accent
	}
	lift := func(shift uint) int32 {
		c := float64((h >> shift) & 0xff)
		return int32(c + (255-c)*welcomeGlow + 0.5)
	}
	return tcell.NewRGBColor(lift(16), lift(8), lift(0))
}
