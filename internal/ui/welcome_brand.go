package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/buildinfo"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The brand column. This is the first thing anyone sees of Console-IR, and the
// only screen that runs before there is a database, so it carries the identity
// on its own.
//
// It replaced a three-row block mark drawn in half-block characters. That mark
// rendered as two orange blobs and read as nothing in particular, and it sat
// above a plain-text name, so the screen spent six rows on two weak identity
// elements instead of one strong one.

// wordmarkUnicode spells CONSOLE-IR in box-drawing characters. Twenty-seven
// columns, which is what sets the left column's minimum width.
var wordmarkUnicode = []string{
	"┌─┐┌─┐┌┐┌┌─┐┌─┐┬  ┌─┐  ┬┬─┐",
	"│  │ ││││└─┐│ ││  ├┤   │├┬┘",
	"└─┘└─┘┘└┘└─┘└─┘┴─┘└─┘  ┴┴└─",
}

// wordmarkASCII is the same name for a terminal that cannot draw the other one.
// A locale that is not UTF-8 turns every box-drawing character into a
// replacement glyph, which looks like a rendering fault on the first screen.
var wordmarkASCII = []string{welcomeTitleText}

// wordmarkLines is the mark this terminal can actually draw.
func wordmarkLines() []string {
	if !supportsUnicode() {
		return wordmarkASCII
	}
	return wordmarkUnicode
}

// supportsUnicode reports whether the terminal's locale is UTF-8. tcell will
// happily draw block characters into a Latin-1 terminal, where they arrive as
// question marks.
func supportsUnicode() bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if val := os.Getenv(key); val != "" {
			v := strings.ToLower(val)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return false
}

// The gradient.
//
// The mark is lit left to right rather than blended between two palette
// colours: a ramp of one hue's brightness reads the same way in every theme,
// including the two accessibility palettes, where a second colour picked to
// look good in gruvbox would land somewhere unintended. It also composes with
// the reveal, which is the same ramp with a moving bright edge.
const (
	// welcomeRampFloor is how dark the unlit end of the mark is, as a fraction
	// of the accent's own brightness.
	welcomeRampFloor = 0.55
	// welcomeRampCeiling is the lit end. The accent at full strength.
	welcomeRampCeiling = 1.0
)

// wordmarkCells is the mark as column cells, painted a row at a time.
func (v *welcomeView) wordmarkCells() []welcomeCell {
	lines := wordmarkLines()
	out := make([]welcomeCell, 0, len(lines))
	for _, line := range lines {
		out = append(out, welcomeCell{text: v.paintWordmark(line), width: len([]rune(line))})
	}
	return out
}

// paintWordmark colours one row of the mark.
//
// Flat where the terminal cannot do better. A luminance ramp quantised to 256
// colours bands into visible steps, which looks like a rendering fault on the
// first screen — worse than the flat accent it replaced.
func (v *welcomeView) paintWordmark(line string) string {
	runes := []rune(line)
	edge := v.sweepEdge(len(runes))

	if !v.truecolor && edge < 0 {
		return fmt.Sprintf("[%s]%s[-:-:-]", v.theme.TagAccent, tview.Escape(line))
	}

	var b strings.Builder
	for i, r := range runes {
		switch {
		case edge >= 0 && i > edge:
			// Not arrived. A blank rather than nothing, so the mark occupies
			// its full width from the first frame and the page never reflows.
			b.WriteRune(' ')
		case edge >= 0 && i == edge:
			fmt.Fprintf(&b, "[%s:-:b]%c[-:-:-]", tagColor(v.glowColor()), r)
		case v.truecolor:
			fmt.Fprintf(&b, "[%s]%c", tagColor(v.rampAt(rampFraction(i, len(runes)))), r)
		default:
			fmt.Fprintf(&b, "[%s]%c", v.theme.TagAccent, r)
		}
	}
	b.WriteString("[-:-:-]")
	return b.String()
}

// rampFraction is how far along the mark a character sits, from 0 to 1.
func rampFraction(i, n int) float64 {
	if n <= 1 {
		return welcomeRampCeiling
	}
	return float64(i) / float64(n-1)
}

// rampAt is the accent at a given point on the ramp.
func (v *welcomeView) rampAt(f float64) tcell.Color {
	return scaleColor(v.theme.Accent, welcomeRampFloor+f*(welcomeRampCeiling-welcomeRampFloor))
}

// scaleColor multiplies a colour's channels by f, clamped to a valid colour.
func scaleColor(c tcell.Color, f float64) tcell.Color {
	h := c.Hex()
	if h < 0 {
		return c
	}
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	channel := func(shift uint) int32 {
		return int32(float64((h>>shift)&0xff)*f + 0.5)
	}
	return tcell.NewRGBColor(channel(16), channel(8), channel(0))
}

// supportsTrueColor reports whether the terminal can draw a smooth ramp.
//
// COLORTERM rather than tcell's own Colors(), which reports 256 for a great
// many terminals that handle 24-bit colour perfectly well — it keys off TERM,
// and almost nobody sets TERM to a truecolor entry.
//
// NO_COLOR turns the gradient off. It does not turn the theme off: that is a
// larger decision than this screen, and a monochrome first run would be a
// worse answer than a flat accent.
func supportsTrueColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	return strings.Contains(ct, "truecolor") || strings.Contains(ct, "24bit")
}

// identityLine is the build and the schema it speaks, which are the two facts a
// bug report needs and the two this screen is uniquely placed to give: `console-
// ir version` needs a database that a first run does not have yet.
func (v *welcomeView) identityLine() string {
	return fmt.Sprintf("%s   ·   OCSF %s", buildinfo.Display(v.opts.Version), ocsf.SchemaVersion())
}
