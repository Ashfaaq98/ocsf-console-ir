package ui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// The wordmark carries no bracket into tview's dynamic-colour parser.
//
// The gradient writes one colour tag per character, so the mark and the markup
// are interleaved. A bracket in the mark itself would be read as a tag and
// swallow whatever came after it, and the failure would be a hole in the
// product's name on the first screen anybody sees.
func TestWordmarkCarriesNoBrackets(t *testing.T) {
	for _, set := range [][]string{wordmarkUnicode, wordmarkASCII} {
		for _, line := range set {
			if strings.ContainsAny(line, "[]") {
				t.Errorf("the wordmark line %q contains a bracket", line)
			}
		}
	}
}

// Every row of the mark is the same width, or the gradient runs at a different
// rate on each one and the mark shears.
func TestWordmarkRowsAreEqualWidth(t *testing.T) {
	want := len([]rune(wordmarkUnicode[0]))
	for i, line := range wordmarkUnicode {
		if got := len([]rune(line)); got != want {
			t.Errorf("wordmark row %d is %d columns, want %d", i, got, want)
		}
	}
}

// The gradient must not change what the mark says. However it is coloured, the
// characters that reach the screen are the same ones.
func TestGradientPreservesTheWordmark(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})

	for _, truecolor := range []bool{false, true} {
		v.truecolor = truecolor
		for _, line := range wordmarkLines() {
			if got := stripTags(v.paintWordmark(line)); got != line {
				t.Errorf("truecolor=%v: painted %q, want %q", truecolor, got, line)
			}
		}
	}
}

// A terminal that cannot draw 24-bit colour gets one flat accent rather than a
// ramp quantised into visible bands.
func TestGradientIsFlatWithoutTrueColor(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.truecolor = false

	got := v.paintWordmark(wordmarkLines()[0])
	if strings.Count(got, "[") != 2 {
		t.Errorf("the flat mark carries %d tags, want one colour and one reset: %q",
			strings.Count(got, "["), got)
	}
}

// And a terminal that can gets a ramp that actually ramps: the lit end is
// brighter than the unlit end, in every theme.
func TestGradientRampsInEveryTheme(t *testing.T) {
	for name, build := range themeBuilders {
		t.Run(name, func(t *testing.T) {
			v := newTestWelcome(t, WelcomeOptions{})
			v.theme = build()
			v.truecolor = true

			dark, light := v.rampAt(0), v.rampAt(1)
			if luminance(dark) >= luminance(light) {
				t.Errorf("the ramp does not brighten: %v then %v", dark, light)
			}
			if light != v.theme.Accent {
				t.Errorf("the lit end is %v, want the accent %v", light, v.theme.Accent)
			}
		})
	}
}

func TestScaleColorLeavesNonRGBColoursAlone(t *testing.T) {
	if got := scaleColor(tcell.ColorDefault, 0.5); got != tcell.ColorDefault {
		t.Errorf("scaling the default colour produced %v", got)
	}
}

// luminance is a rough brightness, enough to order two shades of one hue.
func luminance(c tcell.Color) int32 {
	h := c.Hex()
	if h < 0 {
		return -1
	}
	return (h>>16)&0xff + (h>>8)&0xff + h&0xff
}
