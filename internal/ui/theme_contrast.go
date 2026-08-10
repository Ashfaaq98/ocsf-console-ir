package ui

import (
	"math"

	"github.com/gdamore/tcell/v2"
)

// What makes a theme correct rather than merely a preference.
//
// Severity is colour-coded on every screen, so two severities that look alike
// is a defect in the same class as a wrong number: the analyst reads the wrong
// urgency off a queue and works the wrong finding first. That is why the
// high-contrast and colourblind palettes shipped registered but unclaimed —
// nobody had checked them, and there was nothing to check them with.
//
// The three properties below are mechanical, so they can be asserted rather
// than eyeballed: severities differ from each other, each is legible on the
// surface behind it, and — for a palette that claims colourblind safety — they
// still differ once the colours are put through the vision they claim to serve.

// rgb is a colour as three channels, 0-255.
type rgb struct{ r, g, b float64 }

// toRGB decomposes a tcell colour. Palette entries below 256 have no RGB of
// their own — they are whatever the terminal says they are — so they cannot be
// measured and report false.
func toRGB(c tcell.Color) (rgb, bool) {
	if !c.Valid() {
		return rgb{}, false
	}
	if c&tcell.ColorIsRGB == 0 {
		return rgb{}, false
	}
	v := int32(c) & 0xffffff
	return rgb{
		r: float64((v >> 16) & 0xff),
		g: float64((v >> 8) & 0xff),
		b: float64(v & 0xff),
	}, true
}

// relativeLuminance is the WCAG definition, used for contrast ratios.
func (c rgb) relativeLuminance() float64 {
	channel := func(v float64) float64 {
		s := v / 255
		if s <= 0.03928 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(c.r) + 0.7152*channel(c.g) + 0.0722*channel(c.b)
}

// contrastRatio is the WCAG ratio between two colours: 1 is identical, 21 is
// black on white.
func contrastRatio(a, b rgb) float64 {
	la, lb := a.relativeLuminance(), b.relativeLuminance()
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// distance is how far apart two colours are in plain RGB space.
//
// Deliberately not a perceptual metric: this is a floor, not a judgement. Two
// severity colours a couple of steps apart are the same colour to a reader even
// if a perceptual model can tell them apart.
func distance(a, b rgb) float64 {
	dr, dg, db := a.r-b.r, a.g-b.g, a.b-b.b
	return math.Sqrt(dr*dr + dg*dg + db*db)
}

// Thresholds. Both are floors chosen to catch a palette that is wrong, not to
// grade one that is right.
const (
	// severityDistanceFloor is how far apart two severity colours must be.
	// Roughly the gap between a mid orange and a mid red.
	severityDistanceFloor = 60

	// severityContrastFloor is the least contrast a severity colour may have
	// against the surface it is drawn on. WCAG asks 4.5 for body text and 3.0
	// for large text; a severity badge is short, bold and coloured, so 3.0 is
	// the floor and anything under it is unreadable rather than merely tiring.
	severityContrastFloor = 3.0
)

// severityColours is the five, in order, with names for a failure message.
func severityColours(t Theme) []struct {
	name  string
	color tcell.Color
} {
	return []struct {
		name  string
		color tcell.Color
	}{
		{"critical", t.SeverityCritical},
		{"high", t.SeverityHigh},
		{"medium", t.SeverityMedium},
		{"low", t.SeverityLow},
		{"informational", t.SeverityInfo},
	}
}

// simulateColourblind approximates how a colour is seen with a given form of
// colour blindness.
//
// The Brettel/Viénot-style linear approximation in sRGB. It is not a clinical
// model and does not need to be: it is used to prove that five colours claiming
// to be distinguishable do not collapse into two, which is a large effect.
func simulateColourblind(c rgb, kind string) rgb {
	switch kind {
	case "protanopia": // no red cone
		return rgb{
			r: 0.567*c.r + 0.433*c.g,
			g: 0.558*c.r + 0.442*c.g,
			b: 0.242*c.g + 0.758*c.b,
		}
	case "deuteranopia": // no green cone
		return rgb{
			r: 0.625*c.r + 0.375*c.g,
			g: 0.700*c.r + 0.300*c.g,
			b: 0.300*c.g + 0.700*c.b,
		}
	case "tritanopia": // no blue cone
		return rgb{
			r: 0.950*c.r + 0.050*c.g,
			g: 0.433*c.g + 0.567*c.b,
			b: 0.475*c.g + 0.525*c.b,
		}
	}
	return c
}
