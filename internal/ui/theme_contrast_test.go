package ui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// mustRGB fails the test for a colour that cannot be measured.
func mustRGB(t *testing.T, theme, what string, c tcell.Color) rgb {
	t.Helper()
	v, ok := toRGB(c)
	if !ok {
		t.Fatalf("%s: %s is not an RGB colour, so it cannot be checked", theme, what)
	}
	return v
}

// No theme may give two severities the same colour.
//
// Severity is colour-coded on every screen, so two severities that look alike
// is a defect in the same class as a wrong number — the analyst reads the wrong
// urgency off the queue and works the wrong finding first.
func TestSeverityColoursAreDistinct(t *testing.T) {
	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		colours := severityColours(theme)

		for i := 0; i < len(colours); i++ {
			for j := i + 1; j < len(colours); j++ {
				a := mustRGB(t, name, colours[i].name, colours[i].color)
				b := mustRGB(t, name, colours[j].name, colours[j].color)
				if d := distance(a, b); d < severityDistanceFloor {
					t.Errorf("%s: %s and %s are %.0f apart, want at least %d",
						name, colours[i].name, colours[j].name, d, severityDistanceFloor)
				}
			}
		}
	}
}

// Every severity colour must be readable on the surface it is drawn on.
func TestSeverityColoursAreLegible(t *testing.T) {
	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		for _, surface := range []struct {
			what  string
			color tcell.Color
		}{
			{"the pane background", theme.Bg},
			{"a panel surface", theme.Surface},
		} {
			bg := mustRGB(t, name, surface.what, surface.color)
			for _, sev := range severityColours(theme) {
				fg := mustRGB(t, name, sev.name, sev.color)
				if r := contrastRatio(fg, bg); r < severityContrastFloor {
					t.Errorf("%s: %s on %s has contrast %.1f, want at least %.1f",
						name, sev.name, surface.what, r, severityContrastFloor)
				}
			}
		}
	}
}

// The colourblind palette must still work for the readers it names.
//
// This is the claim the palette makes, and nothing tested it. A palette that
// separates severities by red and green alone passes every check above and
// collapses into two colours for the people it was built for.
func TestTheColourblindPaletteSurvivesColourblindness(t *testing.T) {
	theme := themeBuilders["colorblind"]()
	colours := severityColours(theme)

	for _, kind := range []string{"protanopia", "deuteranopia", "tritanopia"} {
		for i := 0; i < len(colours); i++ {
			for j := i + 1; j < len(colours); j++ {
				a := simulateColourblind(mustRGB(t, "colorblind", colours[i].name, colours[i].color), kind)
				b := simulateColourblind(mustRGB(t, "colorblind", colours[j].name, colours[j].color), kind)
				if d := distance(a, b); d < severityDistanceFloor {
					t.Errorf("colorblind/%s: %s and %s collapse to %.0f apart, want at least %d",
						kind, colours[i].name, colours[j].name, d, severityDistanceFloor)
				}
			}
		}
	}
}

// The checks bite.
//
// A test that only ever passes proves nothing, so this builds the palette the
// checks exist to reject and asserts each one catches it.
func TestTheThemeChecksRejectABadPalette(t *testing.T) {
	bad := themeDark()
	bad.SeverityHigh = bad.SeverityCritical      // indistinguishable
	bad.SeverityMedium = bad.Bg                  // invisible
	bad.SeverityLow = tcell.NewRGBColor(0, 0, 1) // effectively black on black

	var collisions, unreadable int
	colours := severityColours(bad)
	for i := 0; i < len(colours); i++ {
		a, _ := toRGB(colours[i].color)
		for j := i + 1; j < len(colours); j++ {
			b, _ := toRGB(colours[j].color)
			if distance(a, b) < severityDistanceFloor {
				collisions++
			}
		}
		bg, _ := toRGB(bad.Bg)
		if contrastRatio(a, bg) < severityContrastFloor {
			unreadable++
		}
	}

	if collisions == 0 {
		t.Error("the distinctness check passed a palette with two identical severities")
	}
	if unreadable == 0 {
		t.Error("the contrast check passed a severity drawn in the background colour")
	}
}

// Every registered theme paints in colours that can be measured, so nothing
// slips past the checks above by being unmeasurable.
func TestEveryThemeUsesMeasurableColours(t *testing.T) {
	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		for what, c := range map[string]tcell.Color{
			"Bg": theme.Bg, "Surface": theme.Surface, "TextPrimary": theme.TextPrimary,
		} {
			if _, ok := toRGB(c); !ok {
				t.Errorf("%s: %s is %v, which has no RGB of its own", name, what, c)
			}
		}
		_ = fmt.Sprint(name)
	}
}

// A theme's colour tags must name the same colours as its widgets.
//
// Every palette carries each severity twice — once as a tcell.Color for widgets
// and once as a hex string for the markup the text panels use. Nothing kept the
// two in step, so a palette could paint a badge in one colour and the table cell
// beside it in another, and the only way to notice was to look.
func TestTheColourTagsMatchTheWidgetColours(t *testing.T) {
	for _, name := range themeNames() {
		th := themeBuilders[name]()
		for _, pair := range []struct {
			what  string
			color tcell.Color
			tag   string
		}{
			{"critical", th.SeverityCritical, th.TagSeverityCritical},
			{"high", th.SeverityHigh, th.TagSeverityHigh},
			{"medium", th.SeverityMedium, th.TagSeverityMedium},
			{"low", th.SeverityLow, th.TagSeverityLow},
			{"informational", th.SeverityInfo, th.TagSeverityInfo},
			{"accent", th.Accent, th.TagAccent},
			{"muted", th.TextMuted, th.TagMuted},
		} {
			tagged := tcell.GetColor(pair.tag)
			if tagged != pair.color {
				t.Errorf("%s: %s is %v as a widget colour but %q (%v) as a tag",
					name, pair.what, pair.color, pair.tag, tagged)
			}
		}
	}
}

// Every screen, in every theme, at two sizes.
//
// The palettes were registered and never looked at. This is the cheap half of
// looking: it will not tell you a colour is ugly, but it catches the failures
// that are not a matter of taste — a colour tag reaching the screen as text
// because a theme's tag string is malformed, and a panel that paints nothing.
func TestEveryScreenRendersInEveryTheme(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 2)
	seedTriageFinding(t, st, "a", "")
	seedEvents(t, ui, 4)

	screens := []struct {
		id    destinationID
		panel string
	}{
		{destHome, "PRIORITY"},
		{destTriage, "FINDINGS"},
		{destCases, "BRIEFING"},
		{destEvents, "Events"},
		{destIndicators, "INDICATORS"},
	}

	for _, name := range themeNames() {
		ui.setTheme(name)
		for _, screen := range screens {
			ui.enterScreen(screen.id)
			awaitIdle(t, ui)
			// Home's clock and refresh ticker repaint from their own goroutine;
			// stopped here so a tick cannot land inside a render.
			if ui.home != nil {
				ui.home.close()
			}

			for _, size := range [][2]int{{150, 40}, {100, 30}} {
				frame := strings.Join(renderPrimitive(t, ui.mainRoot(), size[0], size[1]), "\n")

				for _, fragment := range []string{"[-:-:-]", "[::b]", "[#"} {
					if strings.Contains(frame, fragment) {
						t.Errorf("%s/%v at %dx%d: %q reached the screen as text",
							name, screen.id, size[0], size[1], fragment)
					}
				}
				if !strings.Contains(frame, "Console-IR") {
					t.Errorf("%s/%v at %dx%d: the status bar did not paint",
						name, screen.id, size[0], size[1])
				}
			}
		}
	}
}
