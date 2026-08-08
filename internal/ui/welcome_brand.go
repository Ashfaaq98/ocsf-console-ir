package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/buildinfo"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
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

// wordmarkCells is the mark as column cells, painted a row at a time.
func (v *welcomeView) wordmarkCells() []welcomeCell {
	lines := wordmarkLines()
	out := make([]welcomeCell, 0, len(lines))
	for i, line := range lines {
		out = append(out, welcomeCell{text: v.paintWordmark(line, i), width: len([]rune(line))})
	}
	return out
}

// paintWordmark colours one row of the mark. The gradient arrives in step 6;
// until then every row is the accent, which is what the mark has always been.
func (v *welcomeView) paintWordmark(line string, _ int) string {
	return fmt.Sprintf("[%s]%s[-:-:-]", v.theme.TagAccent, tview.Escape(line))
}

// identityLine is the build and the schema it speaks, which are the two facts a
// bug report needs and the two this screen is uniquely placed to give: `console-
// ir version` needs a database that a first run does not have yet.
func (v *welcomeView) identityLine() string {
	return fmt.Sprintf("%s   ·   OCSF %s", buildinfo.Display(v.opts.Version), ocsf.SchemaVersion())
}
