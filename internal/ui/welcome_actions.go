package ui

import (
	"fmt"
	"strings"

	"github.com/rivo/tview"
)

// The action list: what a first run can do, and what each choice will actually
// cause.

// welcomeOption is one row of the action list.
type welcomeOption struct {
	key    rune
	label  string
	action WelcomeAction
}

var welcomeOptions = []welcomeOption{
	{'1', "Create a database", WelcomeCreate},
	{'2', "Load the demo investigation", WelcomeDemo},
	{'3', "Import a file", WelcomeImport},
	{'4', "Watch a folder", WelcomeWatch},
	{'q', "Quit", WelcomeQuit},
}

// welcomeDefaultCursor is where the cursor rests when the screen opens.
//
// It is the demo, and that is the whole of the recommendation. The screen used
// to carry a line of copy under the card — "Press 2 to immediately explore
// Console-IR" — which said the same thing in a sentence, one row, and a third
// repetition of an action already listed twice. A resting cursor says it by
// pointing at it.
const welcomeDefaultCursor = 1

// actionCells is the action list as the right-hand column.
func (v *welcomeView) actionCells() []welcomeCell {
	out := make([]welcomeCell, 0, len(welcomeOptions))
	for i, o := range welcomeOptions {
		out = append(out, actionCell(o.key, o.label, v.theme, i == v.cursor))
	}
	return out
}

// moveCursor steps the cursor by delta, wrapping at both ends. Wrapping matters
// on a five-item list: pressing up from the top is how people reach the bottom.
func (v *welcomeView) moveCursor(delta int) {
	n := len(welcomeOptions)
	if n == 0 {
		return
	}
	v.cursor = ((v.cursor+delta)%n + n) % n
	v.render()
}

// cursorOption is the option the cursor is resting on.
func (v *welcomeView) cursorOption() welcomeOption {
	if v.cursor < 0 || v.cursor >= len(welcomeOptions) {
		return welcomeOptions[0]
	}
	return welcomeOptions[v.cursor]
}

// welcomeKeycapWidth is the drawn width of a key cap: the key, padded either
// side so the highlight reads as a cap rather than as a coloured character.
const welcomeKeycapWidth = 3

// welcomeKeycapGap separates a cap from its label.
const welcomeKeycapGap = 2

// welcomeActionWidth is the drawn width of every action row.
//
// Uniform, so the selection band is a rectangle. Sized to the longest label, it
// would otherwise follow each row's ragged right edge and read as a highlight
// that could not decide where it ended.
func welcomeActionWidth() int {
	widest := 0
	for _, o := range welcomeOptions {
		if n := len([]rune(o.label)); n > widest {
			widest = n
		}
	}
	return welcomeKeycapWidth + welcomeKeycapGap + widest
}

// actionCell is one "1  Label" row.
//
// The key is a reverse-video cap rather than "[1]". Brackets were there because
// tview reads "[1]" in dynamic-colour text as a colour tag and swallows it, so
// the list showed its own escaping; and no keyboard has a "[1]" key. A cap is
// both what the terminal can draw and what the analyst will press.
func actionCell(key rune, label string, theme Theme, selected bool) welcomeCell {
	width := welcomeKeycapWidth + welcomeKeycapGap + len([]rune(label))
	pad := ""
	if selected {
		// The band runs to the full row width so it is a rectangle. Only the
		// selected row is padded: trailing blanks on the others would be
		// invisible, but they would also make every cell claim a width it is
		// not using, and the columns are laid out from those widths.
		width = welcomeActionWidth()
		pad = strings.Repeat(" ", width-welcomeKeycapWidth-welcomeKeycapGap-len([]rune(label)))
	}

	keycap := fmt.Sprintf("[%s:%s:b] %c [-:-:-]", tagColor(theme.Canvas), theme.TagAccent, key)
	gap := strings.Repeat(" ", welcomeKeycapGap)

	if selected {
		return welcomeCell{
			text: fmt.Sprintf("%s[%s:%s:b]%s%s%s[-:-:-]", keycap,
				tagColor(theme.SelectionFg), tagColor(theme.SelectionBg),
				gap, tview.Escape(label), pad),
			width: width,
		}
	}
	return welcomeCell{
		text:  fmt.Sprintf("%s%s[%s]%s[-:-:-]", keycap, gap, theme.TagTextPrimary, tview.Escape(label)),
		width: width,
	}
}
