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

	// detail says what this choice will actually cause, in one line beneath the
	// label. A bare list of four verbs makes an analyst guess how big the demo
	// is, which folder is being watched, and where the database will land; the
	// screen already knows all three.
	//
	// It is a function rather than a string because two of the four answers are
	// read off this machine, and because that keeps them out of the tests'
	// reach as constants that could drift from what is really there.
	detail func(v *welcomeView) string
}

func welcomeActions() []welcomeOption {
	return []welcomeOption{
		{'1', "Create a database", WelcomeCreate, func(*welcomeView) string {
			return "empty, ready for your own OCSF"
		}},
		{'2', "Load the demo investigation", WelcomeDemo, func(v *welcomeView) string {
			return v.opts.DemoSummary
		}},
		{'3', "Import a file", WelcomeImport, func(*welcomeView) string {
			return "one .json or .jsonl, read as OCSF"
		}},
		{'4', "Watch a folder", WelcomeWatch, func(v *welcomeView) string {
			return v.watchStatus
		}},
		{'q', "Quit", WelcomeQuit, nil},
	}
}

var welcomeOptions = welcomeActions()

// welcomeDefaultCursor is where the cursor rests when the screen opens.
//
// It is the demo, and that is the whole of the recommendation. The screen used
// to carry a line of copy under the card — "Press 2 to immediately explore
// Console-IR" — which said the same thing in a sentence, one row, and a third
// repetition of an action already listed twice. A resting cursor says it by
// pointing at it.
const welcomeDefaultCursor = 1

// actionCells is the action list as the right-hand column.
//
// Each action is a label and, where there is room, the consequence beneath it,
// with a blank row between actions so the pairs read as pairs. The details go
// before the actions do: a screen with no actions does nothing at all.
func (v *welcomeView) actionCells() []welcomeCell {
	details := v.density == densityFull
	out := make([]welcomeCell, 0, len(welcomeOptions)*3)

	for i, o := range welcomeOptions {
		selected := i == v.cursor
		rows := []welcomeCell{actionCell(o.key, o.label, v.theme, selected)}

		if details && o.detail != nil {
			if text := o.detail(v); text != "" {
				rows = append(rows, detailCell(text, v.theme, selected))
				// A blank between the pairs, so each detail reads as belonging
				// to the label above it. Only where there are pairs: bare
				// labels are a list, and double-spacing a list costs four rows
				// to say nothing.
				if i < len(welcomeOptions)-1 {
					rows = append(rows, welcomeCell{})
				}
			}
		}

		// One action per frame, so they arrive in a run down the column rather
		// than all at once.
		out = append(out, v.maskActions(rows, i)...)
	}
	return out
}

// detailCell is the consequence line beneath an action, indented to sit under
// the label rather than under the key cap.
func detailCell(text string, theme Theme, selected bool) welcomeCell {
	indent := strings.Repeat(" ", welcomeKeycapWidth+welcomeKeycapGap)
	if !selected {
		return welcomeCell{
			text:  fmt.Sprintf("%s[%s]%s[-:-:-]", indent, theme.TagMuted, tview.Escape(text)),
			width: welcomeKeycapWidth + welcomeKeycapGap + len([]rune(text)),
		}
	}

	// Selected, the detail is part of the same band as its label, so the two
	// read as one selected thing rather than as a highlighted row with a loose
	// line under it.
	width := welcomeActionWidth()
	if n := welcomeKeycapWidth + welcomeKeycapGap + len([]rune(text)); n > width {
		width = n
	}
	pad := strings.Repeat(" ", width-welcomeKeycapWidth-welcomeKeycapGap-len([]rune(text)))
	return welcomeCell{
		text: fmt.Sprintf("%s[%s:%s]%s%s[-:-:-]", indent,
			tagColor(theme.TextMuted), tagColor(theme.SelectionBg), tview.Escape(text), pad),
		width: width,
	}
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
