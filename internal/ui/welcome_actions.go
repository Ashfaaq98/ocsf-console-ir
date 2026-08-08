package ui

import (
	"fmt"

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

// actionCells is the action list as the right-hand column.
func (v *welcomeView) actionCells() []welcomeCell {
	out := make([]welcomeCell, 0, len(welcomeOptions))
	for _, o := range welcomeOptions {
		out = append(out, actionCell(o.key, o.label, v.theme, false))
	}
	return out
}

// welcomeKeycapWidth is the drawn width of a key cap: the key, padded either
// side so the highlight reads as a cap rather than as a coloured character.
const welcomeKeycapWidth = 3

// actionCell is one "1  Label" row.
//
// The key is a reverse-video cap rather than "[1]". Brackets were there because
// tview reads "[1]" in dynamic-colour text as a colour tag and swallows it, so
// the list showed its own escaping; and no keyboard has a "[1]" key. A cap is
// both what the terminal can draw and what the analyst will press.
func actionCell(key rune, label string, theme Theme, selected bool) welcomeCell {
	keycap := fmt.Sprintf("[%s:%s:b] %c [-:-:-]", tagColor(theme.Canvas), theme.TagAccent, key)
	labelTag := theme.TagTextPrimary
	if selected {
		labelTag = theme.TagAccent
	}
	return welcomeCell{
		text:  fmt.Sprintf("%s  [%s]%s[-:-:-]", keycap, labelTag, tview.Escape(label)),
		width: welcomeKeycapWidth + 2 + len([]rune(label)),
	}
}
