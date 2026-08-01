package ui

import (
	"fmt"
	"strings"

	"github.com/rivo/tview"
)

// buildCaseNotesTab renders chronological decision log notes.
func (ui *UI) buildCaseNotesTab(caseID string) *tview.Flex {
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	flex.SetBackgroundColor(ui.theme.Bg)

	notesList := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	notesList.SetBorder(true).
		SetTitle(" CHRONOLOGICAL DECISION LOG ").
		SetTitleColor(ui.theme.Header).
		SetBackgroundColor(ui.theme.Bg)

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  [%s]2026-08-01 10:15:00[-:-:-]  [%s:b]paolo (Analyst)[-:-:-]  [%s][Containment Action][-:-:-]\n",
		ui.theme.TagMuted, ui.theme.TagAccent, ui.theme.TagWarning))
	sb.WriteString(fmt.Sprintf("  [%s]Host FIN-02 isolated from network. Kerberos tickets revoked.[-:-:-]\n\n", ui.theme.TagTextPrimary))

	notesList.SetText(sb.String())
	flex.AddItem(notesList, 0, 1, true)

	return flex
}
