package ui

import (
	"fmt"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// buildCaseTimelineTab builds the chronological clustered timeline view.
func (ui *UI) buildCaseTimelineTab(events []store.Event) *tview.TextView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	tv.SetBorder(true).
		SetTitle(" CASE TIMELINE ").
		SetTitleColor(ui.theme.Header).
		SetBackgroundColor(ui.theme.Bg)

	var sb strings.Builder
	sb.WriteString("\n")

	if len(events) == 0 {
		sb.WriteString(fmt.Sprintf("  [%s]No timeline events recorded for this case.[-:-:-]\n", ui.theme.TagMuted))
		tv.SetText(sb.String())
		return tv
	}

	for i, e := range events {
		glyph := "├"
		if i == len(events)-1 {
			glyph = "└"
		}

		timeStr := e.Timestamp.Format("15:04:05")
		sevBadge := formatSeverityBadge(e.Severity, ui.theme)

		sb.WriteString(fmt.Sprintf("  [%s]%s ● %s[-:-:-]  %s  [%s:b]%s[-:-:-]\n",
			ui.theme.TagAccent, timeStr, glyph, sevBadge, ui.theme.TagTextPrimary, e.Message))
		sb.WriteString(fmt.Sprintf("  [%s]  │           Host: %s  ·  User: %s  ·  Class: %d[-:-:-]\n",
			ui.theme.TagMuted, e.Host, e.UserName, e.ClassUID))
		sb.WriteString("  │\n")
	}

	tv.SetText(sb.String())
	return tv
}
