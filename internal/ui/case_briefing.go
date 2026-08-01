package ui

import (
	"fmt"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// CaseBriefingView renders the main Executive Incident Briefing tab.
type CaseBriefingView struct {
	flex             *tview.Flex
	incidentStmtBox  *tview.TextView
	scopeCardBox     *tview.TextView
	hypothesesBox    *tview.TextView
	nextActionsTable *tview.Table
}

// buildCaseBriefingTab constructs the briefing view components.
func (ui *UI) buildCaseBriefingTab(c store.Case) *tview.Flex {
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	flex.SetBackgroundColor(ui.theme.Bg)

	// Top row: Statement & Scope
	topRow := tview.NewFlex().SetDirection(tview.FlexColumn)

	stmtBox := tview.NewTextView().SetDynamicColors(true)
	stmtBox.SetBorder(true).SetTitle(" INCIDENT STATEMENT ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Surface)
	stmtBox.SetText(fmt.Sprintf("\n  [%s:b]We are investigating: %s[-:-:-]\n  [%s]Severity: %s  ·  Status: %s  ·  Owner: %s[-:-:-]",
		ui.theme.TagTextPrimary, c.Title, ui.theme.TagMuted, formatSeverityBadge(c.Severity, ui.theme), formatCaseStatus(c.Status, ui.theme), c.AssignedTo))

	scopeBox := tview.NewTextView().SetDynamicColors(true)
	scopeBox.SetBorder(true).SetTitle(" INCIDENT SCOPE ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Surface)
	scopeBox.SetText(fmt.Sprintf("\n  [%s]Findings: %d  ·  Evidence Events: %d[-:-:-]\n  [%s]Created: %s[-:-:-]",
		ui.theme.TagTextPrimary, c.FindingCount, c.EventCount, ui.theme.TagMuted, renderRelativeTime(c.CreatedAt)))

	topRow.AddItem(stmtBox, 0, 2, false).
		AddItem(scopeBox, 0, 1, false)

	// Bottom row: Hypotheses & Checklist Next Actions
	bottomRow := tview.NewFlex().SetDirection(tview.FlexColumn)

	hypoBox := tview.NewTextView().SetDynamicColors(true)
	hypoBox.SetBorder(true).SetTitle(" WORKING HYPOTHESES ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Bg)
	var hypoSb strings.Builder
	hypoSb.WriteString("\n")
	hypoSb.WriteString(fmt.Sprintf("  [%s:b]● Confirmed:[-:-:-] [%s]Suspicious execution via PowerShell on FIN-02[-:-:-]\n", ui.theme.TagSeverityCritical, ui.theme.TagTextPrimary))
	hypoSb.WriteString(fmt.Sprintf("  [%s:b]▲ Likely:[-:-:-] [%s]Credential dumping attempt against Domain Admin[-:-:-]\n", ui.theme.TagSeverityHigh, ui.theme.TagTextPrimary))
	hypoSb.WriteString(fmt.Sprintf("  [%s:b]◆ Open Question:[-:-:-] [%s]Has egress traffic established C2 session?[-:-:-]\n", ui.theme.TagSeverityMedium, ui.theme.TagTextPrimary))
	hypoBox.SetText(hypoSb.String())

	actionsTable := tview.NewTable().SetSelectable(true, false)
	actionsTable.SetBorder(true).SetTitle(" NEXT ACTIONS CHECKLIST ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Surface)
	actionsTable.SetCell(0, 0, tview.NewTableCell("State").SetTextColor(ui.theme.TableHeader))
	actionsTable.SetCell(0, 1, tview.NewTableCell("Action Item").SetTextColor(ui.theme.TableHeader))
	actionsTable.SetCell(0, 2, tview.NewTableCell("Assignee").SetTextColor(ui.theme.TableHeader))

	actionsTable.SetCell(1, 0, tview.NewTableCell("[✓]").SetTextColor(ui.theme.Success))
	actionsTable.SetCell(1, 1, tview.NewTableCell("Isolate compromised endpoint FIN-02").SetTextColor(ui.theme.TextPrimary))
	actionsTable.SetCell(1, 2, tview.NewTableCell(c.AssignedTo).SetTextColor(ui.theme.TextMuted))

	actionsTable.SetCell(2, 0, tview.NewTableCell("[ ]").SetTextColor(ui.theme.Warning))
	actionsTable.SetCell(2, 1, tview.NewTableCell("Revoke compromised kerberos tickets").SetTextColor(ui.theme.TextPrimary))
	actionsTable.SetCell(2, 2, tview.NewTableCell(c.AssignedTo).SetTextColor(ui.theme.TextMuted))

	bottomRow.AddItem(hypoBox, 0, 1, false).
		AddItem(actionsTable, 0, 1, true)

	flex.AddItem(topRow, 6, 0, false).
		AddItem(bottomRow, 0, 1, true)

	return flex
}
