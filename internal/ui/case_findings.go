package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// caseFindingHeaders mirror the main triage queue so the two read alike. A
// finding should not look like a different kind of thing depending on whether
// you reached it from the queue or from the case it belongs to.
var caseFindingHeaders = []string{"Sev", "Status", "Verdict", "Risk", "Title", "Analytic"}

// setupCaseFindingsTable builds the table shown on the Findings tab.
//
// Findings are what a case is *about* — OCSF models them as its members, with
// events attached separately as evidence. Escalation has always written that
// membership, but nothing ever read it back: GetCaseFindings had no caller
// outside tests, so an escalated finding vanished from view the moment the case
// was opened.
func (cm *CaseManagement) setupCaseFindingsTable() {
	cm.findingsTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	cm.findingsTable.SetBorder(true).
		SetTitle(" FINDINGS ").
		SetTitleAlign(tview.AlignLeft)

	// Enter opens the finding the same way the queue does.
	cm.findingsTable.SetSelectedFunc(func(row, _ int) {
		idx := row - 1
		if idx < 0 || idx >= len(cm.caseFindings) {
			return
		}
		cm.showCaseFindingModal(cm.caseFindings[idx])
	})
}

// loadCaseFindings fetches the case's findings and renders them. The query runs
// off the UI goroutine; only the render is queued back.
func (cm *CaseManagement) loadCaseFindings() {
	if cm.store == nil || cm.caseData.ID == "" {
		return
	}
	work := func() {
		findings, err := cm.store.GetCaseFindings(cm.ctx, cm.caseData.ID)
		if err != nil {
			cm.logger.Error("failed to load findings for case %s: %v", cm.caseData.ID, err)
		}
		cm.queueUpdate(func() {
			cm.caseFindings = findings
			cm.renderCaseFindings()
			// The tab strip counts them, and so does the briefing's scope.
			cm.renderTabBar()
			cm.renderBriefing()
		})
	}

	// Through spawnLoad so the load is tracked: a bare goroutine cannot be
	// waited on, and "the query has not started" is indistinguishable from
	// "the query has finished" from outside.
	if cm.parentUI != nil {
		cm.parentUI.spawnLoad(work)
		return
	}
	go work()
}

// renderCaseFindings paints cm.caseFindings into the table.
func (cm *CaseManagement) renderCaseFindings() {
	if cm.findingsTable == nil {
		return
	}
	cm.findingsTable.Clear()
	setTableCursor(cm.findingsTable, len(cm.caseFindings) > 0)
	cm.findingsTable.SetSelectedStyle(tcell.StyleDefault.
		Background(cm.theme.SelectionBg).Foreground(cm.theme.SelectionFg))
	// Named like every other pane, and without the count: the tab strip carries
	// that, from the same slice, so a second copy could only ever disagree.
	// The border colour is left to updateFocusStyles, which owns it — setting
	// it here painted the resting grey back over the focus highlight on every
	// re-render.
	cm.findingsTable.SetTitle(" FINDINGS ")

	for col, h := range caseFindingHeaders {
		cm.findingsTable.SetCell(0, col, tview.NewTableCell(h).
			SetTextColor(cm.theme.TableHeader).
			SetBackgroundColor(cm.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold))
	}

	if len(cm.caseFindings) == 0 {
		// An empty pane reads like a broken tab; say what the tab is for.
		for i, line := range []string{
			"No findings attached to this case.",
			"",
			"Findings are what a case is about. Attach one from the findings",
			"queue (D) by pressing e to escalate it into a case.",
		} {
			cell := tview.NewTableCell(line).
				SetTextColor(cm.theme.TableRowMuted).
				SetExpansion(1)
			if i == 0 {
				cell.SetAttributes(tcell.AttrBold)
			}
			cm.findingsTable.SetCell(1+i, 0, cell)
		}
		return
	}

	// Highest risk first, matching the triage queue's ordering.
	sort.SliceStable(cm.caseFindings, func(i, j int) bool {
		a, b := cm.caseFindings[i], cm.caseFindings[j]
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if a.SeverityID != b.SeverityID {
			return a.SeverityID > b.SeverityID
		}
		return a.LastSeen.After(b.LastSeen)
	})

	for i, f := range cm.caseFindings {
		row := i + 1
		cells := []struct {
			text  string
			color tcell.Color
		}{
			{strings.ToUpper(dashIfEmpty(f.Severity)), cm.severityColor(f.Severity)},
			{dashIfEmpty(f.Status), cm.theme.TableRow},
			{dashIfEmpty(f.Verdict), cm.theme.TableRow},
			{riskText(f.RiskScore), cm.theme.TableRow},
			// Prose, so the entities inside it are coloured where their shape
			// gives them away — the same as the queue this finding came from.
			{paintTextOn(dashIfEmpty(f.Title), tagColor(cm.theme.TextPrimary), cm.theme),
				cm.theme.TextPrimary},
			{dashIfEmpty(f.AnalyticName), cm.theme.TableRowMuted},
		}
		for col, c := range cells {
			cell := tview.NewTableCell(c.text).SetTextColor(c.color)
			if col == 4 {
				cell.SetExpansion(1)
			}
			cm.findingsTable.SetCell(row, col, cell)
		}
	}
}

// showCaseFindingModal shows one finding's detail, reusing the modal stack.
func (cm *CaseManagement) showCaseFindingModal(f store.Finding) {
	body := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	body.SetBorder(true).SetTitle(" Finding ").SetTitleAlign(tview.AlignLeft)
	body.SetBackgroundColor(cm.theme.Surface)
	body.SetTextColor(cm.theme.TextPrimary)

	body.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc ||
			(event.Key() == tcell.KeyRune && (event.Rune() == 'q' || event.Rune() == 'Q')) {
			cm.popModalRoot()
			return nil
		}
		return event
	})
	body.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEsc {
			cm.popModalRoot()
		}
	})

	lbl, val := cm.theme.TagWarning, cm.theme.TagTextPrimary
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s::b]%s[-:-:-]\n\n",
		cm.theme.TagTextPrimary, paintText(dashIfEmpty(f.Title), cm.theme)))

	for _, row := range [][2]string{
		{"Severity", strings.ToUpper(dashIfEmpty(f.Severity))},
		{"Status", dashIfEmpty(f.Status)},
		{"Verdict", dashIfEmpty(f.Verdict)},
		{"Risk", riskText(f.RiskScore)},
		{"Analytic", dashIfEmpty(f.AnalyticName)},
		{"Finding UID", dashIfEmpty(f.FindingUID)},
		{"First seen", timeText(f.FirstSeen)},
		{"Last seen", timeText(f.LastSeen)},
	} {
		sb.WriteString(fmt.Sprintf("[%s]%-12s[-] [%s]%s[-]\n", lbl, row[0], val, row[1]))
	}

	if techniques := f.AttackTechniques(); len(techniques) > 0 {
		sb.WriteString(fmt.Sprintf("\n[%s]%-12s[-] [%s]%s[-]\n",
			lbl, "ATT&CK", val, strings.Join(techniques, ", ")))
	}
	if f.Message != "" {
		sb.WriteString(fmt.Sprintf("\n[%s]Message:[-]\n[%s]%s[-]\n", lbl, val, f.Message))
	}
	sb.WriteString(fmt.Sprintf("\n\n[%s][Esc or q] close[-]", cm.theme.TagMuted))

	body.SetText(sb.String())
	cm.pushModalRoot(body)
}

func (cm *CaseManagement) severityColor(severity string) tcell.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return cm.theme.SeverityCritical
	case "high":
		return cm.theme.SeverityHigh
	case "medium":
		return cm.theme.SeverityMedium
	case "low":
		return cm.theme.SeverityLow
	default:
		return cm.theme.SeverityInfo
	}
}

func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func riskText(score int) string {
	if score <= 0 {
		return "—"
	}
	return fmt.Sprintf("%d", score)
}

// timeText renders a timestamp, or a dash when it was never set.
func timeText(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04:05")
}

// detachSelectedFinding removes a finding from the case.
//
// A finding is what the case is *about* — OCSF models it as a case member, not
// as attached evidence — so detaching one narrows what the case claims. That is
// a decision, so it is confirmed and it is recorded in the audit trail. The
// finding itself is untouched and can be escalated back.
func (cm *CaseManagement) detachSelectedFinding() {
	row, _ := cm.findingsTable.GetSelection()
	idx := row - 1
	if idx < 0 || idx >= len(cm.caseFindings) {
		cm.updateStatus("Select a finding to detach")
		return
	}
	f := cm.caseFindings[idx]

	modal := tview.NewModal().
		SetText(fmt.Sprintf("Detach %q from this case?\n\nThe finding is not deleted.", truncate(f.Title, 60))).
		AddButtons([]string{"Detach", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			cm.popModalRoot()
			if label != "Detach" {
				return
			}
			go func() {
				err := cm.store.RemoveCaseMember(cm.ctx, cm.caseData.ID, store.MemberTypeFinding, f.ID)
				cm.app.QueueUpdateDraw(func() {
					if err != nil {
						cm.updateStatus(fmt.Sprintf("Could not detach: %v", err))
						return
					}
					cm.updateStatus(fmt.Sprintf("Detached %s", truncate(f.Title, 40)))
					cm.loadCaseFindings()
					cm.renderBriefing()
				})
				// The audit trail carries what the case used to claim.
				_ = cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "finding_detached",
					cm.getCurrentAnalyst(), map[string]interface{}{"finding_id": f.ID, "title": f.Title})
			}()
		})
	cm.pushModalRoot(modal)
}
