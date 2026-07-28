package ui

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// contextFindings is the query context for the findings queue, alongside
// contextAll for events and a case ID for a specific case.
const contextFindings = "FINDINGS"

// jumpToFindings switches the main table to the findings triage queue.
//
// Findings are the analyst's unit of work: a queue of a dozen detections rather
// than thousands of log lines. ALL EVENTS remains available for raw-log triage.
func (ui *UI) jumpToFindings() {
	ui.showFindings = true
	ui.showAll = false
	ui.selectedCaseID = ""

	ui.app.SetFocus(ui.eventList)
	ui.eventList.Clear()
	ui.setFindingsHeaders()
	ui.eventList.SetCell(1, 0, tview.NewTableCell("Loading...").
		SetTextColor(ui.theme.TableRowMuted))
	ui.setStatusDirect("[%s]Loading findings...[-:-:-]", ui.theme.TagWarning)

	go ui.loadFindings()
}

func (ui *UI) setFindingsHeaders() {
	headers := []string{"Last Seen", "Sev", "Status", "Verdict", "Risk", "Title", "Analytic", "ATT&CK"}
	for col, header := range headers {
		ui.eventList.SetCell(0, col, tview.NewTableCell(header).
			SetTextColor(ui.theme.TableHeader).
			SetBackgroundColor(ui.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold))
	}
}

// loadFindings fetches the triage queue and renders it.
func (ui *UI) loadFindings() {
	if !atomic.CompareAndSwapInt32(&ui.loadingEvents, 0, 1) {
		return
	}
	atomic.StoreInt64(&ui.lastLoadStart, time.Now().UnixNano())
	defer func() {
		atomic.StoreInt32(&ui.loadingEvents, 0)
		atomic.StoreInt64(&ui.lastLoadStart, 0)
	}()

	defer func() {
		if r := recover(); r != nil {
			if ui.logger != nil {
				ui.logger.Printf("panic in loadFindings: %v", r)
			}
			ui.setStatusDirect("[%s]Error loading findings (recovered)[-:-:-]", ui.theme.TagError)
		}
	}()

	filter := store.FindingFilter{OpenOnly: ui.findingsOpenOnly}
	findings, err := ui.store.GetFindings(ui.ctx, filter)
	if err != nil {
		ui.app.QueueUpdateDraw(func() {
			ui.setStatusDirect("[%s]Error loading findings: %v[-:-:-]", ui.theme.TagError, err)
		})
		return
	}

	total, err := ui.store.CountFindings(ui.ctx, filter)
	if err != nil {
		total = len(findings)
	}

	ui.app.QueueUpdateDraw(func() {
		ui.findings = findings
		ui.updateFindingsList(total)
		scope := "all"
		if ui.findingsOpenOnly {
			scope = "open"
		}
		ui.setStatusDirect("[%s]%d findings (%s) • s: status • v: verdict • o: open/all • Enter: details[-:-:-]",
			ui.theme.TagSuccess, len(findings), scope)
	})
}

// updateFindingsList renders the findings queue into the main table.
func (ui *UI) updateFindingsList(total int) {
	ui.eventList.Clear()
	ui.eventList.SetSelectedStyle(tcell.StyleDefault.
		Background(ui.theme.SelectionBg).Foreground(ui.theme.SelectionFg))
	ui.eventList.SetBorderColor(ui.theme.Border)

	scope := "All"
	if ui.findingsOpenOnly {
		scope = "Open"
	}
	ui.eventList.SetTitle(fmt.Sprintf(" Findings (%s, %d) ", scope, total))
	ui.setFindingsHeaders()

	if len(ui.findings) == 0 {
		hint := []string{
			"No findings yet.",
			"",
			"Findings are OCSF detections — class_uid 2001-2008, or any event with is_alert=true.",
			"They are what a SIEM or EDR emits when something is worth an analyst's attention.",
			"",
			"Drop a Detection Finding into  data/incoming/  to see it here.",
			"Press  A  to browse all raw events instead.",
		}
		if ui.findingsOpenOnly {
			hint = []string{
				"No open findings.",
				"",
				"Everything has been triaged. Press  o  to include resolved and suppressed findings.",
			}
		}
		for i, line := range hint {
			cell := tview.NewTableCell(line).
				SetTextColor(ui.theme.TableRowMuted).
				SetExpansion(1)
			if i == 0 {
				cell.SetAttributes(tcell.AttrBold)
			}
			ui.eventList.SetCell(1+i, 0, cell)
		}
		return
	}

	// Highest risk first, then most recent: the queue should put what matters at
	// the top rather than making the analyst sort it themselves.
	sort.SliceStable(ui.findings, func(i, j int) bool {
		a, b := ui.findings[i], ui.findings[j]
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if a.SeverityID != b.SeverityID {
			return a.SeverityID > b.SeverityID
		}
		return a.LastSeen.After(b.LastSeen)
	})

	for i, f := range ui.findings {
		row := i + 1
		attack := strings.Join(f.AttackTechniques(), ", ")

		verdict := f.VerdictName()
		if verdict == "" {
			verdict = "—"
		}
		risk := "—"
		if f.RiskScore > 0 {
			risk = fmt.Sprintf("%d", f.RiskScore)
		}

		cells := []struct {
			text  string
			color tcell.Color
		}{
			{f.LastSeen.Format("01-02 15:04"), ui.theme.TextMuted},
			{strings.ToUpper(shortSeverity(f.Severity)), ui.getSeverityTcellColor(f.Severity)},
			{f.StatusName(), ui.findingStatusColor(f)},
			{verdict, ui.findingVerdictColor(f)},
			{risk, ui.theme.TextPrimary},
			{f.Title, ui.theme.TextPrimary},
			{f.AnalyticName, ui.theme.TextMuted},
			{attack, ui.theme.TextMuted},
		}
		for col, c := range cells {
			cell := tview.NewTableCell(c.text).SetTextColor(c.color)
			if col == 5 {
				cell.SetExpansion(1)
			}
			ui.eventList.SetCell(row, col, cell)
		}
	}

	if ui.eventList.GetRowCount() > 1 {
		ui.eventList.Select(1, 0)
	}
}

func shortSeverity(sev string) string {
	if sev == "" {
		return "?"
	}
	if len(sev) > 4 {
		return sev[:4]
	}
	return sev
}

// findingStatusColor encodes triage state in colour so the queue reads at a
// glance: untouched work stands out, finished work recedes.
func (ui *UI) findingStatusColor(f store.Finding) tcell.Color {
	switch f.StatusID {
	case ocsf.FindingStatusNew:
		return ui.theme.Accent
	case ocsf.FindingStatusInProgress:
		return ui.theme.TextPrimary
	default:
		return ui.theme.TableRowMuted
	}
}

func (ui *UI) findingVerdictColor(f store.Finding) tcell.Color {
	switch f.VerdictID {
	case ocsf.VerdictTruePositive, ocsf.VerdictSecurityRisk:
		return ui.getSeverityTcellColor("critical")
	case ocsf.VerdictFalsePositive, ocsf.VerdictBenign:
		return ui.theme.TableRowMuted
	case ocsf.VerdictSuspicious:
		return ui.getSeverityTcellColor("high")
	default:
		return ui.theme.TextMuted
	}
}

// currentFinding returns the finding under the cursor.
func (ui *UI) currentFinding() (store.Finding, bool) {
	row, _ := ui.eventList.GetSelection()
	if row > 0 && row-1 < len(ui.findings) {
		return ui.findings[row-1], true
	}
	return store.Finding{}, false
}

// showFindingDetails renders the selected finding in the detail pane, including
// the evidence and related events that connect it back to telemetry.
func (ui *UI) showFindingDetails() {
	f, ok := ui.currentFinding()
	if !ok {
		return
	}
	ui.selectedFindingID = f.ID

	var b strings.Builder
	line := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		fmt.Fprintf(&b, "[%s]%-14s[-] %s\n", ui.theme.TagMuted, label+":", value)
	}

	fmt.Fprintf(&b, "[%s]%s[-]\n\n", ui.theme.TagAccent, f.Title)

	line("Class", fmt.Sprintf("%s (%d)", f.ClassName(), f.ClassUID))
	line("Status", f.StatusName())
	if v := f.VerdictName(); v != "" {
		line("Verdict", v)
	}
	line("Severity", f.Severity)
	if f.RiskScore > 0 {
		line("Risk score", fmt.Sprintf("%d", f.RiskScore))
	}
	if f.ConfidenceID > 0 {
		line("Confidence", ocsf.ConfidenceName(f.ConfidenceID))
	}
	line("Analytic", f.AnalyticName)
	line("Finding UID", f.FindingUID)
	line("First seen", f.FirstSeen.Format("2006-01-02 15:04:05"))
	line("Last seen", f.LastSeen.Format("2006-01-02 15:04:05"))
	if f.Assignee != "" {
		line("Assignee", f.Assignee)
	}
	if f.IsSuspectedBreach {
		line("Breach", "SUSPECTED")
	}
	if f.CaseID != "" {
		line("Case", f.CaseID)
	}

	if techniques := f.AttackTechniques(); len(techniques) > 0 {
		line("ATT&CK", strings.Join(techniques, ", "))
	}

	if f.Message != "" && f.Message != f.Title {
		fmt.Fprintf(&b, "\n[%s]Message[-]\n%s\n", ui.theme.TagMuted, f.Message)
	}

	// Evidence artifacts: what the detection actually saw.
	if ev := f.Evidences(); len(ev) > 0 {
		fmt.Fprintf(&b, "\n[%s]Evidence (%d)[-]\n", ui.theme.TagAccent, len(ev))
		for _, e := range ev {
			label := e.Name
			if label == "" {
				label = "evidence"
			}
			verdict := ""
			if e.Verdict != "" {
				verdict = "  [" + e.Verdict + "]"
			}
			fmt.Fprintf(&b, "  • %s%s\n", label, verdict)
			if e.Process != nil && e.Process.Name != "" {
				fmt.Fprintf(&b, "      process: %s", e.Process.Name)
				if e.Process.CommandLine != "" {
					fmt.Fprintf(&b, "  %s", e.Process.CommandLine)
				}
				b.WriteString("\n")
			}
			if e.File != nil && e.File.Name != "" {
				fmt.Fprintf(&b, "      file: %s\n", e.File.Name)
			}
			if e.SrcEndpoint != nil && e.SrcEndpoint.IP != "" {
				fmt.Fprintf(&b, "      src: %s\n", e.SrcEndpoint.IP)
			}
			if e.DstEndpoint != nil && e.DstEndpoint.IP != "" {
				fmt.Fprintf(&b, "      dst: %s\n", e.DstEndpoint.IP)
			}
			if e.User != nil && e.User.Name != "" {
				fmt.Fprintf(&b, "      user: %s\n", e.User.Name)
			}
		}
	}

	// related_events is OCSF's documented route from a finding back to the
	// telemetry the analytic examined.
	if rel := f.RelatedEvents(); len(rel) > 0 {
		fmt.Fprintf(&b, "\n[%s]Related events (%d)[-]\n", ui.theme.TagAccent, len(rel))
		for _, r := range rel {
			fmt.Fprintf(&b, "  • %s", r.UID)
			if r.TypeUID != 0 {
				fmt.Fprintf(&b, "  (type_uid %d)", r.TypeUID)
			}
			b.WriteString("\n")
		}
	}

	// Indicators, from the observables table.
	if obs, err := ui.store.GetObservablesByFinding(ui.ctx, f.ID); err == nil && len(obs) > 0 {
		fmt.Fprintf(&b, "\n[%s]Observables (%d)[-]\n", ui.theme.TagAccent, len(obs))
		for _, o := range obs {
			src := "derived"
			if o.IsAsserted() {
				src = "asserted"
			}
			fmt.Fprintf(&b, "  • %-14s %s  [%s]\n", o.Type, o.Value, src)
		}
	}

	ui.eventDetail.SetText(b.String())
	ui.eventDetail.ScrollToBeginning()
}

// showFindingStatusModal lets the analyst move a finding through triage.
func (ui *UI) showFindingStatusModal() {
	f, ok := ui.currentFinding()
	if !ok {
		ui.setStatusDirect("[%s]No finding selected[-:-:-]", ui.theme.TagWarning)
		return
	}

	statuses := ocsf.FindingStatuses(f.ClassUID)
	labels := make([]string, len(statuses))
	current := 0
	for i, s := range statuses {
		labels[i] = ocsf.FindingStatusName(f.ClassUID, s)
		if s == f.StatusID {
			current = i
		}
	}

	form := tview.NewForm()
	form.SetTitle(" Set Finding Status ").SetBorder(true)
	ui.applyFormTheme(form)

	selected := current
	form.AddDropDown("Status", labels, current, func(_ string, idx int) { selected = idx })
	form.AddButton("Save", func() {
		if selected < 0 || selected >= len(statuses) {
			ui.restoreMainLayout()
			return
		}
		statusID := statuses[selected]
		go func() {
			if err := ui.store.UpdateFindingStatus(ui.ctx, f.ID, statusID); err != nil {
				ui.app.QueueUpdateDraw(func() {
					ui.setStatusDirect("[%s]Failed to set status: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}
			ui.app.QueueUpdateDraw(func() {
				ui.setStatusDirect("[%s]Status set to %s[-:-:-]",
					ui.theme.TagSuccess, ocsf.FindingStatusName(f.ClassUID, statusID))
			})
			ui.loadFindings()
		}()
		ui.restoreMainLayout()
	})
	form.AddButton("Cancel", func() { ui.restoreMainLayout() })

	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
}

// showFindingVerdictModal records the analyst's true/false-positive judgement.
func (ui *UI) showFindingVerdictModal() {
	f, ok := ui.currentFinding()
	if !ok {
		ui.setStatusDirect("[%s]No finding selected[-:-:-]", ui.theme.TagWarning)
		return
	}

	verdicts := ocsf.Verdicts()
	labels := make([]string, len(verdicts))
	current := 0
	for i, v := range verdicts {
		labels[i] = ocsf.VerdictName(v)
		if v == f.VerdictID {
			current = i
		}
	}

	form := tview.NewForm()
	form.SetTitle(" Set Verdict ").SetBorder(true)
	ui.applyFormTheme(form)

	selected := current
	form.AddDropDown("Verdict", labels, current, func(_ string, idx int) { selected = idx })
	form.AddButton("Save", func() {
		if selected < 0 || selected >= len(verdicts) {
			ui.restoreMainLayout()
			return
		}
		verdictID := verdicts[selected]
		go func() {
			if err := ui.store.UpdateFindingVerdict(ui.ctx, f.ID, verdictID); err != nil {
				ui.app.QueueUpdateDraw(func() {
					ui.setStatusDirect("[%s]Failed to set verdict: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}
			ui.app.QueueUpdateDraw(func() {
				ui.setStatusDirect("[%s]Verdict set to %s[-:-:-]",
					ui.theme.TagSuccess, ocsf.VerdictName(verdictID))
			})
			ui.loadFindings()
		}()
		ui.restoreMainLayout()
	})
	form.AddButton("Cancel", func() { ui.restoreMainLayout() })

	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
}

// toggleFindingsScope switches between open findings and everything.
func (ui *UI) toggleFindingsScope() {
	ui.findingsOpenOnly = !ui.findingsOpenOnly
	go ui.loadFindings()
}

// applyFormTheme styles a modal form consistently with the rest of the TUI.
func (ui *UI) applyFormTheme(form *tview.Form) {
	form.SetBackgroundColor(ui.theme.Surface)
	form.SetFieldBackgroundColor(ui.theme.Surface)
	form.SetFieldTextColor(ui.theme.TextPrimary)
	form.SetLabelColor(ui.theme.TextPrimary)
	form.SetButtonBackgroundColor(ui.theme.SelectionBg)
	form.SetButtonTextColor(ui.theme.SelectionFg)
	form.SetBorderColor(ui.theme.FocusBorder)
	form.SetTitleColor(ui.theme.Accent)
}
