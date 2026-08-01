package ui

import (
	"fmt"
	"os"
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
	ui.restoreEventsView()

	ui.app.SetFocus(ui.eventList)
	ui.eventList.Clear()
	ui.setFindingsHeaders()
	ui.eventList.SetCell(1, 0, tview.NewTableCell("Loading...").
		SetTextColor(ui.theme.TableRowMuted))
	ui.setStatusDirect("[%s]Loading findings...[-:-:-]", ui.theme.TagWarning)

	go ui.loadFindings()
}

// triageColumns returns the visible columns for the current width.
//
// §7 drops source first, then technique, then asset. The title never truncates
// below 30 columns, which is why it is never a candidate: a queue of unreadable
// titles is not a queue.
func (ui *UI) triageColumns() []string {
	all := []string{"!", "Risk", "Age", "Status", "Title", "Asset", "Tactic", "Source"}
	_, _, width, _ := ui.eventList.GetInnerRect()
	switch {
	case width >= 120:
		return all
	case width >= 100:
		return all[:7] // drop Source
	case width >= 84:
		return all[:6] // drop Tactic
	default:
		return all[:5] // drop Asset
	}
}

func (ui *UI) setFindingsHeaders() {
	headers := ui.triageColumns()
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

	// Filtering re-queries. It does not filter a loaded page in Go, which is
	// only correct while the page happens to be the whole result set.
	filter := ui.triageFilterState().storeFilter(time.Now(), triagePageSize, 0)
	findings, err := ui.store.GetFindings(ui.ctx, filter)
	if err != nil {
		ui.queueUpdate(func() {
			ui.findingsErr = err
			ui.updateFindingsList(0)
			ui.setStatusDirect("[%s]Error loading findings: %v[-:-:-]", ui.theme.TagError, err)
		})
		return
	}

	total, err := ui.store.CountFindings(ui.ctx, filter)
	if err != nil {
		total = len(findings)
	}

	// A second count, unfiltered. Without it an empty screen cannot say whether
	// there are no findings or whether the filter removed them all, and §7
	// forbids showing the first message when the second is true.
	unfiltered, err := ui.store.CountFindings(ui.ctx, store.FindingFilter{})
	if err != nil {
		unfiltered = total
	}

	ui.queueUpdate(func() {
		ui.findings = findings
		ui.findingsTotal = total
		ui.findingsUnfiltered = unfiltered
		ui.findingsErr = nil
		ui.updateFindingsList(total)
		ui.repaintTriageChrome()
		ui.setStatusDirect("[%s]%d of %d findings • %s[-:-:-]",
			ui.theme.TagSuccess, len(findings), unfiltered, ui.triageFilterState().describe())
	})
}

// triagePageSize bounds one query. §7: paginate, never load an unbounded set.
const triagePageSize = 200

// updateFindingsList renders the findings queue into the main table.
func (ui *UI) updateFindingsList(total int) {
	ui.eventList.Clear()
	ui.eventList.SetSelectedStyle(tcell.StyleDefault.
		Background(ui.theme.SelectionBg).Foreground(ui.theme.SelectionFg))
	ui.eventList.SetBorderColor(ui.theme.Border)

	ui.eventList.SetTitle(fmt.Sprintf(" FINDINGS  ·  %d of %d ", total, ui.findingsUnfiltered))
	ui.setFindingsHeaders()

	// One panel failing does not replace the screen, and the filters stay
	// usable so the analyst can narrow their way out of a slow query.
	if ui.findingsErr != nil {
		for i, line := range []string{
			"Could not load findings.",
			"",
			ui.findingsErr.Error(),
			"",
			"[r] Retry",
		} {
			ui.eventList.SetCell(1+i, 0, tview.NewTableCell(tview.Escape(line)).
				SetTextColor(ui.theme.TableRowMuted).SetExpansion(1).SetSelectable(false))
		}
		return
	}

	if len(ui.findings) == 0 {
		// Two distinct empty states. Telling an analyst there are no findings
		// when a filter removed them is telling them their data is gone.
		var hint []string
		switch emptyKind(len(ui.findings), ui.findingsUnfiltered) {
		case triageFilteredOut:
			hint = []string{
				"No findings match these filters.",
				"",
				ui.triageFilterState().describe(),
				"",
				"[F] Clear filters      [V] Next saved view",
			}
		default:
			hint = []string{
				"No findings yet.",
				"",
				"Findings are OCSF detections — class_uid 2001-2008, or any event with is_alert=true.",
				"They are what a SIEM or EDR emits when something is worth an analyst's attention.",
				"",
				fmt.Sprintf("Drop a Detection Finding into  %s  to see it here.", ui.watchedDir()),
				"Press  2  to browse all raw events instead.",
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

	// The ordering is the query's, not this function's. Sorting here would sort
	// only the page that happens to be loaded, which is right until the result
	// exceeds one page and then silently wrong.

	visible := len(ui.triageColumns())

	for i, f := range ui.findings {
		row := i + 1
		attack := strings.Join(f.AttackTechniques(), ", ")

		risk := "—"
		if f.RiskScore > 0 {
			risk = fmt.Sprintf("%d", f.RiskScore)
		}

		// Very basic asset/source extraction logic from metadata/raw json
		asset := "—"
		source := f.AnalyticName
		if source == "" {
			source = "—"
		}

		// If there is an IP or Hostname in Evidences, we could extract it, but
		// for now we'll put a placeholder or basic parse.
		if strings.Contains(f.EvidencesJSON, "hostname") {
			asset = "Endpoint" // naive placeholder
		}

		selPrefix := " "
		if ui.triageSelection().has(f.FindingUID) {
			selPrefix = "✓"
		}

		cells := []struct {
			text  string
			color tcell.Color
		}{
			{selPrefix + " " + formatSeverityBadge(f.Severity, ui.theme), ui.getSeverityTcellColor(f.Severity)},
			{risk, ui.theme.TextPrimary},
			{renderRelativeTime(f.LastSeen), ui.theme.TextMuted},
			{f.StatusName(), ui.findingStatusColor(f)},
			{f.Title, ui.theme.TextPrimary},
			{asset, ui.theme.TextMuted},
			{attack, ui.theme.TextMuted},
			{source, ui.theme.TextMuted},
		}
		for col, c := range cells {
			if col >= visible {
				break
			}
			cell := tview.NewTableCell(c.text).SetTextColor(c.color)
			if col == 4 { // Title is col 4
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
	// Named for what it holds. It said "Event Details" on a screen that shows
	// findings, which is the distinction the whole product turns on.
	ui.eventDetail.SetTitle(" SELECTED FINDING ")

	var b strings.Builder
	line := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		fmt.Fprintf(&b, "[%s]%-14s[-] %s\n", ui.theme.TagMuted, label+":", value)
	}

	// §7 order, identical to the inspector on Analyst Home so a finding reads
	// the same wherever it is seen: title, the one-line verdict, how it was
	// found, when — then why it matters, then the counts, and only then the
	// raw record. A human explanation always precedes the JSON.
	fmt.Fprintf(&b, "[%s]%s[-]\n\n", ui.theme.TagAccent, f.Title)

	risk := "—"
	if f.RiskScore > 0 {
		risk = fmt.Sprintf("%d", f.RiskScore)
	}
	fmt.Fprintf(&b, "[%s]risk[-] %s · %s · %s\n\n",
		ui.theme.TagMuted, risk, formatSeverityBadge(f.Severity, ui.theme), f.StatusName())

	line("Analytic", f.AnalyticName)
	line("First seen", f.FirstSeen.Format("2006-01-02 15:04:05"))
	line("Last seen", f.LastSeen.Format("2006-01-02 15:04:05"))

	// Why it matters, before any artifact list. The message is the producer's
	// own explanation; without it the analyst is reading JSON to find out what
	// the detection thought it saw.
	why := strings.TrimSpace(f.Message)
	if why == "" || why == f.Title {
		why = "No description was supplied by the producer."
	}
	fmt.Fprintf(&b, "\n[%s]WHY IT MATTERS[-]\n%s\n", ui.theme.TagMuted, why)

	// The counts, so the shape of the finding is legible before the detail.
	fmt.Fprintf(&b, "\n[%s]EVIDENCE[-] %d   [%s]INDICATORS[-] %d   [%s]RELATED EVENTS[-] %d\n",
		ui.theme.TagMuted, len(f.Evidences()),
		ui.theme.TagMuted, len(f.AttackTechniques()),
		ui.theme.TagMuted, len(f.RelatedEvents()))

	caseLabel := "none"
	if f.CaseID != "" {
		caseLabel = f.CaseID
	}
	fmt.Fprintf(&b, "[%s]RELATED CASES[-] %s\n", ui.theme.TagMuted, caseLabel)

	fmt.Fprintf(&b, "\n[%s]  j  raw OCSF[-]\n", ui.theme.TagAccent)

	// Reference detail below the summary, in the order it was.
	fmt.Fprintf(&b, "\n[%s]%s[-]\n", ui.theme.TagMuted, strings.Repeat("─", 30))
	line("Class", fmt.Sprintf("%s (%d)", f.ClassName(), f.ClassUID))
	if v := f.VerdictName(); v != "" {
		line("Verdict", v)
	}
	if f.ConfidenceID > 0 {
		line("Confidence", ocsf.ConfidenceName(f.ConfidenceID))
	}
	line("Finding UID", f.FindingUID)
	if f.Assignee != "" {
		line("Assignee", f.Assignee)
	}
	if f.IsSuspectedBreach {
		line("Breach", "SUSPECTED")
	}
	if techniques := f.AttackTechniques(); len(techniques) > 0 {
		line("ATT&CK", strings.Join(techniques, ", "))
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

// escalateFindingToCase turns the selected finding into case work.
//
// This is the hinge of the whole workflow: triage decides something matters, and
// escalation makes it an investigation. The finding joins as a member — the
// thing the case is *about* — while supporting events are attached separately
// as evidence.
func (ui *UI) escalateFindingToCase() {
	f, ok := ui.currentFinding()
	if !ok {
		ui.setStatusDirect("[%s]No finding selected[-:-:-]", ui.theme.TagWarning)
		return
	}

	existing, err := ui.store.ListCases(ui.ctx)
	if err != nil {
		ui.setStatusDirect("[%s]Could not load cases: %v[-:-:-]", ui.theme.TagError, err)
		return
	}

	form := tview.NewForm()
	form.SetTitle(" Escalate Finding to Case ").SetBorder(true)
	ui.applyFormTheme(form)

	// Offer the existing cases plus a new one, so a second detection in the same
	// incident lands in the case that is already open rather than starting another.
	options := []string{"— Create new case —"}
	for _, c := range existing {
		options = append(options, fmt.Sprintf("%s  (%s)", c.Title, c.Status))
	}

	target := 0
	form.AddDropDown("Case", options, 0, func(_ string, idx int) { target = idx })

	title := f.Title
	if len(title) > 60 {
		title = title[:60]
	}
	form.AddInputField("New case title", title, 60, nil, func(text string) { title = text })

	severities := []string{"low", "medium", "high", "critical"}
	severity := f.Severity
	sevIdx := 1
	for i, s := range severities {
		if s == severity {
			sevIdx = i
		}
	}
	form.AddDropDown("Severity", severities, sevIdx, func(text string, _ int) { severity = text })

	form.AddButton("Escalate", func() {
		ui.restoreMainLayout()
		go func() {
			caseID := ""
			if target > 0 && target-1 < len(existing) {
				caseID = existing[target-1].ID
			} else {
				newCase := store.Case{
					Title:       title,
					Description: "Escalated from finding: " + f.FindingUID,
					Severity:    severity,
					Status:      store.CaseStatusInvestigating,
					AssignedTo:  ui.currentAnalyst(),
				}
				id, err := ui.store.CreateOrUpdateCase(ui.ctx, newCase)
				if err != nil {
					ui.app.QueueUpdateDraw(func() {
						ui.setStatusDirect("[%s]Failed to create case: %v[-:-:-]", ui.theme.TagError, err)
					})
					return
				}
				caseID = id
			}

			if err := ui.store.AssignFindingToCase(ui.ctx, f.ID, caseID); err != nil {
				ui.app.QueueUpdateDraw(func() {
					ui.setStatusDirect("[%s]Failed to attach finding: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}

			// Escalating means someone is working it.
			if f.StatusID == ocsf.FindingStatusNew {
				_ = ui.store.UpdateFindingStatus(ui.ctx, f.ID, ocsf.FindingStatusInProgress)
			}
			_ = ui.store.LogCaseAction(ui.ctx, caseID, "finding_escalated", ui.currentAnalyst(),
				map[string]interface{}{"finding_uid": f.FindingUID, "title": f.Title})

			ui.app.QueueUpdateDraw(func() {
				ui.setStatusDirect("[%s]Finding attached to case[-:-:-]", ui.theme.TagSuccess)
			})
			ui.loadFindings()
			_ = ui.refreshCases()
		}()
	})
	form.AddButton("Cancel", func() { ui.restoreMainLayout() })

	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
}

// currentAnalyst returns the operator name recorded on audit entries.
func (ui *UI) currentAnalyst() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "analyst"
}

// repaintCurrentList re-renders the main table for whichever view is open,
// without touching the database.
//
// The findings queue and the events list share one table widget, so anything
// that re-renders it has to know which of the two is showing. applyTheme called
// updateEventsList unconditionally, which silently replaced a findings queue
// with events on every theme change — the detail pane kept showing the finding,
// because only the table was rebuilt.
func (ui *UI) repaintCurrentList() {
	// Home is not a list. Restyling it means rebuilding it against the new
	// theme, which is what re-entering it does.
	if ui.home != nil && ui.onHome() {
		ui.showAnalystHome()
		return
	}
	// The table may not exist yet: setTheme runs while restoring the persisted
	// choice, before the layout is assembled.
	if ui.eventList == nil {
		return
	}
	if ui.showFindings {
		ui.updateFindingsList(ui.findingsTotal)
		return
	}
	ui.updateEventsList()
}

// refreshCurrentView reloads the data behind whichever view is open.
//
// Same trap as repaintCurrentList, one level up: 'r' went straight to
// scheduleEventsReload, so refreshing the findings queue replaced it with
// events. Every user-initiated refresh should come through here.
func (ui *UI) refreshCurrentView(source string) {
	// Home owns its own panels and their loading states, so it refreshes itself
	// rather than being repainted from the event/finding loaders.
	if ui.home != nil && ui.onHome() {
		ui.home.refresh()
		return
	}
	if ui.showFindings {
		go ui.loadFindings()
		return
	}
	ui.scheduleEventsReload(source)
}

// toggleTriageChip flips one quick filter and re-queries.
//
// Re-queries rather than filters what is loaded: the loaded page is at most
// triagePageSize rows, so filtering it in Go answers correctly right up until
// the result is larger than one page, and then answers wrongly and silently.
func (ui *UI) toggleTriageChip(id chipID) {
	ui.triageFilterState().toggle(id)
	ui.repaintTriageChrome()
	go ui.loadFindings()
}

// clearTriageFilters returns to the default view.
func (ui *UI) clearTriageFilters() {
	f := ui.triageFilterState()
	f.applyView(0)
	f.search = ""
	ui.repaintTriageChrome()
	go ui.loadFindings()
}

// cycleTriageView moves to the next saved view.
func (ui *UI) cycleTriageView() {
	ui.triageFilterState().cycleView()
	ui.repaintTriageChrome()
	ui.setStatusDirect("[%s]View: %s[-:-:-]", ui.theme.TagAccent, ui.triageFilterState().viewName())
	go ui.loadFindings()
}
