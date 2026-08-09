package ui

import (
	"fmt"
	"os"
	"strings"
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
	// The context flags come from the destination table via beginScreen. Set
	// here as well, four functions kept four copies of the same three lines.
	ui.restoreEventsView()

	ui.app.SetFocus(ui.eventList)
	ui.eventList.Clear()
	ui.setFindingsHeaders()
	ui.eventList.SetCell(1, 0, tview.NewTableCell("Loading...").
		SetTextColor(ui.theme.TableRowMuted))
	ui.setStatusDirect("[%s]Loading findings...[-:-:-]", ui.theme.TagWarning)

	ui.spawnLoad(ui.loadFindings)
}

// triageColumn is one column of the queue and the width at which it earns its
// space.
type triageColumn struct {
	title string
	// minWidth is the pane width from which this column is drawn. Zero means
	// always: the first four say what the finding is and how urgent, and Title
	// says what happened, so a queue without them is not a queue.
	minWidth int
	// expand gives the column the pane's slack.
	expand bool
}

// triageColumnSet is every column, in display order.
//
// Display order and drop order used to be the same thing — the ladder returned
// a prefix of one slice — which meant a column could only be added at the end,
// where it is also the first to go. Case belongs beside Status and is worth
// more than Asset or Tactic, so the two orders are now separate: this slice is
// what the analyst reads left to right, and minWidth is what survives a narrow
// terminal.
func triageColumnSet() []triageColumn {
	return []triageColumn{
		{title: "!"},
		{title: "Risk"},
		{title: "Age"},
		{title: "Status"},
		{title: "Case", minWidth: 96},
		{title: "Title", expand: true},
		{title: "Asset", minWidth: 84},
		{title: "Tactic", minWidth: 108},
		{title: "Source", minWidth: 124},
	}
}

// triageColumns returns the visible columns for the current width.
func (ui *UI) triageColumns() []triageColumn {
	_, _, width, _ := ui.eventList.GetInnerRect()
	out := make([]triageColumn, 0, len(triageColumnSet()))
	for _, c := range triageColumnSet() {
		if width >= c.minWidth {
			out = append(out, c)
		}
	}
	return out
}

func (ui *UI) setFindingsHeaders() {
	for col, c := range ui.triageColumns() {
		ui.eventList.SetCell(0, col, tview.NewTableCell(c.title).
			SetTextColor(ui.theme.TableHeader).
			SetBackgroundColor(ui.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold))
	}
}

// triageCell is one rendered value.
type triageCell struct {
	text  string
	color tcell.Color
}

// triageRow renders one finding's cells, by column title.
//
// By title rather than by position: the cells were a slice indexed against the
// column list, with the title's expansion applied to "col == 4" — so inserting
// a column silently moved the expansion onto whatever landed there.
func (ui *UI) triageRow(f store.Finding) map[string]triageCell {
	t := ui.theme

	sel := " "
	if ui.triageSelection().has(f.FindingUID) {
		sel = "✓"
	}
	risk := "—"
	if f.RiskScore > 0 {
		risk = fmt.Sprintf("%d", f.RiskScore)
	}

	return map[string]triageCell{
		"!":      {sel + " " + formatSeverityBadge(f.Severity, t), ui.getSeverityTcellColor(f.Severity)},
		"Risk":   {risk, t.TextPrimary},
		"Age":    {renderRelativeTime(f.LastSeen), t.TextMuted},
		"Status": {f.StatusName(), ui.findingStatusColor(f)},
		"Case":   ui.triageCaseCell(f),
		"Title":  {f.Title, t.TextPrimary},
		"Asset":  {orDash(ui.findingAsset[f.ID]), t.TextMuted},
		"Tactic": {orDash(strings.Join(f.AttackTechniques(), ", ")), t.TextMuted},
		"Source": {orDash(f.AnalyticName), t.TextMuted},
	}
}

// triageCaseCell says whether a finding is already someone's work.
//
// The queue could not answer that without opening each finding in turn, and it
// is the first thing worth knowing about a detection: an escalated finding is
// being handled, and triaging it again is duplicated work. The case's title
// comes from the page's own lookup; the identifier alone would be no answer.
func (ui *UI) triageCaseCell(f store.Finding) triageCell {
	if strings.TrimSpace(f.CaseID) == "" {
		return triageCell{"—", ui.theme.TextMuted}
	}
	if title := ui.findingCase[f.CaseID]; title != "" {
		return triageCell{truncate(title, triageCaseWidth), ui.theme.Accent}
	}
	// The case exists but its title has not been read. Say that it is in one
	// rather than showing a UUID no one recognises.
	return triageCell{"in a case", ui.theme.Accent}
}

// triageCaseWidth bounds the Case column. Long enough to tell two cases apart,
// short enough that it never competes with the title.
const triageCaseWidth = 16

// findingCases is the title of each case the loaded page belongs to.
//
// One query per distinct case on the page, which for a triage queue is a
// handful — most findings are in no case at all, which is the point of the
// column.
func (ui *UI) findingCases(findings []store.Finding) map[string]string {
	out := map[string]string{}
	if ui.store == nil {
		return out
	}
	for _, f := range findings {
		id := strings.TrimSpace(f.CaseID)
		if id == "" {
			continue
		}
		if _, done := out[id]; done {
			continue
		}
		c, err := ui.store.GetCase(ui.ctx, id)
		if err != nil || c == nil {
			// Recorded as seen so a missing case is not looked up once per row.
			out[id] = ""
			continue
		}
		out[id] = c.Title
	}
	return out
}

// loadFindings fetches the triage queue and renders it.
func (ui *UI) loadFindings() {
	// The findings queue's own guard. It shared one with the events list, so a
	// findings load in flight silently cancelled an events load and vice versa.
	if !ui.findingsLoad.begin() {
		return
	}
	defer ui.findingsLoad.end()

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

	// The host or user each detection fired on, one query for the page.
	//
	// The column read the evidence artifacts, and a producer need not supply
	// any — the demo dataset supplies none at all — so it was a dash on every
	// row while the inspector beside it listed the host from the observables.
	assets := ui.findingAssets(findings)
	cases := ui.findingCases(findings)

	ui.queueUpdate(func() {
		ui.findings = findings
		ui.findingAsset = assets
		ui.findingCase = cases
		ui.findingsTotal = total
		ui.findingsUnfiltered = unfiltered
		ui.findingsErr = nil
		ui.updateFindingsList(total)
		ui.repaintTriageChrome()
		ui.setStatusDirect("[%s]%d of %d findings • %s[-:-:-]",
			ui.theme.TagSuccess, len(findings), unfiltered, ui.triageFilterState().describe())
	})
}

// findingsTitle says how many findings are shown and why the rest are not.
//
// It read "%d of %d", which is how a pager reads — so a queue of ten under an
// Open filter, in a database of fifteen, looked like page one of two with five
// findings unaccounted for. They are not on another page; they are filtered out.
func (ui *UI) findingsTitle(shown int) string {
	title := fmt.Sprintf("FINDINGS  ·  %d", shown)
	if hidden := ui.findingsUnfiltered - shown; hidden > 0 {
		title = fmt.Sprintf("FINDINGS  ·  %d shown  ·  %d hidden by filters", shown, hidden)
	}
	return title + ui.droppedColumnSuffix()
}

// droppedColumnSuffix says how many columns the terminal is too narrow for.
//
// The queue drops columns rather than scrolling sideways — there is nothing off
// to the right to scroll to — and until now it dropped them silently, so a
// narrow terminal was indistinguishable from a build without those columns.
// Worded to stay apart from the filter count beside it: rows are hidden, and
// columns do not fit.
func (ui *UI) droppedColumnSuffix() string {
	_, _, width, _ := ui.eventList.GetInnerRect()
	if width <= 0 {
		// Never drawn. The column set is a guess at this point, so it is not
		// something to report.
		return ""
	}
	dropped := len(triageColumnSet()) - len(ui.triageColumns())
	if dropped <= 0 {
		return ""
	}
	if dropped == 1 {
		return "  ·  1 column dropped to fit"
	}
	return fmt.Sprintf("  ·  %d columns dropped to fit", dropped)
}

// triagePageSize bounds one query. §7: paginate, never load an unbounded set.
const triagePageSize = 200

// updateFindingsList renders the findings queue into the main table.
func (ui *UI) updateFindingsList(total int) {
	// The filter panel, if it is open over the queue, counts what this query
	// returned. Deferred because the two empty states return early, and a
	// filter that matches nothing is exactly when the count is worth reading.
	defer ui.filterModal.refreshCount()

	// Where the cursor was, before the table is torn down.
	//
	// This function repaints for reasons that are not a reload — marking a
	// finding with Space, a theme change — and every one of them sent the
	// cursor back to the top, so marking the fifth finding meant scrolling back
	// down to reach the sixth.
	wasOn := ""
	if row, _ := ui.eventList.GetSelection(); row > 0 && row-1 < len(ui.findings) {
		wasOn = ui.findings[row-1].ID
	}

	ui.eventList.Clear()
	ui.eventList.SetSelectedStyle(tcell.StyleDefault.
		Background(ui.theme.SelectionBg).Foreground(ui.theme.SelectionFg))
	ui.eventList.SetBorderColor(ui.theme.Border)

	ui.eventList.SetTitle(" " + ui.findingsTitle(total) + " ")
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
			// Escaped: a table cell parses colour tags, so "[F]" is read as one
			// and disappears — taking with it the only instruction on screen.
			cell := tview.NewTableCell(tview.Escape(line)).
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

	columns := ui.triageColumns()

	for i, f := range ui.findings {
		row := i + 1
		values := ui.triageRow(f)
		for col, c := range columns {
			v := values[c.title]
			cell := tview.NewTableCell(v.text).SetTextColor(v.color)
			if c.expand {
				cell.SetExpansion(1)
			}
			ui.eventList.SetCell(row, col, cell)
		}
	}

	ui.selectLoadedFinding(wasOn)
}

// selectLoadedFinding puts the cursor on the finding another screen asked for,
// falling back to the top of the queue.
func (ui *UI) selectLoadedFinding(wasOn string) {
	if ui.eventList.GetRowCount() <= 1 {
		return
	}

	// A finding another screen asked for wins: it is an explicit request, and
	// it only survives one repaint.
	want := ui.pendingFindingID
	ui.pendingFindingID = ""

	// Otherwise stay where the analyst left the cursor, if that finding is
	// still in the list. It will not be after a filter change, which is the one
	// case where the top of the queue is the right answer.
	if want == "" {
		want = wasOn
	}

	if want != "" {
		for i, f := range ui.findings {
			if f.ID == want {
				ui.eventList.Select(i+1, 0)
				return
			}
		}
	}
	ui.eventList.Select(1, 0)
}

// findingAssets is the host or user each finding fired on, by finding id.
//
// From the observables, in one query for the whole page. The column used to
// read the evidence artifacts, which a producer need not supply — the demo
// dataset supplies none — so it was a dash on every row while the inspector
// beside it listed the host. Before that it held the literal string "Endpoint"
// whenever the raw JSON happened to contain the substring "hostname".
func (ui *UI) findingAssets(findings []store.Finding) map[string]string {
	out := map[string]string{}
	if ui.store == nil || len(findings) == 0 {
		return out
	}

	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	byFinding, err := ui.store.GetObservablesForFindings(ui.ctx, ids)
	if err != nil {
		ui.logger.Warn("triage: could not read finding observables: %v", err)
		return out
	}

	for id, obs := range byFinding {
		if v := preferredAsset(obs); v != "" {
			out[id] = v
		}
	}
	return out
}

// preferredAsset picks the one observable worth a column.
//
// A host first: "which machine" is the question after "what happened". Then the
// user, then an address — in the order an analyst would ask.
func preferredAsset(obs []store.Observable) string {
	for _, want := range []int{
		ocsf.ObservableTypeHostname,
		ocsf.ObservableTypeUserName,
		ocsf.ObservableTypeIPAddress,
	} {
		for _, o := range obs {
			if o.TypeID == want && strings.TrimSpace(o.Value) != "" {
				return o.Value
			}
		}
	}
	return ""
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

// currentFinding returns the finding under the cursor.
func (ui *UI) currentFinding() (store.Finding, bool) {
	// Whichever screen is showing owns the answer. Escalation and verdicts both
	// act on "the selected finding", and that used to mean Triage's table
	// specifically — so pressing e on the dashboard interrogated an empty table
	// and reported that nothing was selected.
	if ui.destination == destHome && ui.home != nil {
		if f := ui.home.selectedFinding(); f != nil {
			return *f, true
		}
		return store.Finding{}, false
	}
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

	// The head is the shared renderer — the same one the dashboard uses, so a
	// finding reads identically wherever it is seen. It replaced a second
	// implementation that showed strictly less: no indicator prevalence, ATT&CK
	// as bare comma-joined identifiers, the raw case identifier instead of the
	// case's name, two identical timestamps under different labels, and no
	// escaping at all, so a title containing a bracket was read as a colour tag.
	r := findingInspector{
		theme: ui.theme,
		width: ui.inspectorWidth(),
		// Triage's pane is the full height of the screen rather than a fifteen
		// row panel, so the producer's description is not squeezed into two.
		narrativeLines: triageNarrativeLines,
	}

	var b strings.Builder
	b.WriteString(r.render(f, ui.findingInspect.get(f.ID)))
	b.WriteString("\n")
	ui.appendFindingDetail(&b, f)

	ui.eventDetail.SetText(b.String())
	ui.eventDetail.ScrollToBeginning()
}

// triageNarrativeLines is how much of the producer's description Triage shows.
const triageNarrativeLines = 6

// inspectorWidth is the detail pane's width for the current layout.
//
// From the layout rather than the widget: tview reports the previous frame's
// rect, so asking the widget gives an answer one repaint out of date.
func (ui *UI) inspectorWidth() int {
	main := ui.termWidth
	if main <= 0 {
		// Before the first frame. Ask the widget — stale, but better than a
		// constant once anything has been drawn at all.
		if ui.eventDetail != nil {
			if _, _, w, _ := ui.eventDetail.GetInnerRect(); w > 0 {
				return w
			}
		}
		return 60
	}
	if ui.navRailVisible() {
		main -= navRailWidth
	}

	// The detail pane is one third of the body beside the list, or the full
	// width beneath it — see restoreEventsView, which builds both arrangements
	// from the same 2:1 ratio.
	w := main / 3
	if ui.currentLayoutMode != LayoutWide {
		w = main
	}
	if w < 40 {
		return 40
	}
	return w - 2
}

// findingSelectionChanged repaints the inspector and, once the cursor settles,
// asks for the context the record does not carry.
//
// The queries used to run inline on the UI goroutine from the table's selection
// callback — one GetObservablesByFinding per row while an arrow key was held.
func (ui *UI) findingSelectionChanged() {
	ui.showFindingDetails()

	f, ok := ui.currentFinding()
	if !ok {
		return
	}
	id := f.ID
	ui.findingInspect.schedule(f.ID, f.CaseID, func() {
		if sel, ok := ui.currentFinding(); ok && sel.ID == id {
			ui.showFindingDetails()
		}
	})
}

// appendFindingDetail writes the long form below the shared head: the artifacts
// the detection saw, the telemetry it came from, and the record's identifiers.
//
// This is what Triage has that the dashboard does not, and the reason it has a
// pane rather than a panel.
func (ui *UI) appendFindingDetail(b *strings.Builder, f store.Finding) {
	t := ui.theme
	line := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		fmt.Fprintf(b, "[%s]%-14s[-] %s\n", t.TagMuted, label+":", tview.Escape(value))
	}

	fmt.Fprintf(b, "\n[%s]%s[-]\n", t.TagMuted, strings.Repeat("─", 30))
	line("Class", fmt.Sprintf("%s (%d)", f.ClassName(), f.ClassUID))
	line("Finding UID", f.FindingUID)
	if f.IsSuspectedBreach {
		line("Breach", "SUSPECTED")
	}

	// Evidence artifacts: what the detection actually saw.
	if ev := f.Evidences(); len(ev) > 0 {
		// OCSF's own display name for finding_info.evidences. "Evidence" alone
		// collides with the case tab one keystroke away, which holds events —
		// these are artifacts.
		fmt.Fprintf(b, "\n[%s]Evidence Artifacts (%d)[-]\n", t.TagAccent, len(ev))
		for _, e := range ev {
			label := e.Name
			if label == "" {
				label = "evidence"
			}
			verdict := ""
			if e.Verdict != "" {
				verdict = "  [" + e.Verdict + "]"
			}
			fmt.Fprintf(b, "  • %s%s\n", tview.Escape(label), tview.Escape(verdict))
			if e.Process != nil && e.Process.Name != "" {
				fmt.Fprintf(b, "      process: %s", tview.Escape(e.Process.Name))
				if e.Process.CommandLine != "" {
					fmt.Fprintf(b, "  %s", tview.Escape(e.Process.CommandLine))
				}
				b.WriteString("\n")
			}
			if e.File != nil && e.File.Name != "" {
				fmt.Fprintf(b, "      file: %s\n", tview.Escape(e.File.Name))
			}
			if e.SrcEndpoint != nil && e.SrcEndpoint.IP != "" {
				fmt.Fprintf(b, "      src: %s\n", tview.Escape(e.SrcEndpoint.IP))
			}
			if e.DstEndpoint != nil && e.DstEndpoint.IP != "" {
				fmt.Fprintf(b, "      dst: %s\n", tview.Escape(e.DstEndpoint.IP))
			}
			if e.User != nil && e.User.Name != "" {
				fmt.Fprintf(b, "      user: %s\n", tview.Escape(e.User.Name))
			}
		}
	}

	// related_events is OCSF's documented route from a finding back to the
	// telemetry the analytic examined.
	if rel := f.RelatedEvents(); len(rel) > 0 {
		fmt.Fprintf(b, "\n[%s]Related events (%d)[-]\n", t.TagAccent, len(rel))
		for _, r := range rel {
			fmt.Fprintf(b, "  • %s", tview.Escape(r.UID))
			if r.TypeUID != 0 {
				fmt.Fprintf(b, "  (type_uid %d)", r.TypeUID)
			}
			b.WriteString("\n")
		}
	}
}

// showFindingStatusModal lets the analyst move findings through triage.
//
// It acts on the marked findings when any are marked, and on the cursor row
// otherwise — which is what the selection strip above the queue has always
// advertised, and what it never did.
func (ui *UI) showFindingStatusModal() {
	targets := ui.triageTargets()
	if len(targets) == 0 {
		ui.setStatusDirect("[%s]No finding selected[-:-:-]", ui.theme.TagWarning)
		return
	}
	f := targets[0]

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
	form.SetTitle(fmt.Sprintf(" Set Status · %s ", plural(len(targets), "finding"))).SetBorder(true)
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
			done, failed := 0, 0
			for _, target := range targets {
				if err := ui.store.UpdateFindingStatus(ui.ctx, target.ID, statusID); err != nil {
					failed++
					continue
				}
				done++
			}
			ui.queueUpdate(func() {
				if done == 0 {
					ui.setStatusDirect("[%s]Failed to set status on %s[-:-:-]",
						ui.theme.TagError, plural(failed, "finding"))
					return
				}
				ui.triageSelection().clear()
				name := ocsf.FindingStatusName(f.ClassUID, statusID)
				if failed > 0 {
					ui.setStatusDirect("[%s]%s set to %s, %d could not be[-:-:-]",
						ui.theme.TagWarning, plural(done, "finding"), name, failed)
					return
				}
				ui.setStatusDirect("[%s]%s set to %s[-:-:-]",
					ui.theme.TagSuccess, plural(done, "finding"), name)
			})
			ui.loadFindings()
		}()
		ui.restoreMainLayout()
	})
	form.AddButton("Cancel", func() { ui.restoreMainLayout() })

	ui.overlayForm(form, 64)
}

// showFindingVerdictModal records the analyst's true/false-positive judgement,
// on the marked findings or on the cursor row.
func (ui *UI) showFindingVerdictModal() {
	targets := ui.triageTargets()
	if len(targets) == 0 {
		ui.setStatusDirect("[%s]No finding selected[-:-:-]", ui.theme.TagWarning)
		return
	}
	f := targets[0]

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
	form.SetTitle(fmt.Sprintf(" Set Verdict · %s ", plural(len(targets), "finding"))).SetBorder(true)
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
			done, failed := 0, 0
			for _, target := range targets {
				if err := ui.store.UpdateFindingVerdict(ui.ctx, target.ID, verdictID); err != nil {
					failed++
					continue
				}
				done++
			}
			ui.queueUpdate(func() {
				if done == 0 {
					ui.setStatusDirect("[%s]Failed to set a verdict on %s[-:-:-]",
						ui.theme.TagError, plural(failed, "finding"))
					return
				}
				ui.triageSelection().clear()
				name := ocsf.VerdictName(verdictID)
				if failed > 0 {
					ui.setStatusDirect("[%s]%s set to %s, %d could not be[-:-:-]",
						ui.theme.TagWarning, plural(done, "finding"), name, failed)
					return
				}
				ui.setStatusDirect("[%s]%s set to %s[-:-:-]",
					ui.theme.TagSuccess, plural(done, "finding"), name)
			})
			ui.loadFindings()
		}()
		ui.restoreMainLayout()
	})
	form.AddButton("Cancel", func() { ui.restoreMainLayout() })

	ui.overlayForm(form, 64)
}

// toggleFindingsScope switches between open findings and everything.
func (ui *UI) toggleFindingsScope() {
	ui.findingsOpenOnly = !ui.findingsOpenOnly
	ui.spawnLoad(ui.loadFindings)
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
// escalateFindingToCase escalates whatever the cursor is on.
func (ui *UI) escalateFindingToCase() {
	f, ok := ui.currentFinding()
	if !ok {
		ui.setStatusDirect("[%s]No finding selected[-:-:-]", ui.theme.TagWarning)
		return
	}
	ui.escalateFindings([]store.Finding{f})
}

// triageTargets is what a bulk key should act on: the marked findings if any
// are marked, otherwise the one under the cursor.
//
// The two were never connected. Space marks findings in ui.triageSelection,
// keyed by finding uid so a mark survives a refilter — but c, a, d, Ctrl+A and
// Ctrl+D all read ui.selectedEventIDs, which is the *events* screen's map. With
// three findings marked, the strip said "3 selected" and c answered "No events
// selected. Use Space to select events first."
func (ui *UI) triageTargets() []store.Finding {
	if sel := ui.triageSelection(); sel.count() > 0 {
		if picked := sel.resolve(ui.findings); len(picked) > 0 {
			return picked
		}
	}
	if f, ok := ui.currentFinding(); ok {
		return []store.Finding{f}
	}
	return nil
}

// escalateFindings attaches one or more findings to a case, new or existing.
func (ui *UI) escalateFindings(findings []store.Finding) {
	if len(findings) == 0 {
		ui.setStatusDirect("[%s]No finding selected[-:-:-]", ui.theme.TagWarning)
		return
	}
	f := findings[0]

	existing, err := ui.store.ListCases(ui.ctx)
	if err != nil {
		ui.setStatusDirect("[%s]Could not load cases: %v[-:-:-]", ui.theme.TagError, err)
		return
	}

	form := tview.NewForm()
	form.SetTitle(fmt.Sprintf(" Escalate %s to Case ", plural(len(findings), "finding"))).SetBorder(true)
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
					ui.queueUpdate(func() {
						ui.setStatusDirect("[%s]Failed to create case: %v[-:-:-]", ui.theme.TagError, err)
					})
					return
				}
				caseID = id
			}

			// Attach every one of them, and report what did not land rather
			// than stopping at the first failure with the rest unaccounted for.
			attached, failed := 0, 0
			for _, sel := range findings {
				if err := ui.store.AssignFindingToCase(ui.ctx, sel.ID, caseID); err != nil {
					failed++
					continue
				}
				attached++
				// Escalating means someone is working it.
				if sel.StatusID == ocsf.FindingStatusNew {
					_ = ui.store.UpdateFindingStatus(ui.ctx, sel.ID, ocsf.FindingStatusInProgress)
				}
			}
			if attached == 0 {
				ui.queueUpdate(func() {
					ui.setStatusDirect("[%s]Failed to attach %s[-:-:-]",
						ui.theme.TagError, plural(failed, "finding"))
				})
				return
			}
			for _, sel := range findings {
				_ = ui.store.LogCaseAction(ui.ctx, caseID, "finding_escalated", ui.currentAnalyst(),
					map[string]interface{}{"finding_uid": sel.FindingUID, "title": sel.Title})
			}

			ui.queueUpdate(func() {
				ui.triageSelection().clear()
				if failed > 0 {
					ui.setStatusDirect("[%s]%s attached, %d could not be[-:-:-]",
						ui.theme.TagWarning, plural(attached, "finding"), failed)
					return
				}
				ui.setStatusDirect("[%s]%s attached to case[-:-:-]",
					ui.theme.TagSuccess, plural(attached, "finding"))
			})
			ui.loadFindings()
			_ = ui.refreshCases()
		}()
	})
	form.AddButton("Cancel", func() { ui.restoreMainLayout() })

	ui.overlayForm(form, 64)
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
		ui.enterScreen(destHome)
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
		ui.spawnLoad(ui.loadFindings)
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
	ui.spawnLoad(ui.loadFindings)
}

// clearTriageFilters returns to the default view.
func (ui *UI) clearTriageFilters() {
	f := ui.triageFilterState()
	// Clear means clear. It used to mean "back to My queue", whose chips
	// include Open — so the filter an analyst most wants to drop was the one
	// that came back every time they cleared.
	f.clear()
	ui.repaintTriageChrome()
	ui.spawnLoad(ui.loadFindings)
}

// cycleTriageView moves to the next saved view.
func (ui *UI) cycleTriageView() {
	ui.triageFilterState().cycleView()
	ui.repaintTriageChrome()
	ui.setStatusDirect("[%s]View: %s[-:-:-]", ui.theme.TagAccent, ui.triageFilterState().viewName())
	ui.spawnLoad(ui.loadFindings)
}
