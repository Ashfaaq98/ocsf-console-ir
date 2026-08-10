package ui

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The Reports screen: what has been produced, and the means to produce more.
//
// It used to be a paragraph of static text advertising "Case Bundles
// (JSON/STIX)", "Generated Incident Briefings" and "Telemetry Export (OCSF
// JSONL)" — three things that did not exist, with no key to reach any of them,
// on a numbered destination any demo walks into.
//
// A report is kept rather than recomputed. Regenerate last month's in November
// and cases have closed, statuses have changed and findings have been
// re-triaged: the document that went to a client is not reproducible from the
// data, so the text is the record. Listing files on disk instead would be a
// screen that lies as soon as one is moved.

// reportsView is the screen's state.
type reportsView struct {
	table   *tview.Table
	preview *tview.TextView
	root    *tview.Flex

	reports []store.Report
	// shown is the report whose text is in the preview, so scrolling it does
	// not need the database again.
	shown *store.Report

	// One piece of work at a time. The list and the preview are separate loads
	// that touch the same slice and the same widgets, and they arrive together
	// whenever a refresh lands while the cursor is moving.
	load  loadGuard
	again int32
}

// reportPreviewRows is the preview's share of the screen.
const reportPreviewRows = 3

func (ui *UI) switchToReports() {
	if ui.reports == nil {
		ui.reports = ui.buildReportsView()
	}
	ui.setMainView(ui.reports.root)
	ui.app.SetFocus(ui.reports.table)
	ui.setStatusDirect("[%s]Reports[-:-:-]", ui.theme.TagAccent)
	ui.spawnLoad(ui.loadReports)
}

func (ui *UI) buildReportsView() *reportsView {
	t := ui.theme
	v := &reportsView{}

	v.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	attachTableScrollbar(v.table, 1, &ui.theme)
	stylePanel(v.table.Box, "REPORTS", PanelRolePrimary, t)
	v.table.SetBackgroundColor(t.Bg)
	v.table.SetSelectedStyle(tcell.StyleDefault.
		Background(t.SelectionBg).Foreground(t.SelectionFg))

	v.preview = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	attachScrollbar(v.preview, &ui.theme)
	stylePanel(v.preview.Box, "PREVIEW", PanelRoleInspector, t)
	v.preview.SetBackgroundColor(t.Surface)

	v.table.SetSelectionChangedFunc(func(int, int) { ui.spawnLoad(ui.loadReportPreview) })
	v.table.SetSelectedFunc(func(int, int) { ui.app.SetFocus(v.preview) })

	v.root = tview.NewFlex().SetDirection(tview.FlexRow)
	v.root.SetBackgroundColor(t.Bg)
	v.root.AddItem(v.table, 0, 2, true)
	v.root.AddItem(v.preview, 0, reportPreviewRows, false)
	return v
}

// reportsWork runs one piece of Reports work at a time.
//
// A request that arrives while another is running is remembered rather than
// dropped, so the screen always settles on the row the cursor is on.
func (ui *UI) reportsWork(fn func()) {
	v := ui.reports
	if v == nil {
		return
	}
	if !v.load.begin() {
		atomic.StoreInt32(&v.again, 1)
		return
	}
	for {
		fn()
		v.load.end()
		if !atomic.CompareAndSwapInt32(&v.again, 1, 0) {
			return
		}
		if !v.load.begin() {
			return
		}
	}
}

// loadReports reads the list, off the UI goroutine.
func (ui *UI) loadReports() {
	ui.reportsWork(func() {
		ui.readReports()
		ui.readReportPreview()
	})
}

// loadReportPreview reads just the selected report's text.
func (ui *UI) loadReportPreview() {
	ui.reportsWork(ui.readReportPreview)
}

func (ui *UI) readReports() {
	if ui.store == nil || ui.reports == nil {
		return
	}
	list, err := ui.store.ListReports(ui.ctx)
	if err != nil {
		ui.queueUpdate(func() {
			ui.setStatusDirect("[%s]Could not read reports: %v[-:-:-]", ui.theme.TagError, err)
		})
		return
	}
	ui.queueUpdate(func() {
		ui.reports.reports = list
		ui.renderReports()
	})
}

func (ui *UI) renderReports() {
	v := ui.reports
	if v == nil {
		return
	}
	t := ui.theme

	v.table.Clear()
	for col, h := range []string{"GENERATED", "KIND", "COVERS", "SIZE"} {
		v.table.SetCell(0, col, tview.NewTableCell(" "+h).
			SetTextColor(t.TableHeader).SetBackgroundColor(t.TableHeaderBg).SetSelectable(false))
	}
	stylePanel(v.table.Box, fmt.Sprintf("REPORTS  ·  %d", len(v.reports)), PanelRolePrimary, t)

	if len(v.reports) == 0 {
		for i, line := range []string{
			"No reports yet.",
			"",
			"A report is a case written up: what happened, which detections fired,",
			"the evidence behind them, the indicators, and the decisions recorded.",
			"",
			"Press n to write one, or E inside a case.",
		} {
			colour := t.TableRowMuted
			if i == 0 {
				colour = t.TextPrimary
			}
			v.table.SetCell(i+1, 0, tview.NewTableCell(" "+line).
				SetTextColor(colour).SetSelectable(false).SetExpansion(1))
		}
		v.preview.SetText("")
		return
	}

	for i, r := range v.reports {
		row := i + 1
		v.table.SetCell(row, 0, tview.NewTableCell(" "+r.CreatedAt.Format("2006-01-02 15:04")).
			SetTextColor(t.TextMuted))
		v.table.SetCell(row, 1, tview.NewTableCell(r.Kind).SetTextColor(t.Accent))
		v.table.SetCell(row, 2, tview.NewTableCell(tview.Escape(r.Covers())).
			SetTextColor(t.TextPrimary).SetExpansion(1))
		v.table.SetCell(row, 3, tview.NewTableCell(humanSize(r.Size())+" ").
			SetAlign(tview.AlignRight).SetTextColor(t.TextMuted))
	}

	if row, _ := v.table.GetSelection(); row < 1 {
		v.table.Select(1, 0)
	}
}

// selectedReport is the row under the cursor.
func (ui *UI) selectedReport() *store.Report {
	v := ui.reports
	if v == nil {
		return nil
	}
	row, _ := v.table.GetSelection()
	if row <= 0 || row-1 >= len(v.reports) {
		return nil
	}
	return &v.reports[row-1]
}

// loadReportPreview reads the selected report's text.
//
// The list carries a size but not the document: thirty reports on screen should
// not be thirty documents in memory.
func (ui *UI) readReportPreview() {
	if ui.store == nil || ui.reports == nil {
		return
	}
	sel := ui.selectedReport()
	if sel == nil {
		ui.queueUpdate(func() { ui.reports.preview.SetText("") })
		return
	}
	id := sel.ID

	full, err := ui.store.GetReport(ui.ctx, id)
	if err != nil {
		ui.queueUpdate(func() {
			ui.reports.preview.SetText(fmt.Sprintf("\n [%s]Could not read this report: %v[-:-:-]",
				ui.theme.TagError, err))
		})
		return
	}

	ui.queueUpdate(func() {
		// The cursor may have moved while this was reading.
		if cur := ui.selectedReport(); cur == nil || cur.ID != id {
			return
		}
		ui.reports.shown = full
		ui.reports.preview.SetText(tview.Escape(full.Content))
		ui.reports.preview.ScrollToBeginning()

		title := "PREVIEW"
		if full.WrittenPath != "" {
			title = "PREVIEW  ·  written to " + full.WrittenPath
		}
		stylePanel(ui.reports.preview.Box, title, PanelRoleInspector, ui.theme)
	})
}

// reportKeys are the screen's own.
func (ui *UI) reportKeys(ev *tcell.EventKey) *tcell.EventKey {
	if ui.reports == nil {
		return ev
	}

	// Tab belongs to this screen's two panes.
	//
	// Unclaimed it reached cycleFocus, which moves between the case sidebar,
	// the events table and the event detail — none of which is on this screen.
	// Focus landed on a widget nobody could see and the status bar announced
	// "Focus: Cases" while Reports was showing.
	if ev.Key() == tcell.KeyTab || ev.Key() == tcell.KeyBacktab {
		ui.cycleReportFocus()
		return nil
	}

	if ev.Key() != tcell.KeyRune {
		return ev
	}
	switch ev.Rune() {
	case 'n':
		ui.showNewReportMenu()
		return nil
	case 'w':
		ui.writeSelectedReport()
		return nil
	case 'd':
		ui.deleteSelectedReport()
		return nil
	case 'r':
		ui.spawnLoad(ui.loadReports)
		return nil
	}
	return ev
}

// cycleReportFocus moves between the list and the report being read.
func (ui *UI) cycleReportFocus() {
	v := ui.reports
	if v == nil || ui.app == nil {
		return
	}
	if ui.app.GetFocus() == v.preview {
		ui.app.SetFocus(v.table)
		ui.setStatusDirect("[%s]Reports[-:-:-]", ui.theme.TagAccent)
		return
	}
	ui.app.SetFocus(v.preview)
	ui.setStatusDirect("[%s]Reading[-:-:-] · ↑↓ scrolls · Tab returns to the list", ui.theme.TagAccent)
}

// showNewReportMenu asks which case to write up.
//
// Only case reports for now. Weekly and monthly need the timing data that
// UpdateFindingStatus and UpdateFindingVerdict have only just begun recording,
// and a periodic report whose central metric is blank is not worth offering.
func (ui *UI) showNewReportMenu() {
	t := ui.theme
	if len(ui.cases) == 0 {
		ui.setStatusDirect("[%s]No cases to report on yet[-:-:-]", t.TagMuted)
		return
	}

	list := tview.NewList().ShowSecondaryText(true)
	list.SetBackgroundColor(t.SurfaceRaised)
	list.SetMainTextColor(t.TextPrimary)
	list.SetSecondaryTextColor(t.TextMuted)
	list.SetSelectedBackgroundColor(t.SelectionBg)
	list.SetSelectedTextColor(t.SelectionFg)

	for _, c := range ui.cases {
		c := c
		list.AddItem(truncate(c.Title, 46),
			fmt.Sprintf("   %s · %s · %s",
				strings.ToUpper(orDash(c.Severity)),
				strings.ToLower(orDash(c.Status)),
				plural(c.FindingCount, "finding")),
			0, func() {
				ui.closeModal()
				ui.writeReportForCase(c.ID)
			})
	}

	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			ui.closeModal()
			return nil
		}
		return ev
	})

	height := len(ui.cases)*2 + 4
	if height > 20 {
		height = 20
	}
	ui.overlayModal(modalPanel(list, "Report on which case?", t), 60, height)
	ui.app.SetFocus(list)
}

// writeReportForCase generates a case report and shows it.
func (ui *UI) writeReportForCase(caseID string) {
	ui.setStatusDirect("[%s]Writing the report…[-:-:-]", ui.theme.TagWarning)
	ui.spawnLoad(func() {
		rec, err := ui.generateCaseReport(ui.ctx, caseID)
		if err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Could not write the report: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}
		ui.queueUpdate(func() {
			ui.setStatusDirect("[%s]Report written · %s · w saves it to a file[-:-:-]",
				ui.theme.TagSuccess, rec.Title)
		})
		ui.loadReports()
	})
}

// writeSelectedReport puts the selected report on disk.
func (ui *UI) writeSelectedReport() {
	sel := ui.selectedReport()
	if sel == nil {
		ui.setStatusDirect("[%s]No report selected[-:-:-]", ui.theme.TagMuted)
		return
	}
	id := sel.ID

	ui.spawnLoad(func() {
		full, err := ui.store.GetReport(ui.ctx, id)
		if err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Could not read the report: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}
		path, err := writeReportFile(*full)
		if err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Could not write the file: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}
		_ = ui.store.RecordReportPath(ui.ctx, id, path)

		ui.queueUpdate(func() {
			// The whole path, not a folder name: the one thing an analyst needs
			// after writing a file is where it went.
			ui.setStatusDirect("[%s]Written to %s[-:-:-]", ui.theme.TagSuccess, path)
		})
		ui.loadReports()
	})
}

// deleteSelectedReport removes the record. The file it was written to is left
// where it is — this owns the record, not the analyst's filesystem.
func (ui *UI) deleteSelectedReport() {
	sel := ui.selectedReport()
	if sel == nil {
		return
	}
	id, title := sel.ID, sel.Title

	ui.spawnLoad(func() {
		if err := ui.store.DeleteReport(ui.ctx, id); err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Could not delete: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}
		ui.queueUpdate(func() {
			ui.setStatusDirect("[%s]Deleted the report for %s · any file written stays[-:-:-]",
				ui.theme.TagAccent, title)
		})
		ui.loadReports()
	})
}

// humanSize renders a report's length the way a file manager would.
func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
