package ui

import (
	"context"
	"fmt"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// showAnalystHome opens the dashboard. It is the only destination the UI starts
// on: whether a database exists at all is settled in cmd, before the store is
// opened, so a first run never gets this far.
//
// Home renders its own empty states, so an existing but empty database is not a
// special case here.
func (ui *UI) showAnalystHome() {
	ui.showFindings = false
	ui.showAll = false
	ui.selectedCaseID = ""
	ui.setMainView(ui.buildHomeDashboard(ui.ctx))
	ui.setStatusDirect("[%s]Analyst Home • Press 1-5 to navigate[-:-:-]", ui.theme.TagAccent)
}

// buildHomeDashboard renders the wide / standard dashboard for Analyst Home.
func (ui *UI) buildHomeDashboard(ctx context.Context) *tview.Flex {
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	flex.SetBackgroundColor(ui.theme.Bg)

	// Top Header metrics row: Triage Pulse, Active Cases, Evidence Today
	topRow := tview.NewFlex().SetDirection(tview.FlexColumn)

	// Triage Pulse Box
	triageBox := tview.NewTextView().SetDynamicColors(true)
	triageBox.SetBorder(true).SetTitle(" OPEN FINDINGS ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Surface)

	// Active Cases Box
	casesBox := tview.NewTextView().SetDynamicColors(true)
	casesBox.SetBorder(true).SetTitle(" ACTIVE CASES ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Surface)

	// Evidence Today Box
	evidenceBox := tview.NewTextView().SetDynamicColors(true)
	evidenceBox.SetBorder(true).SetTitle(" EVIDENCE TODAY ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Surface)

	topRow.AddItem(triageBox, 0, 1, false).
		AddItem(casesBox, 0, 1, false).
		AddItem(evidenceBox, 0, 1, false)

	// Bottom Row: Priority Queue (left) & Right Column (right)
	bottomRow := tview.NewFlex().SetDirection(tview.FlexColumn)

	queueTable := tview.NewTable().SetSelectable(true, false)
	queueTable.SetBorder(true).SetTitle(" PRIORITY QUEUE ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Bg)

	rightCol := tview.NewFlex().SetDirection(tview.FlexRow)

	resumeList := tview.NewList()
	resumeList.SetBorder(true).SetTitle(" RESUME WORK ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Surface)
	resumeList.SetMainTextColor(ui.theme.TextPrimary).SetSelectedBackgroundColor(ui.theme.SelectionBg)

	pivotsList := tview.NewList()
	pivotsList.SetBorder(true).SetTitle(" RECENT PIVOTS ").SetTitleColor(ui.theme.Header).SetBackgroundColor(ui.theme.Surface)
	pivotsList.SetMainTextColor(ui.theme.TextPrimary).SetSelectedBackgroundColor(ui.theme.SelectionBg)

	rightCol.AddItem(resumeList, 0, 1, false).
		AddItem(pivotsList, 0, 1, false)

	bottomRow.AddItem(queueTable, 0, 2, true).
		AddItem(rightCol, 0, 1, false)

	flex.AddItem(topRow, 5, 0, false).
		AddItem(bottomRow, 0, 1, true)

	// Load metrics asynchronously
	go ui.populateHomeDashboard(ctx, triageBox, casesBox, evidenceBox, queueTable, resumeList, pivotsList)

	return flex
}

// populateHomeDashboard fetches store metrics and populates the dashboard widgets.
func (ui *UI) populateHomeDashboard(ctx context.Context, triageBox, casesBox, evidenceBox *tview.TextView, queueTable *tview.Table, resumeList, pivotsList *tview.List) {
	var findings []store.Finding
	if ui.store != nil {
		findings, _ = ui.store.GetFindings(ctx, store.FindingFilter{OpenOnly: true})
	}
	cases := ui.cases

	// Counted in the database rather than measured from ui.events, which holds
	// one page of whatever view was last loaded. Home is now the screen every
	// session opens on, so this number is the first one an analyst sees.
	totalEvents := 0
	if ui.store != nil {
		if n, err := ui.store.CountEvents(ctx, store.EventFilter{}); err == nil {
			totalEvents = n
		} else {
			ui.logger.Warn("home: could not count events: %v", err)
		}
	}

	var critCount, highCount int
	for _, f := range findings {
		sev := strings.ToUpper(f.Severity)
		if strings.Contains(sev, "CRIT") || f.RiskScore >= 80 {
			critCount++
		} else if strings.Contains(sev, "HIGH") || f.RiskScore >= 60 {
			highCount++
		}
	}

	ui.app.QueueUpdateDraw(func() {
		// Triage Box text
		triageBox.SetText(fmt.Sprintf("\n  [%s:b]%02d[-:-:-]  [%s]%d critical / %d high[-:-:-]\n  [%s]Open Findings Queue[-:-:-]",
			ui.theme.TagTextPrimary, len(findings), ui.theme.TagSeverityCritical, critCount, highCount, ui.theme.TagMuted))

		// Cases Box text
		casesBox.SetText(fmt.Sprintf("\n  [%s:b]%02d[-:-:-]  [%s]active investigations[-:-:-]\n  [%s]In progress[-:-:-]",
			ui.theme.TagAccent, len(cases), ui.theme.TagMuted, ui.theme.TagMuted))

		// Evidence Box text
		evidenceBox.SetText(fmt.Sprintf("\n  [%s:b]%d events[-:-:-]  [%s]Local SQLite[-:-:-]\n  [%s]Ingest Live • Offline & local first[-:-:-]",
			ui.theme.TagSuccess, totalEvents, ui.theme.TagMuted, ui.theme.TagMuted))

		// Priority Queue table setup
		queueTable.Clear()
		queueTable.SetCell(0, 0, tview.NewTableCell("Sev").SetTextColor(ui.theme.TableHeader))
		queueTable.SetCell(0, 1, tview.NewTableCell("Risk").SetTextColor(ui.theme.TableHeader))
		queueTable.SetCell(0, 2, tview.NewTableCell("Finding Title").SetTextColor(ui.theme.TableHeader))
		queueTable.SetCell(0, 3, tview.NewTableCell("Age").SetTextColor(ui.theme.TableHeader))

		limit := 5
		if len(findings) < limit {
			limit = len(findings)
		}
		for i := 0; i < limit; i++ {
			f := findings[i]
			row := i + 1
			queueTable.SetCell(row, 0, tview.NewTableCell(formatSeverityBadge(f.Severity, ui.theme)))
			queueTable.SetCell(row, 1, tview.NewTableCell(formatRisk(f.RiskScore, ui.theme)))
			queueTable.SetCell(row, 2, tview.NewTableCell(f.Title).SetTextColor(ui.theme.TextPrimary))
			queueTable.SetCell(row, 3, tview.NewTableCell(renderRelativeTime(f.LastSeen)).SetTextColor(ui.theme.TextMuted))
		}

		// Resume List
		resumeList.Clear()
		if len(ui.recentCases) == 0 {
			resumeList.AddItem("No recent cases", "Press 'c' to create investigation", 'c', nil)
		} else {
			for i, caseID := range ui.recentCases {
				if i >= 4 {
					break
				}
				// Find case title
				title := caseID
				for _, c := range ui.cases {
					if c.ID == caseID {
						title = c.Title
						break
					}
				}
				resumeList.AddItem(title, "Recently opened", rune('1'+i), nil)
			}
		}

		// Pivots List
		pivotsList.Clear()
		if len(ui.recentPivots) == 0 {
			pivotsList.AddItem("No recent pivots", "Select an event and press 'p'", 'p', nil)
		} else {
			for i, p := range ui.recentPivots {
				if i >= 4 {
					break
				}
				pivotsList.AddItem(p, "Recent indicator search", 0, nil)
			}
		}
	})
}

// The onboarding screen that used to live here has moved to welcome.go, where
// it runs before the store is opened rather than as a panel inside a UI that
// has already created the database it is offering to create.
