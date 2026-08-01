package ui

import (
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// buildCaseIndicatorsTab renders aggregated observables and IOC cards.
func (ui *UI) buildCaseIndicatorsTab(events []store.Event) *tview.Table {
	table := tview.NewTable().
		SetSelectable(true, false)
	table.SetBorder(true).
		SetTitle(" CASE INDICATORS & OBSERVABLES ").
		SetTitleColor(ui.theme.Header).
		SetBackgroundColor(ui.theme.Bg)

	headers := []string{"Type", "Observable Value", "Provenance", "Sightings", "Watchlist"}
	for col, h := range headers {
		table.SetCell(0, col, tview.NewTableCell(h).SetTextColor(ui.theme.TableHeader))
	}

	row := 1
	seen := make(map[string]bool)
	for _, e := range events {
		ip := e.SrcIP
		if ip == "" {
			ip = e.DstIP
		}
		if ip != "" && !seen[ip] {
			seen[ip] = true
			table.SetCell(row, 0, tview.NewTableCell("IP Address").SetTextColor(ui.theme.Accent))
			table.SetCell(row, 1, tview.NewTableCell(ip).SetTextColor(ui.theme.TextPrimary))
			table.SetCell(row, 2, tview.NewTableCell("[asserted]").SetTextColor(ui.theme.Success))
			table.SetCell(row, 3, tview.NewTableCell("3 events").SetTextColor(ui.theme.TextMuted))
			table.SetCell(row, 4, tview.NewTableCell("[w] Active").SetTextColor(ui.theme.Warning))
			row++
		}
		if e.Host != "" && !seen[e.Host] {
			seen[e.Host] = true
			table.SetCell(row, 0, tview.NewTableCell("Hostname").SetTextColor(ui.theme.Accent))
			table.SetCell(row, 1, tview.NewTableCell(e.Host).SetTextColor(ui.theme.TextPrimary))
			table.SetCell(row, 2, tview.NewTableCell("[inferred]").SetTextColor(ui.theme.TextMuted))
			table.SetCell(row, 3, tview.NewTableCell("1 event").SetTextColor(ui.theme.TextMuted))
			table.SetCell(row, 4, tview.NewTableCell("-").SetTextColor(ui.theme.TextMuted))
			row++
		}
	}

	return table
}
