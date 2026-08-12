package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// Indicators are the case's IOCs, aggregated by identity and carrying their
// provenance.
//
// **Provenance is mandatory and visually distinct.** An indicator the producer
// asserted and one Console-IR inferred are defended differently — the first is
// somebody else's claim, the second is ours — so they must never render alike.
// A glyph as well as a colour, because this is exactly the distinction that has
// to survive a 16-colour terminal.
//
// This tab previously counted "3 events" for every indicator whatever the case
// held, and wrote provenance as "[asserted]" — which tview reads as a colour
// tag and swallows, so the mandatory distinction rendered as nothing at all.

// Provenance values an indicator can carry. "manual" is an analyst's own
// entry, which is neither the producer's claim nor our inference and must not
// be mistaken for either.
const provenanceManual = "manual"

// provenanceMark renders an indicator's origin.
func provenanceMark(source string, t Theme) (glyph, colour, label string) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "derived":
		return "◦", t.TagMuted, "derived"
	case provenanceManual:
		return "✎", t.TagWarning, "manual"
	default:
		return "▪", t.TagAccent, "asserted"
	}
}

// manualIndicators are the analyst's own entries, stored as notes tagged "ioc".
//
// They are merged with the observables rather than shown separately: an analyst
// who typed an address in wants to see it beside the ones the parser found, and
// dropping them from this tab would silently lose their input.
func manualIndicators(notes []store.Note) ([]store.CaseIndicator, map[string]string) {
	out := []store.CaseIndicator{}
	byValue := map[string]string{}

	for _, n := range notes {
		if !strings.EqualFold(n.LinkedType, "ioc") || strings.TrimSpace(n.LinkedID) == "" {
			continue
		}
		kind := strings.TrimPrefix(strings.TrimSpace(n.Content), "ioc_type:")
		if kind == "" || kind == n.Content {
			kind = "manual"
		}
		out = append(out, store.CaseIndicator{
			Type: kind, Value: n.LinkedID, Source: provenanceManual,
			Sightings: 1, FirstSeen: n.CreatedAt, LastSeen: n.CreatedAt,
		})
		byValue[n.LinkedID] = n.ID
	}
	return out, byValue
}

// renderCaseIndicators draws the aggregated indicators.
func renderCaseIndicators(table *tview.Table, indicators []store.CaseIndicator, t Theme, emptyHint []string) {
	table.Clear()
	setTableCursor(table, len(indicators) > 0)

	// The three numeric columns are right-aligned, headers included. A sighting
	// time is 11 columns dated and 5 bare — "08-06 05:59" beside "09:07" — so
	// left-aligned they ran into each other and neither column had an edge.
	headers := []struct {
		title string
		align int
	}{
		{"TYPE", tview.AlignLeft},
		{"VALUE", tview.AlignLeft},
		{"PROVENANCE", tview.AlignLeft},
		{"SIGHTINGS", tview.AlignRight},
		{"FIRST", tview.AlignRight},
		{"LAST", tview.AlignRight},
	}
	for col, h := range headers {
		title := " " + h.title
		if h.align == tview.AlignRight {
			title = h.title + " "
		}
		table.SetCell(0, col, tview.NewTableCell(title).
			SetAlign(h.align).
			SetTextColor(t.TableHeader).SetBackgroundColor(t.TableHeaderBg).SetSelectable(false))
	}

	if len(indicators) == 0 {
		// The empty state is the caller's: this renderer serves a case's tab
		// and the cross-database screen, and "this case's events and findings"
		// was wrong on the second of those.
		if len(emptyHint) == 0 {
			emptyHint = []string{"No indicators extracted."}
		}
		for i, line := range emptyHint {
			colour := t.TextMuted
			if i == 0 {
				colour = t.TextPrimary
			}
			table.SetCell(i+1, 0, tview.NewTableCell(" "+line).
				SetTextColor(colour).SetSelectable(false).SetExpansion(1))
		}
		return
	}

	for i, ind := range indicators {
		glyph, colour, label := provenanceMark(ind.Source, t)
		row := i + 1

		table.SetCell(row, 0, tview.NewTableCell(" "+tview.Escape(orDash(ind.Type))).SetTextColor(t.TextMuted))

		// Not truncated here. The column expands into whatever the pane has
		// left, and cutting the text first defeated that: a SHA-256 is 64
		// characters, the cut was at 44, and the space it would have used sat
		// empty between this column and the next. tview clips what genuinely
		// does not fit.
		// The value is coloured by what it is: an address, a host, a user, a
		// file. The type is right there in the column beside it, so this costs
		// no guesswork — the indicator carries its OCSF type_id.
		value := tview.Escape(ind.Value)
		valueColour := t.TextPrimary
		if class, ok := entityClassOf(ind.TypeID); ok {
			valueColour = entityColour(class, t)
		}
		table.SetCell(row, 1, tview.NewTableCell(value).
			SetTextColor(valueColour).SetExpansion(1))

		table.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("[%s]%s %s[-]", colour, glyph, label)))
		table.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%d ", ind.Sightings)).
			SetAlign(tview.AlignRight).SetTextColor(t.TextMuted))
		table.SetCell(row, 4, tview.NewTableCell(stampOrDash(ind.FirstSeen)+" ").
			SetAlign(tview.AlignRight).SetTextColor(t.TextMuted))
		table.SetCell(row, 5, tview.NewTableCell(stampOrDash(ind.LastSeen)+" ").
			SetAlign(tview.AlignRight).SetTextColor(t.TextMuted))
	}
}

// stampOrDash renders a sighting time.
//
// With the date unless it was today. A bare clock time collapses every day onto
// the same twenty-four labels, so on a cross-case view two sightings a week
// apart read as two sightings minutes apart.
func stampOrDash(at time.Time) string {
	if at.IsZero() {
		return "—"
	}
	if sameDay(at, time.Now()) {
		return at.Format("15:04")
	}
	return at.Format("01-02 15:04")
}

// renderIOCs paints the Indicators tab.
func (cm *CaseManagement) renderIOCs() {
	if cm.iocsTable == nil {
		return
	}
	indicators, err := cm.store.GetCaseIndicators(cm.ctx, cm.caseData.ID)
	if err != nil {
		cm.iocsTable.Clear()
		for i, line := range []string{"Could not load indicators.", tview.Escape(err.Error()), "", "r  Retry"} {
			colour := cm.theme.TextMuted
			if i == 0 {
				colour = cm.theme.Error
			}
			cm.iocsTable.SetCell(i, 0, tview.NewTableCell(" "+line).
				SetTextColor(colour).SetSelectable(false).SetExpansion(1))
		}
		return
	}
	manual, noteIDs := manualIndicators(cm.notes)
	seen := map[string]bool{}
	for _, ind := range indicators {
		seen[strings.ToLower(ind.Value)] = true
	}
	for _, ind := range manual {
		// An analyst entry for a value the evidence already carries is the same
		// indicator; listing it twice would double the apparent corroboration.
		if !seen[strings.ToLower(ind.Value)] {
			indicators = append(indicators, ind)
		}
	}

	cm.caseIndicators = indicators
	// The tab strip counts them.
	cm.renderTabBar()
	renderCaseIndicators(cm.iocsTable, indicators, cm.theme, []string{
		"No indicators extracted.",
		"",
		"Indicators come from the observables on this case's events and findings.",
		"Attach evidence, or wait for enrichment to derive them.",
	})

	// Map the manual rows back to their notes, so Space and d still act on the
	// analyst's own entries.
	cm.iocRowToManualID = map[int]string{}
	for i, ind := range indicators {
		if id, ok := noteIDs[ind.Value]; ok && strings.EqualFold(ind.Source, provenanceManual) {
			cm.iocRowToManualID[i+1] = id
		}
	}
}

// pivotSelectedIndicator opens the pivot for the indicator under the cursor.
//
// It reuses the Events screen's pivot rather than building a second one, so
// "where else has this appeared?" is answered the same way wherever it is
// asked.
func (cm *CaseManagement) pivotSelectedIndicator() {
	row, _ := cm.iocsTable.GetSelection()
	if row <= 0 || row-1 >= len(cm.caseIndicators) {
		return
	}
	ind := cm.caseIndicators[row-1]

	if cm.parentUI == nil {
		cm.updateStatus("Pivot needs the main window")
		return
	}

	// Asked first, because it leaves.
	//
	// A pivot spans the whole database, which a case screen cannot show — so
	// answering it means closing the case and opening the Events screen. Doing
	// that silently on Enter, the key least likely to be read as "leave", threw
	// the analyst out of the investigation they were in with no warning and no
	// way back to where they were.
	modal := tview.NewModal().
		SetText(fmt.Sprintf(
			"Pivot on %s?\n\nThis shows every event and finding that carries it, "+
				"across the whole database — so it closes this case and opens the Events screen.",
			ind.Value)).
		AddButtons([]string{"Pivot", "Stay in the case"}).
		SetDoneFunc(func(_ int, label string) {
			cm.popModalRoot()
			if label != "Pivot" {
				return
			}
			cm.close()
			cm.parentUI.pivotTo(pivotTarget{
				TypeID: ind.TypeID,
				Value:  ind.Value,
				Kind:   orDash(ind.Type),
			})
		})

	modal.SetBackgroundColor(cm.theme.Surface)
	modal.SetTextColor(cm.theme.TextPrimary)
	modal.SetBorderColor(cm.theme.FocusBorder)
	cm.pushModalRoot(modal)
}

// mergeIndicators combines the same indicator seen in several cases.
func mergeIndicators(in []store.CaseIndicator) []store.CaseIndicator {
	byKey := map[string]store.CaseIndicator{}
	order := []string{}

	for _, ind := range in {
		key := fmt.Sprintf("%d/%s", ind.TypeID, ind.Value)
		prev, seen := byKey[key]
		if !seen {
			byKey[key] = ind
			order = append(order, key)
			continue
		}
		prev.Sightings += ind.Sightings
		// Asserted anywhere means asserted: one producer's claim is not
		// weakened by another case having only inferred it.
		if strings.EqualFold(ind.Source, "asserted") {
			prev.Source = ind.Source
		}
		if !ind.FirstSeen.IsZero() && (prev.FirstSeen.IsZero() || ind.FirstSeen.Before(prev.FirstSeen)) {
			prev.FirstSeen = ind.FirstSeen
		}
		if ind.LastSeen.After(prev.LastSeen) {
			prev.LastSeen = ind.LastSeen
		}
		byKey[key] = prev
	}

	out := make([]store.CaseIndicator, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out
}
