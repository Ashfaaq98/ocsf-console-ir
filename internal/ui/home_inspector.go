package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// The selected finding, in full.
//
// This is the panel the dashboard is judged on. Its predecessor showed six rows
// — title, risk, analytic, a truncated sentence, and a line of key hints for
// three keys that did not work — while the record behind it carried the
// indicators, the technique, the verdict, the confidence and the assignee, all
// stored and none of it displayed.
//
// Two columns, because a finding read in full is wider than it is tall.

// Inspector geometry.
const (
	// homeInspectorSplit is where the right column starts, as a fraction of the
	// panel's inner width. The left column carries the narrative and the
	// indicators, which are the long-form half.
	homeInspectorSplit = 46

	// homeMaxIndicators bounds the indicator list. Beyond a handful it is a
	// table to read rather than a set of leads to follow, and the Indicators
	// screen exists for the rest.
	homeMaxIndicators = 5

	// homeMaxTechniques bounds the ATT&CK list for the same reason.
	homeMaxTechniques = 4

	// homeInspectorDebounce is how long the cursor has to rest before the
	// indicator queries run. Holding the arrow key down a queue of forty would
	// otherwise issue two queries per row passed through.
	homeInspectorDebounce = 120 * time.Millisecond
)

// findingContext is everything the inspector knows about the selected finding
// beyond the record itself. It is filled asynchronously, so the panel paints
// what it has and fills the rest in when the queries land.
type findingContext struct {
	findingID string

	// indicators are the finding's observables, most shared first — an
	// indicator seen in five other findings is a lead; one seen nowhere else is
	// a detail.
	indicators []indicatorSighting

	// caseTitle is the case this finding belongs to, by name. The panel used to
	// print the raw identifier, and "case_e882aa1e-8a4b-40ad-b92b-774746d7efbd"
	// is forty characters that say nothing.
	caseTitle string

	loaded bool
}

// indicatorSighting is one observable and how widely it is seen.
type indicatorSighting struct {
	Type  string
	Value string
	// Findings is how many findings carry this indicator, including this one.
	Findings int
}

// homeInspector owns the context and the debounce timer.
type homeInspector struct {
	mu    sync.Mutex
	ctx   findingContext
	timer *time.Timer
}

// selectionChanged is called on every cursor movement.
//
// It repaints immediately from the record — which needs no query — and only
// schedules the lookups once the cursor has settled.
func (h *homeView) selectionChanged() {
	h.renderInspector()

	f := h.selectedFinding()
	if f == nil {
		return
	}
	id := f.ID

	h.inspect.mu.Lock()
	if h.inspect.timer != nil {
		h.inspect.timer.Stop()
	}
	h.inspect.timer = time.AfterFunc(homeInspectorDebounce, func() {
		h.loadFindingContext(id)
	})
	h.inspect.mu.Unlock()
}

// loadFindingContext runs the per-selection queries off the UI goroutine.
func (h *homeView) loadFindingContext(findingID string) {
	st := h.ui.store
	if st == nil {
		return
	}
	ctx := h.ui.ctx

	fc := findingContext{findingID: findingID, loaded: true}

	if obs, err := st.GetObservablesByFinding(ctx, findingID); err == nil {
		fc.indicators = h.rankIndicators(ctx, obs)
	}

	if f := h.findingByID(findingID); f != nil && strings.TrimSpace(f.CaseID) != "" {
		if c, err := st.GetCase(ctx, f.CaseID); err == nil && strings.TrimSpace(c.Title) != "" {
			fc.caseTitle = c.Title
		}
	}

	h.inspect.mu.Lock()
	h.inspect.ctx = fc
	h.inspect.mu.Unlock()

	h.ui.queueUpdate(func() {
		// The cursor may have moved on while these ran. Repainting anyway would
		// show one finding's indicators under another's title.
		if sel := h.selectedFinding(); sel != nil && sel.ID == findingID {
			h.renderInspector()
		}
	})
}

// rankIndicators counts how widely each observable is seen and orders by it.
//
// This count is the most useful number on the screen: it separates an indicator
// that is a detail of one detection from one that ties several together.
func (h *homeView) rankIndicators(ctx context.Context, obs []store.Observable) []indicatorSighting {
	out := make([]indicatorSighting, 0, len(obs))
	seen := map[string]bool{}

	for _, o := range obs {
		value := strings.TrimSpace(o.Value)
		if value == "" {
			continue
		}
		key := fmt.Sprintf("%d/%s", o.TypeID, strings.ToLower(value))
		if seen[key] {
			continue
		}
		seen[key] = true

		n, err := h.ui.store.CountFindingsByObservable(ctx, o.TypeID, value)
		if err != nil {
			n = 0
		}
		out = append(out, indicatorSighting{
			Type:     indicatorTypeLabel(o),
			Value:    value,
			Findings: n,
		})
	}

	// Most widely seen first, then by type so the order is stable between
	// repaints of the same finding.
	sortIndicators(out)
	if len(out) > homeMaxIndicators {
		out = out[:homeMaxIndicators]
	}
	return out
}

func sortIndicators(in []indicatorSighting) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0; j-- {
			a, b := in[j-1], in[j]
			if a.Findings > b.Findings || (a.Findings == b.Findings && a.Type <= b.Type) {
				break
			}
			in[j-1], in[j] = b, a
		}
	}
}

// indicatorTypeLabel is the short, lowercase word for an observable's type.
func indicatorTypeLabel(o store.Observable) string {
	name := strings.TrimSpace(o.Type)
	if name == "" {
		name = ocsf.ObservableTypeName(o.TypeID)
	}
	name = strings.ToLower(name)
	// The registry's captions are display names — "User Name", "File Name",
	// "IP Address". The first word is the distinction that matters in a narrow
	// column, and the few that are still too long for it are named here.
	if i := strings.IndexAny(name, " -"); i > 0 {
		name = name[:i]
	}
	if short, ok := indicatorTypeShort[name]; ok {
		return short
	}
	if name == "" || name == "unknown" {
		return "other"
	}
	if len([]rune(name)) > indicatorTypeWidth {
		return string([]rune(name)[:indicatorTypeWidth])
	}
	return name
}

// indicatorTypeWidth is the type column. A wider one would push the values,
// which are what the analyst actually reads, off the panel.
const indicatorTypeWidth = 7

// indicatorTypeShort renames the types whose own word does not fit.
var indicatorTypeShort = map[string]string{
	"hostname":     "host",
	"fingerprint":  "hash",
	"resource":     "res",
	"organization": "org",
}

// findingByID looks a finding up in the loaded queue.
func (h *homeView) findingByID(id string) *store.Finding {
	d, _ := h.snapshot()
	for i := range d.queue {
		if d.queue[i].ID == id {
			return &d.queue[i]
		}
	}
	return nil
}

// findingContextFor is the context if it belongs to this finding, else empty.
func (h *homeView) findingContextFor(id string) findingContext {
	h.inspect.mu.Lock()
	defer h.inspect.mu.Unlock()
	if h.inspect.ctx.findingID != id {
		return findingContext{}
	}
	return h.inspect.ctx
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// renderInspector paints the selected finding.
//
// The human explanation comes before the record — never the other way round.
func (h *homeView) renderInspector() {
	_, loading := h.snapshot()
	t := h.ui.theme

	if loading[panelQueue] {
		h.inspector.SetText(" " + loadingState("", t))
		return
	}
	f := h.selectedFinding()
	if f == nil {
		h.inspector.SetText(fmt.Sprintf("\n [%s]Select a finding to see why it matters.[-:-:-]", t.TagMuted))
		return
	}

	fc := h.findingContextFor(f.ID)
	left, right := h.inspectorColumns(*f, fc)

	var b strings.Builder
	b.WriteString(h.inspectorHeadline(*f))
	b.WriteString("\n\n")
	b.WriteString(h.inspectorNarrative(*f))
	b.WriteString("\n\n")

	for i := 0; i < len(left) || i < len(right); i++ {
		b.WriteString(" ")
		b.WriteString(padCell(cellAt(left, i), widestCell(left)))
		b.WriteString("   ")
		b.WriteString(cellAt(right, i).text)
		b.WriteString("\n")
	}

	h.inspector.SetText(strings.TrimRight(b.String(), "\n"))
}

// padCell writes a cell out to width columns, counting what is drawn rather
// than what is written — a tagged string's length includes markup that is not.
func padCell(c welcomeCell, width int) string {
	if c.width >= width {
		return c.text
	}
	return c.text + strings.Repeat(" ", width-c.width)
}

// inspectorHeadline is the title and the three facts that rank it.
func (h *homeView) inspectorHeadline(f store.Finding) string {
	t := h.ui.theme
	return fmt.Sprintf(" [%s:-:b]%s[-:-:-]   %s [%s]· risk %d · %s[-:-:-]",
		t.TagTextPrimary, tview.Escape(f.Title),
		formatSeverityBadge(severityLabel(f.SeverityID), t),
		t.TagMuted, f.RiskScore, tview.Escape(orDash(f.Status)))
}

// inspectorNarrative is why this finding matters, wrapped rather than cut.
//
// It used to truncate at a hardcoded 110 characters, so a sentence ended in an
// ellipsis with half the panel empty beside it.
func (h *homeView) inspectorNarrative(f store.Finding) string {
	t := h.ui.theme
	why := strings.TrimSpace(f.Message)
	if why == "" {
		why = "No description was supplied by the producer."
	}

	const label = " WHY IT MATTERS  "
	indent := strings.Repeat(" ", len(label))
	lines := wrapText(why, h.inspectorWidth()-len(label))

	var b strings.Builder
	for i, l := range lines {
		if i >= 2 {
			// Two lines is the budget. A producer that writes an essay does not
			// get to push the indicators off the panel.
			break
		}
		lead := fmt.Sprintf("[%s]%s[-:-:-]", t.TagMuted, label)
		if i > 0 {
			lead = indent
		}
		fmt.Fprintf(&b, "%s[%s]%s[-:-:-]\n", lead, t.TagTextPrimary, tview.Escape(l))
	}
	return strings.TrimRight(b.String(), "\n")
}

// inspectorWidth is the panel's inner width, from the last layout rather than
// from the widget: tview reports the previous frame's rect, so asking the
// widget gives an answer one repaint out of date.
func (h *homeView) inspectorWidth() int {
	w := h.width - 2
	if w < 40 {
		return 40
	}
	return w
}

// inspectorColumns builds the two halves beneath the narrative.
func (h *homeView) inspectorColumns(f store.Finding, fc findingContext) (left, right []welcomeCell) {
	t := h.ui.theme
	budget := h.rightColumnBudget()

	left = append(left, textCell("INDICATORS", t.TagMuted))
	switch {
	case !fc.loaded:
		left = append(left, textCell("  …", t.TagMuted))
	case len(fc.indicators) == 0:
		left = append(left, textCell("  none recorded", t.TagMuted))
	default:
		for _, ind := range fc.indicators {
			left = append(left, h.indicatorCell(ind))
		}
	}

	left = append(left, welcomeCell{})
	left = append(left, h.labelled("EVIDENCE", fmt.Sprintf("%d artifacts", evidenceCount(f.EvidencesJSON))))
	left = append(left, h.labelled("CASE", h.caseLabel(f, fc)))

	right = append(right, textCell("ATT&CK", t.TagMuted))
	techniques := findingTechniques(f)
	if len(techniques) == 0 {
		right = append(right, textCell("  none mapped", t.TagMuted))
	}
	for _, tech := range techniques {
		right = append(right, textCell("  "+truncate(tech, budget-2), t.TagTextPrimary))
	}

	right = append(right, welcomeCell{})
	right = append(right, textCell("DETAIL", t.TagMuted))
	right = append(right, h.labelled("analytic", truncate(orDash(f.AnalyticName), budget-12)))
	right = append(right, h.labelled("verdict", truncate(fmt.Sprintf("%s  ·  confidence %s  ·  assignee %s",
		orDash(f.Verdict), orDash(ocsf.ConfidenceName(f.ConfidenceID)), orDash(f.Assignee)), budget-12)))
	right = append(right, h.labelled("seen", truncate(seenRange(f), budget-12)))
	return left, right
}

// rightColumnBudget is how wide the right column may be.
//
// Measured from the left column's widest row, which is fixed by the indicator
// table, rather than from the widget: tview reports the previous frame's rect,
// so asking it gives an answer one repaint out of date.
func (h *homeView) rightColumnBudget() int {
	const leftColumnWidth = 2 + indicatorTypeWidth + 1 + 22 + 1 + 14
	if b := h.inspectorWidth() - leftColumnWidth - 4; b > 20 {
		return b
	}
	return 20
}

// indicatorCell is one observable and how widely it is seen.
func (h *homeView) indicatorCell(ind indicatorSighting) welcomeCell {
	t := h.ui.theme
	// "in 3 more", not plural()'s "in 3 mores" — "more" is already plural.
	shared := "first sighting"
	if ind.Findings > 1 {
		shared = fmt.Sprintf("in %d more", ind.Findings-1)
	}
	plain := fmt.Sprintf("  %-*s %-22s %s", indicatorTypeWidth, ind.Type, truncate(ind.Value, 22), shared)
	return welcomeCell{
		text: fmt.Sprintf("  [%s]%-*s[-:-:-] [%s]%-22s[-:-:-] [%s]%s[-:-:-]",
			t.TagMuted, indicatorTypeWidth, ind.Type, t.TagTextPrimary,
			tview.Escape(truncate(ind.Value, 22)), t.TagAccent, shared),
		width: len([]rune(plain)),
	}
}

// labelled is a muted label with its value beside it.
func (h *homeView) labelled(label, value string) welcomeCell {
	t := h.ui.theme
	// Two spaces, the same indent the indicator rows use, so entries line up
	// under their section heading in either column.
	plain := fmt.Sprintf("  %-9s %s", label, value)
	return welcomeCell{
		text: fmt.Sprintf("  [%s]%-9s[-:-:-] [%s]%s[-:-:-]",
			t.TagMuted, label, t.TagTextPrimary, tview.Escape(value)),
		width: len([]rune(plain)),
	}
}

// caseLabel names the case a finding belongs to.
func (h *homeView) caseLabel(f store.Finding, fc findingContext) string {
	if strings.TrimSpace(f.CaseID) == "" {
		return "not in a case"
	}
	if fc.caseTitle != "" {
		return truncate(fc.caseTitle, 30)
	}
	// The lookup has not landed. The identifier is a poor label but it is not a
	// lie, and it is replaced the moment the query returns.
	return truncate(f.CaseID, 30)
}

// seenRange is when the activity happened, said once when it is one moment.
func seenRange(f store.Finding) string {
	first, last := stamp(f.FirstSeen), stamp(f.LastSeen)
	if first == last {
		return first + "  (single occurrence)"
	}
	return first + " → " + last
}

// findingTechniques is the ATT&CK mapping the producer supplied.
//
// The finding carries it as raw JSON, parsed on the way in and then shown
// nowhere — the one field on the record that says what the attacker was doing.
func findingTechniques(f store.Finding) []string {
	raw := strings.TrimSpace(f.AttacksJSON)
	if raw == "" || raw == "null" {
		return nil
	}

	var attacks []ocsf.Attack
	if err := json.Unmarshal([]byte(raw), &attacks); err != nil {
		return nil
	}

	out := make([]string, 0, len(attacks))
	for _, a := range attacks {
		node := a.SubTechnique
		if node == nil || node.UID == "" {
			node = a.Technique
		}
		if node == nil || node.UID == "" {
			continue
		}
		label := node.UID
		if node.Name != "" {
			label += "  " + node.Name
		}
		out = append(out, truncate(label, 40))
		if len(out) == homeMaxTechniques {
			break
		}
	}
	return out
}
