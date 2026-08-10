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

// A finding, read in full.
//
// One renderer, used by the dashboard and by Triage. It was written for the
// dashboard first, and the result was that the screen you glance at showed more
// about a finding than the screen you triage on: Triage had no indicator
// prevalence, no parsed ATT&CK, no verdict or confidence or assignee, printed
// the raw case identifier, printed identical first and last timestamps twice,
// and escaped nothing — so a finding whose title contained a bracket was parsed
// as a colour tag and lost the rest of the line.
//
// The renderer is a value with no widget and no screen in it. It takes a
// finding and returns a string, which is the seam a render test wants and the
// reason the same code can serve two panels of different heights.

// findingInspector renders one finding.
type findingInspector struct {
	theme Theme
	// width is the panel's inner width, taken from the last layout rather than
	// from the widget: tview reports the previous frame's rect, so asking a
	// widget gives an answer one repaint out of date.
	width int
	// narrativeLines bounds the producer's description. A short panel gives it
	// two lines; a full-height one can afford more. Either way it is bounded —
	// a producer that writes an essay does not get to push the indicators off
	// the panel.
	narrativeLines int
}

// Inspector geometry.
const (
	// homeMaxIndicators bounds the indicator list. Beyond a handful it is a
	// table to read rather than a set of leads to follow, and the Indicators
	// screen exists for the rest.
	homeMaxIndicators = 5

	// homeMaxTechniques bounds the ATT&CK list for the same reason.
	homeMaxTechniques = 4

	// homeInspectorDebounce is how long the cursor has to rest before the
	// indicator queries run. Holding an arrow key down a queue of forty would
	// otherwise issue two queries per row passed through.
	homeInspectorDebounce = 120 * time.Millisecond

	// indicatorTypeWidth is the type column. A wider one would push the values,
	// which are what the analyst actually reads, off the panel.
	indicatorTypeWidth = 7

	// indicatorValueWidth is the value column.
	indicatorValueWidth = 22
)

// ---------------------------------------------------------------------------
// The context: what the record does not carry
// ---------------------------------------------------------------------------

// findingContext is everything the inspector knows about a finding beyond the
// record itself. It is filled asynchronously, so the panel paints what it has
// and fills the rest in when the queries land.
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

// inspectorContext loads a finding's context off the UI goroutine, debounced.
type inspectorContext struct {
	ui *UI

	mu    sync.Mutex
	ctx   findingContext
	timer *time.Timer
}

// schedule loads the context for a finding once the cursor has settled, then
// calls then on the UI goroutine.
//
// The caseID is passed in rather than looked up, so the loader never has to
// know which screen's list the finding came from.
func (c *inspectorContext) schedule(findingID, caseID string, then func()) {
	if c.ui == nil || findingID == "" {
		return
	}

	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(homeInspectorDebounce, func() {
		c.load(findingID, caseID)
		c.ui.queueUpdate(then)
	})
	c.mu.Unlock()
}

// loadNow fills the context synchronously. Tests use it; the application uses
// schedule, which is the same work behind a debounce.
func (c *inspectorContext) loadNow(findingID, caseID string) {
	c.load(findingID, caseID)
}

func (c *inspectorContext) load(findingID, caseID string) {
	st := c.ui.store
	if st == nil {
		return
	}
	ctx := c.ui.ctx
	fc := findingContext{findingID: findingID, loaded: true}

	if obs, err := st.GetObservablesByFinding(ctx, findingID); err == nil {
		fc.indicators = c.rankIndicators(ctx, obs)
	}
	if strings.TrimSpace(caseID) != "" {
		if cs, err := st.GetCase(ctx, caseID); err == nil && cs != nil &&
			strings.TrimSpace(cs.Title) != "" {
			fc.caseTitle = cs.Title
		}
	}

	c.mu.Lock()
	c.ctx = fc
	c.mu.Unlock()
}

// get is the context if it belongs to this finding, else an empty one.
//
// Checked rather than assumed: the queries are asynchronous and the cursor does
// not wait for them, so a late result must not paint one finding's indicators
// under another's title.
func (c *inspectorContext) get(findingID string) findingContext {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.findingID != findingID {
		return findingContext{}
	}
	return c.ctx
}

// rankIndicators counts how widely each observable is seen and orders by it.
//
// This count is the most useful number on the panel: it separates an indicator
// that is a detail of one detection from one that ties several together.
func (c *inspectorContext) rankIndicators(ctx context.Context, obs []store.Observable) []indicatorSighting {
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

		n, err := c.ui.store.CountFindingsByObservable(ctx, o.TypeID, value)
		if err != nil {
			n = 0
		}
		out = append(out, indicatorSighting{
			Type:     indicatorTypeLabel(o),
			Value:    value,
			Findings: n,
		})
	}

	sortIndicators(out)
	if len(out) > homeMaxIndicators {
		out = out[:homeMaxIndicators]
	}
	return out
}

// sortIndicators puts the most widely seen first, then orders by type so the
// result is stable between repaints of the same finding.
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
	// column, and the few still too long for it are named below.
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

// indicatorTypeShort renames the types whose own word does not fit.
var indicatorTypeShort = map[string]string{
	"hostname":     "host",
	"fingerprint":  "hash",
	"resource":     "res",
	"organization": "org",
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// render returns the panel's text for one finding.
//
// The human explanation comes before the record — never the other way round.
func (r findingInspector) render(f store.Finding, fc findingContext) string {
	left, right := r.columns(f, fc)

	var b strings.Builder
	b.WriteString(r.headline(f))
	b.WriteString("\n\n")
	b.WriteString(r.narrative(f))
	b.WriteString("\n\n")

	if r.splits() {
		for i := 0; i < len(left) || i < len(right); i++ {
			b.WriteString(" ")
			b.WriteString(padCell(cellAt(left, i), widestCell(left)))
			b.WriteString("   ")
			b.WriteString(cellAt(right, i).text)
			b.WriteString("\n")
		}
		return strings.TrimRight(b.String(), "\n")
	}

	// Stacked. Beside the queue the pane is a third of the body, which is not
	// enough for two columns — laid out side by side anyway, the right-hand one
	// wrapped onto its own lines and the two interleaved.
	for _, c := range left {
		b.WriteString(" " + c.text + "\n")
	}
	b.WriteString("\n")
	for _, c := range right {
		b.WriteString(" " + c.text + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// splits reports whether the pane is wide enough for two columns.
//
// Measured against the content rather than a layout tier, so the fallback
// happens for the reason it exists — the columns would not fit — and stays
// right if the indicator table's widths change.
func (r findingInspector) splits() bool {
	const minRight = 20
	return r.innerWidth() >= 1+inspectorLeftWidth+3+minRight
}

// inspectorLeftWidth is the left column's width, fixed by the indicator table:
// indent, type, gap, value, gap, and the prevalence note.
const inspectorLeftWidth = 2 + indicatorTypeWidth + 1 + indicatorValueWidth + 1 + 14

// padCell writes a cell out to width columns, counting what is drawn rather
// than what is written — a tagged string's length includes markup that is not.
func padCell(c welcomeCell, width int) string {
	if c.width >= width {
		return c.text
	}
	return c.text + strings.Repeat(" ", width-c.width)
}

// headline is the title and the three facts that rank it.
func (r findingInspector) headline(f store.Finding) string {
	t := r.theme
	return fmt.Sprintf(" [%s:-:b]%s[-:-:-]   %s [%s]· risk %d · %s[-:-:-]",
		t.TagTextPrimary, tview.Escape(f.Title),
		formatSeverityBadge(severityLabel(f.SeverityID), t),
		t.TagMuted, f.RiskScore, tview.Escape(orDash(f.Status)))
}

// narrative is why this finding matters, wrapped rather than cut.
//
// The producer's own description first. finding_info.desc is what the detection
// says it saw; message is often set to the title, and reading the title back
// under "why it matters" says nothing. The panel used to claim nothing was
// supplied whenever message was empty — which was false for every finding that
// carried a desc, because it was parsed and then dropped on the way to storage.
func (r findingInspector) narrative(f store.Finding) string {
	t := r.theme
	why := findingNarrative(f)

	const label = " WHY IT MATTERS  "
	indent := strings.Repeat(" ", len(label))
	lines := wrapText(why, r.innerWidth()-len(label))

	var b strings.Builder
	for i, l := range lines {
		if i >= r.lines() {
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

func (r findingInspector) lines() int {
	if r.narrativeLines < 1 {
		return 2
	}
	return r.narrativeLines
}

func (r findingInspector) innerWidth() int {
	if w := r.width - 2; w > 24 {
		return w
	}
	return 24
}

// rightColumnBudget is how wide the right column may be, measured from the left
// column's width, which the indicator table fixes.
func (r findingInspector) rightColumnBudget() int {
	if !r.splits() {
		// Stacked: the right column has the whole pane.
		return r.innerWidth() - 2
	}
	if b := r.innerWidth() - inspectorLeftWidth - 4; b > 20 {
		return b
	}
	return 20
}

// columns builds the two halves beneath the narrative.
func (r findingInspector) columns(f store.Finding, fc findingContext) (left, right []welcomeCell) {
	t := r.theme
	budget := r.rightColumnBudget()

	left = append(left, textCell("INDICATORS", t.TagMuted))
	switch {
	case !fc.loaded:
		left = append(left, textCell("  …", t.TagMuted))
	case len(fc.indicators) == 0:
		left = append(left, textCell("  none recorded", t.TagMuted))
	default:
		for _, ind := range fc.indicators {
			left = append(left, r.indicatorCell(ind))
		}
	}

	left = append(left,
		welcomeCell{},
		r.labelled("EVIDENCE", fmt.Sprintf("%d artifacts", evidenceCount(f.EvidencesJSON))),
		r.labelled("CASE", r.caseLabel(f, fc)))

	right = append(right, textCell("ATT&CK", t.TagMuted))
	techniques := findingTechniques(f)
	if len(techniques) == 0 {
		right = append(right, textCell("  none mapped", t.TagMuted))
	}
	for _, tech := range techniques {
		right = append(right, textCell("  "+truncate(tech, budget-2), t.TagTextPrimary))
	}

	right = append(right,
		welcomeCell{},
		textCell("DETAIL", t.TagMuted),
		r.labelled("analytic", truncate(orDash(f.AnalyticName), budget-12)),
		r.labelled("verdict", truncate(fmt.Sprintf("%s  ·  confidence %s  ·  assignee %s",
			orDash(f.Verdict), orDash(ocsf.ConfidenceName(f.ConfidenceID)), orDash(f.Assignee)), budget-12)),
		r.labelled("seen", truncate(seenRange(f), budget-12)))
	return left, right
}

// indicatorCell is one observable and how widely it is seen.
func (r findingInspector) indicatorCell(ind indicatorSighting) welcomeCell {
	t := r.theme
	// "in 3 more", not plural()'s "in 3 mores" — "more" is already plural.
	shared := "first sighting"
	if ind.Findings > 1 {
		shared = fmt.Sprintf("in %d more", ind.Findings-1)
	}
	vw := r.valueWidth()
	value := truncate(ind.Value, vw)
	plain := fmt.Sprintf("  %-*s %-*s %s", indicatorTypeWidth, ind.Type, vw, value, shared)
	return welcomeCell{
		text: fmt.Sprintf("  [%s]%-*s[-:-:-] [%s]%-*s[-:-:-] [%s]%s[-:-:-]",
			t.TagMuted, indicatorTypeWidth, ind.Type,
			t.TagTextPrimary, vw, tview.Escape(value),
			t.TagAccent, shared),
		width: len([]rune(plain)),
	}
}

// valueWidth is how much of an indicator's value fits.
//
// Fixed beside the queue would overrun the pane, which is a third of the body
// there; the row would then wrap and the prevalence note — the reason the row
// is worth a query — would land on a line of its own.
func (r findingInspector) valueWidth() int {
	const fixed = 2 + indicatorTypeWidth + 1 + 1 + 14 // indent, type, gaps, note
	if r.splits() {
		return indicatorValueWidth
	}
	w := r.innerWidth() - fixed
	if w < 10 {
		return 10
	}
	if w > indicatorValueWidth {
		return indicatorValueWidth
	}
	return w
}

// labelled is a muted label with its value beside it, indented to match the
// indicator rows so entries line up under their heading in either column.
func (r findingInspector) labelled(label, value string) welcomeCell {
	t := r.theme
	// The label block is twelve columns; whatever is left is the value's.
	if room := r.innerWidth() - 13; room > 8 {
		value = truncate(value, room)
	}
	plain := fmt.Sprintf("  %-9s %s", label, value)
	return welcomeCell{
		text: fmt.Sprintf("  [%s]%-9s[-:-:-] [%s]%s[-:-:-]",
			t.TagMuted, label, t.TagTextPrimary, tview.Escape(value)),
		width: len([]rune(plain)),
	}
}

// caseLabel names the case a finding belongs to.
func (r findingInspector) caseLabel(f store.Finding, fc findingContext) string {
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

// findingNarrative picks the best available account of a finding.
//
// desc, then message when it adds something the title does not, and only then
// the admission that there is nothing. A message identical to the title is
// treated as absent: repeating the heading is not a description.
func findingNarrative(f store.Finding) string {
	if d := strings.TrimSpace(f.Desc); d != "" {
		return d
	}
	msg := strings.TrimSpace(f.Message)
	if msg != "" && !strings.EqualFold(msg, strings.TrimSpace(f.Title)) {
		return msg
	}
	return "No description was supplied by the producer."
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
