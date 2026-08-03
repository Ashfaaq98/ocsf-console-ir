package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Triage's filter state, kept apart from its rendering.
//
// Two rules drive the shape. Filtering re-queries rather than filtering in Go
// over a loaded page, so this type's only job is to produce a store.Finding
// filter. And a filtered-out row and an absent row must be distinguishable, so
// the active filters are state the screen can name rather than something
// applied and forgotten.

// chipID identifies a quick filter.
type chipID int

const (
	chipOpen chipID = iota
	chipSeverityHigh
	chipLast24h
	chipHasIOC
)

// chip is one quick filter, rendered as a removable token above the table.
type chip struct {
	id    chipID
	label string
	// apply narrows a filter. Chips are additive: every active chip applies,
	// and they combine with AND.
	apply func(*store.FindingFilter, time.Time)
}

// triageChips is the set offered. Owner and Source are specified but need a
// value to filter on, so they arrive with the `+ filter` prompt rather than as
// fixed toggles.
func triageChips() []chip {
	return []chip{
		{chipOpen, "Open", func(f *store.FindingFilter, _ time.Time) {
			f.OpenOnly = true
		}},
		{chipSeverityHigh, "Sev ≥ High", func(f *store.FindingFilter, _ time.Time) {
			f.MinSeverityID = ocsf.SeverityHigh
		}},
		{chipLast24h, "Last 24h", func(f *store.FindingFilter, now time.Time) {
			f.SeenAfter = now.Add(-24 * time.Hour)
		}},
		{chipHasIOC, "Has IOC", func(f *store.FindingFilter, _ time.Time) {
			f.HasObservables = true
		}},
	}
}

// savedView is a named starting point. Shipped read-only; user-created views
// persist later and deliberately need no table now.
type savedView struct {
	name  string
	chips []chipID
	// extra applies what no chip covers.
	extra func(*store.FindingFilter, time.Time)
}

func savedViews() []savedView {
	return []savedView{
		{name: "My queue", chips: []chipID{chipOpen}},
		{name: "Critical now", chips: []chipID{chipOpen}, extra: func(f *store.FindingFilter, _ time.Time) {
			f.MinSeverityID = ocsf.SeverityCritical
		}},
		{name: "Stale >24h", chips: []chipID{chipOpen}, extra: func(f *store.FindingFilter, now time.Time) {
			// The same field as "last 24h", read the other way: not seen since.
			f.SeenBefore = now.Add(-24 * time.Hour)
		}},
		{name: "Untriaged", extra: func(f *store.FindingFilter, _ time.Time) {
			f.Statuses = []int{ocsf.FindingStatusNew}
		}},
		{name: "Suppressed", extra: func(f *store.FindingFilter, _ time.Time) {
			f.Statuses = []int{ocsf.FindingStatusSuppressed}
		}},
	}
}

// triageFilter is the screen's filter state.
type triageFilter struct {
	active map[chipID]bool
	view   int // index into savedViews
	search string
}

func newTriageFilter() *triageFilter {
	f := &triageFilter{active: map[chipID]bool{}}
	f.applyView(0)
	return f
}

// applyView resets the chips to a saved view's starting point.
func (f *triageFilter) applyView(idx int) {
	views := savedViews()
	if idx < 0 || idx >= len(views) {
		return
	}
	f.view = idx
	f.active = map[chipID]bool{}
	for _, id := range views[idx].chips {
		f.active[id] = true
	}
}

// viewName is the saved view currently selected.
func (f *triageFilter) viewName() string {
	views := savedViews()
	if f.view < 0 || f.view >= len(views) {
		return ""
	}
	return views[f.view].name
}

// cycleView moves to the next saved view, wrapping.
func (f *triageFilter) cycleView() {
	f.applyView((f.view + 1) % len(savedViews()))
}

// toggle flips one chip.
func (f *triageFilter) toggle(id chipID) {
	if f.active[id] {
		delete(f.active, id)
		return
	}
	f.active[id] = true
}

// activeChips lists the chips in a stable order, for rendering and removal.
func (f *triageFilter) activeChips() []chip {
	out := []chip{}
	for _, c := range triageChips() {
		if f.active[c.id] {
			out = append(out, c)
		}
	}
	return out
}

// triageEmpty names which empty state Triage should show.
type triageEmpty int

const (
	// triageNotEmpty means there are rows to draw.
	triageNotEmpty triageEmpty = iota
	// triageNoFindings means the database holds no findings at all.
	triageNoFindings
	// triageFilteredOut means findings exist but none match.
	triageFilteredOut
)

// emptyKind decides which empty state applies.
//
// The decision cannot be made from the filter alone. The default view carries
// the Open chip, so "is anything filtering?" is true on a fresh install and
// would blame the filter for an empty database — but Open genuinely can be
// responsible, when every finding is resolved. Only the unfiltered count tells
// the two apart, so Triage counts as well as queries.
//
// §7: never show the no-findings copy when a filter is responsible.
func emptyKind(rowsShown, totalUnfiltered int) triageEmpty {
	if rowsShown > 0 {
		return triageNotEmpty
	}
	if totalUnfiltered > 0 {
		return triageFilteredOut
	}
	return triageNoFindings
}

// storeFilter renders the state as a store query.
func (f *triageFilter) storeFilter(now time.Time, limit, offset int) store.FindingFilter {
	out := store.FindingFilter{
		Search: strings.TrimSpace(f.search),
		Sort:   store.SortPriority,
		Limit:  limit,
		Offset: offset,
	}
	for _, c := range f.activeChips() {
		c.apply(&out, now)
	}
	views := savedViews()
	if f.view >= 0 && f.view < len(views) && views[f.view].extra != nil {
		views[f.view].extra(&out, now)
	}
	return out
}

// describe names the active filters in one line, for the empty state. An empty
// state that does not say what is filtering is a dead end.
func (f *triageFilter) describe() string {
	parts := []string{}
	if v := f.viewName(); v != "" {
		parts = append(parts, v)
	}
	for _, c := range f.activeChips() {
		parts = append(parts, c.label)
	}
	if s := strings.TrimSpace(f.search); s != "" {
		parts = append(parts, fmt.Sprintf("search %q", s))
	}
	return strings.Join(parts, " · ")
}

// renderChips draws the chip row: the saved view, the active chips, and the
// prompt for adding one.
func (f *triageFilter) renderChips(theme Theme) string {
	var b strings.Builder
	for _, c := range triageChips() {
		if f.active[c.id] {
			fmt.Fprintf(&b, " [%s:%s] %s ✕[-:-:-]", theme.TagTextPrimary, theme.TagAccent, c.label)
		} else {
			fmt.Fprintf(&b, " [%s]%s[-:-:-]", theme.TagMuted, inactiveChip(c.label))
		}
	}
	fmt.Fprintf(&b, "   [%s]saved:[-:-:-] [%s]%s ▾[-:-:-]", theme.TagMuted, theme.TagAccent, f.viewName())
	return b.String()
}

// inactiveChip renders an unset filter as a bracketed token, so the analyst can
// see what is available as well as what is applied.
func inactiveChip(label string) string {
	return "[" + label + "]"
}

// triageSelection is the set of findings marked for a bulk action.
//
// Keyed by finding uid rather than row index: §7 requires the selection to
// survive refresh, sort and filter changes, and a row index survives none of
// them.
type triageSelection struct {
	ids map[string]bool
}

func newTriageSelection() *triageSelection {
	return &triageSelection{ids: map[string]bool{}}
}

func (s *triageSelection) toggle(uid string) {
	if uid == "" {
		return
	}
	if s.ids[uid] {
		delete(s.ids, uid)
		return
	}
	s.ids[uid] = true
}

func (s *triageSelection) has(uid string) bool { return s.ids[uid] }
func (s *triageSelection) count() int          { return len(s.ids) }
func (s *triageSelection) clear()              { s.ids = map[string]bool{} }

// resolve returns the selected findings out of the rows currently loaded.
func (s *triageSelection) resolve(rows []store.Finding) []store.Finding {
	out := make([]store.Finding, 0, len(s.ids))
	for _, f := range rows {
		if s.ids[f.FindingUID] {
			out = append(out, f)
		}
	}
	return out
}
