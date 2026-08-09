package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Events answer "what else happened around this?", so they arrive grouped.
//
// Grouping is a display concern computed over the page already loaded — never a
// second round trip, and never a re-query when a cluster expands. A thousand
// rows of raw telemetry is not an answer; six events on one host inside six
// minutes is.

// groupKey is what events are clustered by.
type groupKey int

const (
	groupByHost groupKey = iota
	groupByProcess
	groupByTime
	groupNone
)

// String names the grouping for the header and the status line.
func (g groupKey) String() string {
	switch g {
	case groupByHost:
		return "host"
	case groupByProcess:
		return "process"
	case groupByTime:
		return "time"
	default:
		return "none"
	}
}

// next cycles host → process → time → none → host.
func (g groupKey) next() groupKey {
	if g == groupNone {
		return groupByHost
	}
	return g + 1
}

// clusterWindow is the span a time-grouped cluster covers.
const clusterWindow = 5 * time.Minute

// eventCluster is one group of events with its span and count.
type eventCluster struct {
	// Label is the entity, or the window start when grouping by time.
	Label  string
	Events []store.Event
	Start  time.Time
	End    time.Time

	// headerRow is where the cluster's header was drawn, so a keypress on a
	// row can find the cluster it belongs to.
	headerRow int

	// timeGrouped records that the label is a window rather than an entity.
	timeGrouped bool
}

// Count is how many events the cluster holds.
func (c eventCluster) Count() int { return len(c.Events) }

// Span renders the cluster's time range, collapsing to a single stamp when
// every event shares a minute.
func (c eventCluster) Span() string {
	start := c.Start.Format("15:04")
	end := c.End.Format("15:04")
	if start == end {
		return start
	}
	return start + "–" + end
}

// Header is the cluster's one-line summary: entity, span, count.
//
// A time-grouped cluster's label is already a time, so the span replaces it
// rather than sitting beside it — "10:05 · 10:05 · 1 event" says nothing twice.
func (c eventCluster) Header() string {
	noun := "events"
	if c.Count() == 1 {
		noun = "event"
	}
	if c.timeGrouped {
		return fmt.Sprintf("%s · %d %s", c.Span(), c.Count(), noun)
	}
	return fmt.Sprintf("%s · %s · %d %s", c.Label, c.Span(), c.Count(), noun)
}

// clusterEvents groups a loaded page.
//
// Order is preserved: clusters appear in the order their first event does, so
// the grouping never reorders a list the query already ordered. Events with no
// value for the key fall into one "unattributed" cluster rather than vanishing.
func clusterEvents(events []store.Event, key groupKey) []eventCluster {
	if len(events) == 0 {
		return nil
	}
	if key == groupNone {
		// One cluster holding everything, so callers have one shape to render.
		c := eventCluster{Label: "All events", Events: events}
		c.Start, c.End = spanOf(events)
		return []eventCluster{c}
	}

	order := []string{}
	byLabel := map[string][]store.Event{}
	for _, e := range events {
		label := clusterLabel(e, key)
		if _, seen := byLabel[label]; !seen {
			order = append(order, label)
		}
		byLabel[label] = append(byLabel[label], e)
	}

	out := make([]eventCluster, 0, len(order))
	for _, label := range order {
		c := eventCluster{Label: label, Events: byLabel[label], timeGrouped: key == groupByTime}
		c.Start, c.End = spanOf(c.Events)
		out = append(out, c)
	}
	return out
}

// clusterLabel is the group an event belongs to.
func clusterLabel(e store.Event, key groupKey) string {
	switch key {
	case groupByHost:
		return orUnattributed(e.Host)
	case groupByProcess:
		return orUnattributed(e.ProcessName)
	case groupByTime:
		// Truncated to the window, so events either side of a boundary do not
		// land in one cluster merely because they are close together.
		return e.Timestamp.Truncate(clusterWindow).Format("15:04")
	default:
		return "All events"
	}
}

// orUnattributed names the cluster for events carrying no value for the key.
// Dropping them would make the list disagree with its own count.
func orUnattributed(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unattributed"
	}
	return s
}

// spanOf returns the earliest and latest timestamps in a set.
func spanOf(events []store.Event) (time.Time, time.Time) {
	if len(events) == 0 {
		return time.Time{}, time.Time{}
	}
	start, end := events[0].Timestamp, events[0].Timestamp
	for _, e := range events[1:] {
		if e.Timestamp.Before(start) {
			start = e.Timestamp
		}
		if e.Timestamp.After(end) {
			end = e.Timestamp
		}
	}
	return start, end
}

// ---------------------------------------------------------------------------
// Pivot
// ---------------------------------------------------------------------------

// pivotTarget is one entity an analyst can pivot on.
type pivotTarget struct {
	// TypeID and Value identify the observable, which is how the pivot is
	// executed: an indexed lookup on (type_id, value), never a text scan.
	TypeID int
	Value  string
	// Kind is the human label for the observable type.
	Kind string
}

// Label is what the pivot menu shows.
func (p pivotTarget) Label() string {
	return fmt.Sprintf("%s  %s", p.Kind, p.Value)
}

// pivotTargets builds the menu for an event from its observables.
//
// From the observables table rather than from the event's own columns: that is
// what makes the pivot an indexed lookup, and it is also the only way to offer
// entities the parser derived rather than ones the schema happens to have a
// column for. Duplicates are collapsed — the same address as both source and
// destination is one thing to pivot on.
func pivotTargets(observables []store.Observable) []pivotTarget {
	seen := map[string]bool{}
	out := []pivotTarget{}
	for _, o := range observables {
		v := strings.TrimSpace(o.Value)
		if v == "" {
			continue
		}
		key := fmt.Sprintf("%d/%s", o.TypeID, v)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, pivotTarget{TypeID: o.TypeID, Value: v, Kind: observableKind(o)})
	}

	// Stable order so the menu does not reshuffle between openings: by kind,
	// then by value.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// observableKind names an observable's type for display.
func observableKind(o store.Observable) string {
	if t := strings.TrimSpace(o.Type); t != "" {
		return t
	}
	if n := strings.TrimSpace(o.Name); n != "" {
		return n
	}
	return fmt.Sprintf("type %d", o.TypeID)
}

// eventForRow returns the event drawn on a table row, or nil when the row is a
// cluster header or out of range.
//
// A row used to be an offset into ui.events. It stopped being one when cluster
// headers started occupying rows, and every caller that assumed otherwise would
// have selected, opened or pivoted on the wrong event.
// selectFirstEvent puts the cursor on the first row that is an event.
//
// Selecting row 1 selects a cluster header — row 1 always is one — so
// eventForRow returned nil, showEventDetails never fired, and the Events screen
// opened with whatever the previous screen had left in the detail pane.
func (ui *UI) selectFirstEvent() {
	if ui.eventList == nil {
		return
	}

	row := 1
	if len(ui.eventAtRow) > 0 {
		row = -1
		for r := range ui.eventAtRow {
			if row == -1 || r < row {
				row = r
			}
		}
	}
	if row < 1 || row >= ui.eventList.GetRowCount() {
		return
	}

	ui.eventList.Select(row, 0)
	// Explicitly: tview does not fire SelectionChanged when the row selected is
	// the one already selected, which on a fresh list is row 1.
	ui.showEventDetails()
}

func (ui *UI) eventForRow(row int) *store.Event {
	if ui.eventAtRow == nil {
		// No clustering has been rendered, so the historical mapping holds.
		if row > 0 && row-1 < len(ui.events) {
			return &ui.events[row-1]
		}
		return nil
	}
	idx, ok := ui.eventAtRow[row]
	if !ok || idx < 0 || idx >= len(ui.events) {
		return nil
	}
	return &ui.events[idx]
}

// clusterAtRow returns the cluster whose header is on a row, or nil.
func (ui *UI) clusterAtRow(row int) *eventCluster {
	for i := range ui.eventClusters {
		if ui.eventClusters[i].headerRow == row {
			return &ui.eventClusters[i]
		}
	}
	return nil
}

// toggleCluster opens a cluster, or closes it if it was already open.
//
// One open at a time. Expanding everything reproduces the wall of log lines
// that clustering exists to replace, and §8 makes that the default rather than
// a preference.
func (ui *UI) toggleCluster(label string) {
	if ui.expandedCluster == label {
		ui.expandedCluster = ""
	} else {
		ui.expandedCluster = label
	}
	// A re-render, not a re-query: the page is already loaded and the grouping
	// is computed over it.
	ui.updateEventsList()
}

// cycleEventGrouping moves to the next grouping key and re-renders.
func (ui *UI) cycleEventGrouping() {
	ui.eventGroup = ui.eventGroup.next()
	// The open cluster's label belongs to the old grouping, so it is dropped
	// rather than carried into a set of labels it is not part of.
	ui.expandedCluster = ""
	ui.updateEventsList()
	ui.setStatusDirect("[%s]Grouped by %s[-:-:-]", ui.theme.TagAccent, ui.eventGroup)
}
