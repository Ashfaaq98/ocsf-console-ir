package ui

import (
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

func at(hhmm string) time.Time {
	t, err := time.Parse("15:04:05", hhmm)
	if err != nil {
		panic(err)
	}
	return t
}

func ev(ts, host, process, msg string) store.Event {
	return store.Event{
		ID: msg, Timestamp: at(ts), Host: host, ProcessName: process, Message: msg,
	}
}

// Clusters appear in the order their first event does. Grouping must not
// reorder a list the query already ordered.
func TestClusterPreservesOrder(t *testing.T) {
	events := []store.Event{
		ev("09:42:11", "FIN-02", "powershell.exe", "a"),
		ev("10:02:00", "WS-17", "svchost.exe", "b"),
		ev("09:42:14", "FIN-02", "powershell.exe", "c"),
		ev("10:20:00", "dc-01", "lsass.exe", "d"),
	}

	got := clusterEvents(events, groupByHost)
	want := []string{"FIN-02", "WS-17", "dc-01"}
	if len(got) != len(want) {
		t.Fatalf("%d clusters, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Label != want[i] {
			t.Errorf("cluster %d = %q, want %q", i, got[i].Label, want[i])
		}
	}
	if got[0].Count() != 2 {
		t.Errorf("FIN-02 holds %d events, want 2", got[0].Count())
	}
}

// Every event lands in exactly one cluster, or the list disagrees with its
// own count.
func TestClusterLosesNothing(t *testing.T) {
	events := []store.Event{
		ev("09:42:11", "FIN-02", "powershell.exe", "a"),
		ev("09:43:00", "", "", "b"), // no host, no process
		ev("10:02:00", "WS-17", "svchost.exe", "c"),
	}

	for _, key := range []groupKey{groupByHost, groupByProcess, groupByTime, groupNone} {
		total := 0
		for _, c := range clusterEvents(events, key) {
			total += c.Count()
		}
		if total != len(events) {
			t.Errorf("grouping by %s clustered %d of %d events", key, total, len(events))
		}
	}
}

// An event with no value for the key is named, not dropped.
func TestClusterNamesUnattributedEvents(t *testing.T) {
	got := clusterEvents([]store.Event{ev("09:42:11", "", "", "a")}, groupByHost)
	if len(got) != 1 {
		t.Fatalf("%d clusters, want 1", len(got))
	}
	if got[0].Label != "unattributed" {
		t.Errorf("label = %q, want it named rather than blank", got[0].Label)
	}
}

// Time grouping truncates to the window, so two events either side of a
// boundary are not clustered merely because they are close together.
func TestClusterByTimeUsesWindowBoundaries(t *testing.T) {
	events := []store.Event{
		ev("09:44:59", "h", "p", "a"),
		ev("09:45:01", "h", "p", "b"),
	}
	got := clusterEvents(events, groupByTime)
	if len(got) != 2 {
		t.Fatalf("%d clusters, want 2 — events 2 seconds apart across a window boundary", len(got))
	}

	// And two inside one window are one cluster.
	together := clusterEvents([]store.Event{
		ev("09:45:01", "h", "p", "a"),
		ev("09:49:59", "h", "p", "b"),
	}, groupByTime)
	if len(together) != 1 {
		t.Errorf("%d clusters, want 1 for two events inside one window", len(together))
	}
}

func TestClusterSpanAndHeader(t *testing.T) {
	c := clusterEvents([]store.Event{
		ev("09:42:11", "FIN-02", "p", "a"),
		ev("09:48:30", "FIN-02", "p", "b"),
	}, groupByHost)[0]

	if got := c.Span(); got != "09:42–09:48" {
		t.Errorf("span = %q, want 09:42–09:48", got)
	}
	if got := c.Header(); got != "FIN-02 · 09:42–09:48 · 2 events" {
		t.Errorf("header = %q", got)
	}

	// A single event reads as one stamp and one event, not a range of nothing.
	one := clusterEvents([]store.Event{ev("10:20:00", "dc-01", "p", "a")}, groupByHost)[0]
	if got := one.Header(); got != "dc-01 · 10:20 · 1 event" {
		t.Errorf("single-event header = %q", got)
	}
}

func TestGroupKeyCycles(t *testing.T) {
	want := []string{"process", "time", "none", "host"}
	k := groupByHost
	for i, name := range want {
		k = k.next()
		if k.String() != name {
			t.Fatalf("step %d = %q, want %q", i, k.String(), name)
		}
	}
}

func TestClusterEmptyInput(t *testing.T) {
	if got := clusterEvents(nil, groupByHost); got != nil {
		t.Errorf("clustering nothing produced %d clusters", len(got))
	}
}

// ---------------------------------------------------------------------------

// Pivot targets come from the observables table, so the pivot is an indexed
// lookup on (type_id, value) rather than a text scan.
func TestPivotTargetsCarryTheIndexedKey(t *testing.T) {
	got := pivotTargets([]store.Observable{
		{TypeID: 2, Type: "IP Address", Value: "203.0.113.9"},
	})
	if len(got) != 1 {
		t.Fatalf("%d targets, want 1", len(got))
	}
	if got[0].TypeID != 2 || got[0].Value != "203.0.113.9" {
		t.Errorf("target = %+v, want the observable's type and value", got[0])
	}
	if got[0].Kind != "IP Address" {
		t.Errorf("kind = %q", got[0].Kind)
	}
}

// The same address as both source and destination is one thing to pivot on.
func TestPivotTargetsDeduplicate(t *testing.T) {
	got := pivotTargets([]store.Observable{
		{TypeID: 2, Type: "IP Address", Value: "203.0.113.9", Name: "src_endpoint.ip"},
		{TypeID: 2, Type: "IP Address", Value: "203.0.113.9", Name: "dst_endpoint.ip"},
		{TypeID: 1, Type: "Hostname", Value: "FIN-02"},
	})
	if len(got) != 2 {
		t.Fatalf("%d targets, want 2 distinct entities from 3 sightings", len(got))
	}
}

// The same type and different values are different targets; the same value
// under different types likewise.
func TestPivotTargetsKeyOnBothTypeAndValue(t *testing.T) {
	got := pivotTargets([]store.Observable{
		{TypeID: 2, Type: "IP", Value: "203.0.113.9"},
		{TypeID: 2, Type: "IP", Value: "198.51.100.4"},
		{TypeID: 9, Type: "Hash", Value: "203.0.113.9"},
	})
	if len(got) != 3 {
		t.Errorf("%d targets, want 3", len(got))
	}
}

// A stable order, or the menu reshuffles between openings and muscle memory
// selects the wrong entity.
func TestPivotTargetsAreOrderedStably(t *testing.T) {
	in := []store.Observable{
		{TypeID: 2, Type: "IP Address", Value: "203.0.113.9"},
		{TypeID: 1, Type: "Hostname", Value: "WS-17"},
		{TypeID: 2, Type: "IP Address", Value: "198.51.100.4"},
	}
	first := pivotTargets(in)
	for i := 0; i < 5; i++ {
		again := pivotTargets(in)
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d differs at %d: %+v vs %+v", i, j, again[j], first[j])
			}
		}
	}
	if first[0].Kind != "Hostname" {
		t.Errorf("first target is %q, want the order sorted by kind", first[0].Kind)
	}
}

func TestPivotTargetsSkipBlanks(t *testing.T) {
	got := pivotTargets([]store.Observable{
		{TypeID: 2, Type: "IP", Value: "  "},
		{TypeID: 1, Type: "Hostname", Value: "WS-17"},
	})
	if len(got) != 1 {
		t.Errorf("%d targets, want the blank one skipped", len(got))
	}
}

// An observable with no type still gets a label, so the menu never shows a
// nameless row.
func TestObservableKindFallsBack(t *testing.T) {
	if got := observableKind(store.Observable{TypeID: 7, Name: "process.name"}); got != "process.name" {
		t.Errorf("kind = %q, want the name when the type is blank", got)
	}
	if got := observableKind(store.Observable{TypeID: 7}); got != "type 7" {
		t.Errorf("kind = %q, want a fallback naming the type id", got)
	}
}

// A time-grouped cluster's label is already a time, so the header must not say
// it twice: "10:05 · 10:05 · 1 event" reads as a bug.
func TestTimeClusterHeaderDoesNotRepeatItself(t *testing.T) {
	c := clusterEvents([]store.Event{ev("10:05:30", "fw-edge-01", "p", "a")}, groupByTime)[0]
	if got := c.Header(); got != "10:05 · 1 event" {
		t.Errorf("header = %q, want the window stated once", got)
	}

	// The entity groupings still name their entity.
	h := clusterEvents([]store.Event{ev("10:05:30", "fw-edge-01", "p", "a")}, groupByHost)[0]
	if got := h.Header(); got != "fw-edge-01 · 10:05 · 1 event" {
		t.Errorf("host header = %q", got)
	}
}
