package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

func indicatorStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "indicators.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// seedObservedEvent writes an event carrying observables, attached to no case.
func seedObservedEvent(t *testing.T, st *Store, uid, host, ip string, at time.Time) string {
	t.Helper()
	ev := &ocsf.Event{
		Time: at, ClassUID: 4001, ActivityID: 1, TypeUID: 400101,
		SeverityID: ocsf.SeverityLow, Message: "seed",
		Device:      &ocsf.Device{Hostname: host},
		SrcEndpoint: &ocsf.Endpoint{IP: ip},
	}
	ev.Metadata.UID = uid
	id, err := st.SaveEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("seed %s: %v", uid, err)
	}
	return id
}

// An indicator on nothing but an event is still an indicator.
//
// The Indicators screen was built by looping the case list, so it could only
// show what had already been attached to a case: a database full of findings
// and no cases rendered an empty screen over a full observables table.
func TestListIndicatorsSeesObservablesWithNoCase(t *testing.T) {
	st := indicatorStore(t)
	seedObservedEvent(t, st, "e1", "workstation-14", "198.51.100.73", time.Now())

	got, err := st.ListIndicators(context.Background(), IndicatorFilter{Limit: 50})
	if err != nil {
		t.Fatalf("ListIndicators: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no indicators from an event attached to no case")
	}

	values := map[string]bool{}
	for _, i := range got {
		values[i.Value] = true
	}
	for _, want := range []string{"workstation-14", "198.51.100.73"} {
		if !values[want] {
			t.Errorf("the indicator %q is missing: %+v", want, got)
		}
	}
}

// Most widely seen first, so the page a screen shows is the useful one.
func TestListIndicatorsOrdersBySightings(t *testing.T) {
	st := indicatorStore(t)
	now := time.Now()
	// workstation-14 three times, workstation-99 once.
	seedObservedEvent(t, st, "e1", "workstation-14", "10.0.0.1", now)
	seedObservedEvent(t, st, "e2", "workstation-14", "10.0.0.2", now)
	seedObservedEvent(t, st, "e3", "workstation-14", "10.0.0.3", now)
	seedObservedEvent(t, st, "e4", "workstation-99", "10.0.0.4", now)

	got, err := st.ListIndicators(context.Background(), IndicatorFilter{Limit: 50})
	if err != nil {
		t.Fatalf("ListIndicators: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no indicators")
	}
	if got[0].Value != "workstation-14" || got[0].Sightings != 3 {
		t.Errorf("first row is %q with %d sightings, want workstation-14 with 3",
			got[0].Value, got[0].Sightings)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Sightings > got[i-1].Sightings {
			t.Errorf("row %d has more sightings than the row above it: %+v", i, got)
		}
	}
}

func TestListIndicatorsSearchesTheValue(t *testing.T) {
	st := indicatorStore(t)
	now := time.Now()
	seedObservedEvent(t, st, "e1", "workstation-14", "198.51.100.73", now)
	seedObservedEvent(t, st, "e2", "build-agent-03", "10.0.0.9", now)

	got, err := st.ListIndicators(context.Background(), IndicatorFilter{Search: "WORKSTATION", Limit: 50})
	if err != nil {
		t.Fatalf("ListIndicators: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("search returned %d rows, want the one host: %+v", len(got), got)
	}
	if got[0].Value != "workstation-14" {
		t.Errorf("search returned %q", got[0].Value)
	}
}

// A limit is not optional: a screen must never read a million rows into a table.
func TestListIndicatorsPagesAndCounts(t *testing.T) {
	st := indicatorStore(t)
	now := time.Now()
	for i := 0; i < 6; i++ {
		seedObservedEvent(t, st, string(rune('a'+i)),
			"host-"+string(rune('a'+i)), "10.0.0."+string(rune('1'+i)), now)
	}

	total, err := st.CountIndicators(context.Background(), IndicatorFilter{})
	if err != nil {
		t.Fatalf("CountIndicators: %v", err)
	}
	if total < 12 {
		t.Fatalf("counted %d indicators, want the 12 seeded", total)
	}

	page, err := st.ListIndicators(context.Background(), IndicatorFilter{Limit: 5})
	if err != nil {
		t.Fatalf("ListIndicators: %v", err)
	}
	if len(page) != 5 {
		t.Errorf("the page holds %d rows, want 5", len(page))
	}

	second, err := st.ListIndicators(context.Background(), IndicatorFilter{Limit: 5, Offset: 5})
	if err != nil {
		t.Fatalf("ListIndicators: %v", err)
	}
	if len(second) == 0 {
		t.Error("the second page is empty")
	}
	if len(second) > 0 && second[0].Value == page[0].Value {
		t.Error("the second page repeats the first")
	}
}

// An empty database is an empty list, not an error and not a nil the caller has
// to special-case.
func TestListIndicatorsOnAnEmptyStore(t *testing.T) {
	got, err := indicatorStore(t).ListIndicators(context.Background(), IndicatorFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListIndicators: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("got %+v, want an empty list", got)
	}
}
