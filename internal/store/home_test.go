package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

func homeStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "home.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// seedFinding writes one finding with the fields the priority queue orders on.
func seedFinding(t *testing.T, st *Store, uid string, risk, sevID, statusID int, lastSeen time.Time) {
	t.Helper()
	f := &ocsf.Finding{
		FindingInfo: ocsf.FindingInfo{
			UID:           uid,
			Title:         "finding " + uid,
			FirstSeenTime: lastSeen,
			LastSeenTime:  lastSeen,
		},
		StatusID:  statusID,
		RiskScore: risk,
	}
	f.ClassUID = ocsf.ClassDetectionFinding
	f.CategoryUID = ocsf.CategoryFindings
	f.SeverityID = sevID
	f.Time = lastSeen
	if _, err := st.SaveFinding(context.Background(), f); err != nil {
		t.Fatalf("seed %s: %v", uid, err)
	}
}

// seedCase creates a case and returns its id.
func seedCase(t *testing.T, st *Store, title string, statusID int) string {
	t.Helper()
	id, err := st.CreateOrUpdateCase(context.Background(), Case{
		Title: title, Status: CaseStatusLabelFor(statusID), StatusID: statusID,
	})
	if err != nil {
		t.Fatalf("seed case %q: %v", title, err)
	}
	return id
}

// seedEvent writes one event at a given time, with optional endpoints so the
// store derives observables from it.
func seedEvent(t *testing.T, st *Store, uid string, ts time.Time, srcIP, host string) {
	t.Helper()
	ev := &ocsf.Event{
		Time:       ts,
		ClassUID:   4001,
		ActivityID: 1,
		TypeUID:    400101,
		SeverityID: ocsf.SeverityMedium,
		Message:    uid,
	}
	ev.Metadata.UID = uid
	if srcIP != "" {
		ev.SrcEndpoint = &ocsf.Endpoint{IP: srcIP}
	}
	if host != "" {
		ev.Device = &ocsf.Device{Hostname: host}
	}
	if _, err := st.SaveEvent(context.Background(), ev); err != nil {
		t.Fatalf("seed event %s: %v", uid, err)
	}
}

// touch sets a case's updated_at directly, so ordering tests do not depend on
// how many cases fit inside one second.
func touch(t *testing.T, st *Store, caseID string, at time.Time) {
	t.Helper()
	if _, err := st.db.Exec(`UPDATE cases SET updated_at = ? WHERE id = ?`, at.Unix(), caseID); err != nil {
		t.Fatalf("touch %s: %v", caseID, err)
	}
}

func uids(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.FindingUID
	}
	return out
}

// The priority queue's whole reason to exist is the ordering. The panel is
// named for it, so an unordered queue is worse than no queue: it asserts a
// ranking it does not apply.
func TestPriorityQueueOrdering(t *testing.T) {
	st := homeStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	// Deliberately seeded in an order that is neither the answer nor its
	// reverse, so a query that forgets to sort cannot pass by luck.
	seedFinding(t, st, "c-mid-risk", 55, ocsf.SeverityMedium, ocsf.FindingStatusNew, now.Add(-2*time.Hour))
	seedFinding(t, st, "a-top-risk", 98, ocsf.SeverityCritical, ocsf.FindingStatusNew, now.Add(-3*time.Minute))
	seedFinding(t, st, "e-no-risk", 0, ocsf.SeverityLow, ocsf.FindingStatusNew, now.Add(-30*time.Minute))
	seedFinding(t, st, "b-high-risk", 87, ocsf.SeverityHigh, ocsf.FindingStatusNew, now.Add(-12*time.Minute))
	seedFinding(t, st, "d-low-risk", 30, ocsf.SeverityLow, ocsf.FindingStatusNew, now.Add(-time.Hour))

	got, err := st.GetPriorityQueue(ctx, 5)
	if err != nil {
		t.Fatalf("GetPriorityQueue: %v", err)
	}

	want := []string{"a-top-risk", "b-high-risk", "c-mid-risk", "d-low-risk", "e-no-risk"}
	for i := range want {
		if i >= len(got) || got[i].FindingUID != want[i] {
			t.Fatalf("order = %v, want %v", uids(got), want)
		}
	}
}

// Each tie-break has to be reached, or an untested rule is a rule that quietly
// does nothing.
func TestPriorityQueueTieBreaks(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	t.Run("severity breaks a risk tie", func(t *testing.T) {
		st := homeStore(t)
		seedFinding(t, st, "lower-sev", 50, ocsf.SeverityLow, ocsf.FindingStatusNew, now)
		seedFinding(t, st, "higher-sev", 50, ocsf.SeverityCritical, ocsf.FindingStatusNew, now)

		got, _ := st.GetPriorityQueue(context.Background(), 5)
		if len(got) != 2 || got[0].FindingUID != "higher-sev" {
			t.Errorf("order = %v, want the more severe finding first", uids(got))
		}
	})

	t.Run("newest breaks a severity tie", func(t *testing.T) {
		st := homeStore(t)
		seedFinding(t, st, "older", 50, ocsf.SeverityHigh, ocsf.FindingStatusNew, now.Add(-time.Hour))
		seedFinding(t, st, "newer", 50, ocsf.SeverityHigh, ocsf.FindingStatusNew, now)

		got, _ := st.GetPriorityQueue(context.Background(), 5)
		if len(got) != 2 || got[0].FindingUID != "newer" {
			t.Errorf("order = %v, want the newer finding first", uids(got))
		}
	})

	t.Run("new before in progress", func(t *testing.T) {
		st := homeStore(t)
		seedFinding(t, st, "in-progress", 50, ocsf.SeverityHigh, ocsf.FindingStatusInProgress, now)
		seedFinding(t, st, "new", 50, ocsf.SeverityHigh, ocsf.FindingStatusNew, now)

		got, _ := st.GetPriorityQueue(context.Background(), 5)
		if len(got) != 2 || got[0].FindingUID != "new" {
			t.Errorf("order = %v, want the untouched finding first", uids(got))
		}
	})
}

// Two renders of unchanged data must produce the same order. Without a final
// tie-break the rows swap between refreshes, which reads as the screen
// flickering rather than as a sort that never settled.
func TestPriorityQueueIsDeterministic(t *testing.T) {
	st := homeStore(t)
	now := time.Now().Truncate(time.Second)

	// Every orderable field identical; only the uid differs.
	for _, uid := range []string{"zulu", "alpha", "mike", "bravo"} {
		seedFinding(t, st, uid, 70, ocsf.SeverityHigh, ocsf.FindingStatusNew, now)
	}

	first, err := st.GetPriorityQueue(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := st.GetPriorityQueue(context.Background(), 5)
		if err != nil {
			t.Fatal(err)
		}
		for j := range first {
			if again[j].FindingUID != first[j].FindingUID {
				t.Fatalf("run %d = %v, first run = %v", i, uids(again), uids(first))
			}
		}
	}

	if got := uids(first); got[0] != "alpha" {
		t.Errorf("order = %v, want the uid tie-break to sort ascending", got)
	}
}

func TestPriorityQueueExcludesClosedFindings(t *testing.T) {
	st := homeStore(t)
	now := time.Now()

	seedFinding(t, st, "open", 10, ocsf.SeverityLow, ocsf.FindingStatusNew, now)
	seedFinding(t, st, "resolved", 99, ocsf.SeverityCritical, ocsf.FindingStatusResolved, now)

	got, err := st.GetPriorityQueue(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].FindingUID != "open" {
		t.Errorf("queue = %v, want only the open finding despite the closed one scoring higher", uids(got))
	}
}

func TestPriorityQueueRespectsLimit(t *testing.T) {
	st := homeStore(t)
	now := time.Now()
	for _, uid := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		seedFinding(t, st, uid, 50, ocsf.SeverityHigh, ocsf.FindingStatusNew, now)
	}

	got, err := st.GetPriorityQueue(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("got %d findings, want 5", len(got))
	}
}

// The breakdown must sum to the total, or the card contradicts itself.
func TestCountOpenFindingsBucketsSumToTotal(t *testing.T) {
	st := homeStore(t)
	now := time.Now()

	for i, sev := range []int{
		ocsf.SeverityCritical, ocsf.SeverityFatal,
		ocsf.SeverityHigh, ocsf.SeverityHigh,
		ocsf.SeverityMedium,
		ocsf.SeverityLow,
		ocsf.SeverityInformational, ocsf.SeverityUnknown, ocsf.SeverityOther,
	} {
		seedFinding(t, st, string(rune('a'+i)), 10, sev, ocsf.FindingStatusNew, now)
	}

	f, err := st.CountOpenFindings(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if f.Total != 9 {
		t.Errorf("total = %d, want 9", f.Total)
	}
	// Fatal counts as critical; Other and Unknown fall to info rather than
	// being counted as more severe than Fatal.
	if f.Critical != 2 {
		t.Errorf("critical = %d, want 2 (critical + fatal)", f.Critical)
	}
	if f.High != 2 || f.Medium != 1 || f.Low != 1 {
		t.Errorf("high/medium/low = %d/%d/%d, want 2/1/1", f.High, f.Medium, f.Low)
	}
	if f.Info != 3 {
		t.Errorf("info = %d, want 3 (informational + unknown + other)", f.Info)
	}

	if sum := f.Critical + f.High + f.Medium + f.Low + f.Info; sum != f.Total {
		t.Errorf("buckets sum to %d but total is %d", sum, f.Total)
	}
}

func TestCountOpenFindingsOnAnEmptyDatabase(t *testing.T) {
	f, err := homeStore(t).CountOpenFindings(context.Background())
	if err != nil {
		t.Fatalf("an empty database must not be an error: %v", err)
	}
	if f.Total != 0 {
		t.Errorf("total = %d, want 0", f.Total)
	}
}

func TestCountActiveCases(t *testing.T) {
	st := homeStore(t)
	ctx := context.Background()

	seedCase(t, st, "triage me", ocsf.IncidentStatusNew)
	seedCase(t, st, "working on it", ocsf.IncidentStatusInProgress)
	seedCase(t, st, "also working", ocsf.IncidentStatusInProgress)
	seedCase(t, st, "done", ocsf.IncidentStatusResolved)
	seedCase(t, st, "shut", ocsf.IncidentStatusClosed)

	got, err := st.CountActiveCases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 3 {
		t.Errorf("total = %d, want 3 active (resolved and closed are not active)", got.Total)
	}
	if got.Investigating != 2 {
		t.Errorf("investigating = %d, want 2", got.Investigating)
	}
	if got.OldestOpened.IsZero() {
		t.Error("oldest opened is zero with three active cases")
	}
}

func TestCountActiveCasesOnAnEmptyDatabase(t *testing.T) {
	got, err := homeStore(t).CountActiveCases(context.Background())
	if err != nil {
		t.Fatalf("an empty database must not be an error: %v", err)
	}
	if got.Total != 0 || !got.OldestOpened.IsZero() {
		t.Errorf("got %+v, want a zero value", got)
	}
}

// "Today" is the analyst's today. A UTC boundary would empty the card at 7pm
// in Sydney and fill it at 7pm in Los Angeles.
func TestCountEventsTodayUsesLocalMidnight(t *testing.T) {
	st := homeStore(t)
	ctx := context.Background()
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	seedEvent(t, st, "yesterday", midnight.Add(-time.Minute), "", "")
	seedEvent(t, st, "just-after-midnight", midnight.Add(time.Minute), "", "")
	seedEvent(t, st, "recent", now.Add(-time.Minute), "", "")

	n, err := st.CountEventsToday(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("events today = %d, want 2 (the one before midnight is not today)", n)
	}
}

// Indicators are counted by identity, not by sighting: the same address seen in
// four hundred events is one indicator, and a card that says 400 is useless.
func TestCountObservablesCountsDistinctIndicators(t *testing.T) {
	st := homeStore(t)
	ctx := context.Background()

	// The same address twice, from two events, plus one hostname. Three
	// sightings of two indicators.
	seedEvent(t, st, "e1", time.Now(), "203.0.113.5", "WS-17")
	seedEvent(t, st, "e2", time.Now(), "203.0.113.5", "")

	n, err := st.CountObservables(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("observables = %d, want 2 distinct indicators from 3 sightings", n)
	}
}

func TestGetLastEvent(t *testing.T) {
	st := homeStore(t)
	ctx := context.Background()

	// A database with no events is not an error; it is a different message.
	if _, ok, err := st.GetLastEvent(ctx); err != nil || ok {
		t.Fatalf("empty database: ok = %v, err = %v; want false, nil", ok, err)
	}

	newest := time.Now().Truncate(time.Second)
	for i, ts := range []time.Time{newest.Add(-time.Hour), newest, newest.Add(-time.Minute)} {
		seedEvent(t, st, string(rune('a'+i)), ts, "", "")
	}

	got, ok, err := st.GetLastEvent(ctx)
	if err != nil || !ok {
		t.Fatalf("ok = %v, err = %v", ok, err)
	}
	if !got.Equal(newest) {
		t.Errorf("last event = %s, want %s", got, newest)
	}
}

// Recent means recently worked on. Ordering by creation would show the case
// opened first rather than the one being resumed.
func TestGetRecentCasesOrdersByUpdate(t *testing.T) {
	st := homeStore(t)
	ctx := context.Background()

	first := seedCase(t, st, "opened first", ocsf.IncidentStatusNew)
	second := seedCase(t, st, "opened second", ocsf.IncidentStatusNew)

	// updated_at has one-second resolution, so two cases seeded in the same
	// second would tie and fall through to creation order — which is the very
	// thing this test exists to rule out. Set the timestamps explicitly: the
	// older case was worked on since, the newer one has been untouched.
	touch(t, st, first, time.Now())
	touch(t, st, second, time.Now().Add(-time.Hour))

	got, err := st.GetRecentCases(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d cases, want 2", len(got))
	}
	if got[0].Title != "opened first" {
		t.Errorf("first = %q, want the most recently updated case", got[0].Title)
	}
}

func TestGetRecentCasesExcludesClosed(t *testing.T) {
	st := homeStore(t)
	ctx := context.Background()

	seedCase(t, st, "open", ocsf.IncidentStatusNew)
	seedCase(t, st, "closed", ocsf.IncidentStatusClosed)

	got, err := st.GetRecentCases(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Title != "open" {
		t.Errorf("cases = %d, want only the open one", len(got))
	}
}

// Every Home query is issued concurrently and must honour cancellation, or a
// screen the analyst has already left keeps the database busy.
func TestHomeQueriesHonourCancellation(t *testing.T) {
	st := homeStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := st.CountOpenFindings(ctx); err == nil {
		t.Error("CountOpenFindings ignored a cancelled context")
	}
	if _, err := st.CountActiveCases(ctx); err == nil {
		t.Error("CountActiveCases ignored a cancelled context")
	}
	if _, err := st.CountObservables(ctx); err == nil {
		t.Error("CountObservables ignored a cancelled context")
	}
	if _, err := st.GetPriorityQueue(ctx, 5); err == nil {
		t.Error("GetPriorityQueue ignored a cancelled context")
	}
	if _, err := st.GetRecentCases(ctx, 5); err == nil {
		t.Error("GetRecentCases ignored a cancelled context")
	}
	if _, _, err := st.GetLastEvent(ctx); err == nil {
		t.Error("GetLastEvent ignored a cancelled context")
	}
}
