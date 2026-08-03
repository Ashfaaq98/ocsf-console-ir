package store

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

// fileStore opens a file-backed store.
//
// Not :memory: — that pins the pool to a single connection, which is exactly
// the contention this file is about, so an in-memory store cannot see the bug.
func fileStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "concurrency.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testEvent(i int) *ocsf.Event {
	return &ocsf.Event{
		ClassUID: 4001, CategoryUID: 4, SeverityID: 3,
		Time:    time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second),
		Message: fmt.Sprintf("event %d", i),
	}
}

func testFinding(i int) *ocsf.Finding {
	return &ocsf.Finding{
		Event: ocsf.Event{
			ClassUID: 2004, CategoryUID: 2, SeverityID: 4,
			Time:    time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second),
			Message: fmt.Sprintf("finding %d", i),
		},
		FindingInfo: ocsf.FindingInfo{
			UID:   fmt.Sprintf("fnd-%d", i),
			Title: fmt.Sprintf("finding %d", i),
		},
	}
}

// Ingest and enrichment write at the same time, and SQLite allows one writer at
// a time. Every write must wait its turn rather than being dropped: three
// ingests of the same 15-event file used to give 15, 14 and 15.
func TestConcurrentWritesAreNotDropped(t *testing.T) {
	st := fileStore(t)
	ctx := context.Background()

	const writers, each = 4, 25

	var wg sync.WaitGroup
	errs := make(chan error, writers*each)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				n := w*each + i
				// Alternate the two write paths: SaveFinding is the one that
				// reads before it writes, which is where the upgrade failed.
				var err error
				if n%2 == 0 {
					_, err = st.SaveEvent(ctx, testEvent(n))
				} else {
					_, err = st.SaveFinding(ctx, testFinding(n))
				}
				if err != nil {
					errs <- fmt.Errorf("writer %d record %d: %w", w, n, err)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	var failures []error
	for err := range errs {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		t.Fatalf("%d of %d concurrent writes were dropped; first: %v",
			len(failures), writers*each, failures[0])
	}

	// Everything that was written is readable, so nothing was lost quietly.
	events, err := st.GetEvents(ctx, EventFilter{Limit: writers * each})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(events) != writers*each/2 {
		t.Errorf("stored %d events, want %d", len(events), writers*each/2)
	}
}

// Updating the same finding from several goroutines is the shape that fails
// worst: each transaction reads the existing row, then writes it back.
func TestConcurrentUpdatesToOneFindingSucceed(t *testing.T) {
	st := fileStore(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f := testFinding(0) // the same finding_uid every time
			f.Message = fmt.Sprintf("update %d", i)
			if _, err := st.SaveFinding(ctx, f); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("a read-then-write transaction was dropped: %v", err)
	}
}

// The DSN is what actually applies these settings; the constant only documents
// them. Bind the two together so a change to one cannot leave the other behind
// — the same drift that left foreign keys unenforced on the shipped build.
func TestDSNCarriesTheLockingSettings(t *testing.T) {
	if !strings.Contains(sqliteDSNParams, fmt.Sprint(sqliteBusyTimeoutMS)) {
		t.Errorf("the DSN %q does not carry the busy timeout of %d",
			sqliteDSNParams, sqliteBusyTimeoutMS)
	}
	if !strings.Contains(sqliteDSNParams, "busy_timeout") {
		t.Errorf("the DSN %q sets no busy timeout, so a blocked writer fails instead of waiting",
			sqliteDSNParams)
	}
	// Without this a deferred transaction upgrades from read to write and fails
	// on a stale snapshot, which no timeout can rescue.
	if !strings.Contains(sqliteDSNParams, "_txlock=immediate") {
		t.Errorf("the DSN %q leaves transactions deferred", sqliteDSNParams)
	}
	if !strings.Contains(sqliteDSNParams, "WAL") {
		t.Errorf("the DSN %q no longer enables WAL", sqliteDSNParams)
	}
}

// A caller that supplies a creation time means it: an imported incident, a note
// written to a point in an investigation, a seeded demo. Both paths used to
// stamp time.Now() over it while a branch two lines below already handled the
// zero case, so the field looked settable and silently was not.
func TestSuppliedCreationTimesAreKept(t *testing.T) {
	st := fileStore(t)
	ctx := context.Background()
	when := time.Date(2026, 7, 30, 14, 30, 0, 0, time.UTC)

	caseID, err := st.CreateOrUpdateCase(ctx, Case{
		Title: "backdated", Severity: "low", Status: "open", CreatedAt: when,
	})
	if err != nil {
		t.Fatalf("CreateOrUpdateCase: %v", err)
	}
	cases, err := st.ListCases(ctx)
	if err != nil {
		t.Fatalf("ListCases: %v", err)
	}
	var found bool
	for _, c := range cases {
		if c.ID != caseID {
			continue
		}
		found = true
		if !c.CreatedAt.Equal(when) {
			t.Errorf("case opened at %s, want %s", c.CreatedAt.UTC(), when)
		}
	}
	if !found {
		t.Fatal("the case was not stored")
	}

	if _, err := st.AddNote(ctx, Note{
		CaseID: caseID, Content: "written earlier", Author: "paolo", CreatedAt: when,
	}); err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	notes, err := st.GetNotes(ctx, caseID)
	if err != nil {
		t.Fatalf("GetNotes: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("stored %d notes, want 1", len(notes))
	}
	if !notes[0].CreatedAt.Equal(when) {
		t.Errorf("note written at %s, want %s", notes[0].CreatedAt.UTC(), when)
	}
}

// And a caller that supplies nothing still gets now, rather than the zero time.
func TestUnsetCreationTimesDefaultToNow(t *testing.T) {
	st := fileStore(t)
	ctx := context.Background()

	caseID, err := st.CreateOrUpdateCase(ctx, Case{Title: "fresh", Severity: "low", Status: "open"})
	if err != nil {
		t.Fatalf("CreateOrUpdateCase: %v", err)
	}
	cases, _ := st.ListCases(ctx)
	for _, c := range cases {
		if c.ID == caseID && c.CreatedAt.IsZero() {
			t.Error("a case with no creation time was stored at the zero time")
		}
	}
}
