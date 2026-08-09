package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

func volumeStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "volume.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func seedEventAt(t *testing.T, st *Store, at time.Time, uid string) {
	t.Helper()
	ev := &ocsf.Event{
		Time: at, ClassUID: 4001, ActivityID: 1, TypeUID: 400101,
		SeverityID: ocsf.SeverityLow, Message: "seed",
	}
	ev.Metadata.UID = uid
	if _, err := st.SaveEvent(context.Background(), ev); err != nil {
		t.Fatalf("seed %s: %v", uid, err)
	}
}

// The buckets carry shape, which is the whole point: a total says nothing about
// whether the events arrived steadily or all at once.
func TestEventVolumeBucketsCountPerHour(t *testing.T) {
	st := volumeStore(t)
	now := time.Now()

	// Three in the current hour, one three hours back, nothing between.
	for i, at := range []time.Time{now, now, now, now.Add(-3 * time.Hour)} {
		seedEventAt(t, st, at, string(rune('a'+i)))
	}

	got, err := st.EventVolumeBuckets(context.Background(), now, 6)
	if err != nil {
		t.Fatalf("EventVolumeBuckets: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("got %d buckets, want 6: %v", len(got), got)
	}
	if last := got[len(got)-1]; last != 3 {
		t.Errorf("the current hour holds %d, want 3: %v", last, got)
	}
	if got[len(got)-4] != 1 {
		t.Errorf("three hours back holds %d, want 1: %v", got[len(got)-4], got)
	}
}

// A quiet hour is a zero, not a missing row. A caller drawing a sparkline needs
// one value per hour or the shape is a lie.
func TestEventVolumeBucketsFillQuietHours(t *testing.T) {
	st := volumeStore(t)
	now := time.Now()
	seedEventAt(t, st, now, "only")

	got, err := st.EventVolumeBuckets(context.Background(), now, 12)
	if err != nil {
		t.Fatalf("EventVolumeBuckets: %v", err)
	}
	if len(got) != 12 {
		t.Fatalf("got %d buckets, want 12", len(got))
	}
	for i, n := range got[:11] {
		if n != 0 {
			t.Errorf("bucket %d = %d, want 0: %v", i, n, got)
		}
	}
}

// An empty database is a flat line, not an error and not a nil slice the caller
// has to special-case.
func TestEventVolumeBucketsOnAnEmptyStore(t *testing.T) {
	got, err := volumeStore(t).EventVolumeBuckets(context.Background(), time.Now(), 24)
	if err != nil {
		t.Fatalf("EventVolumeBuckets: %v", err)
	}
	if len(got) != 24 {
		t.Fatalf("got %d buckets, want 24", len(got))
	}
	for _, n := range got {
		if n != 0 {
			t.Fatalf("an empty store reported events: %v", got)
		}
	}
}

func TestEventVolumeBucketsRejectsAnEmptyWindow(t *testing.T) {
	if got, err := volumeStore(t).EventVolumeBuckets(context.Background(), time.Now(), 0); err != nil || got != nil {
		t.Errorf("zero hours = (%v, %v), want (nil, nil)", got, err)
	}
}
