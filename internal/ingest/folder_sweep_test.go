package ingest

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// newSweepIngestor builds a watch-mode ingestor over dir with no case
// assignment, so the tests below count events rather than case membership.
func newSweepIngestor(dir string, st *store.Store) *FolderIngestor {
	return NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir:       dir,
		Watch:     true,
		CaseTitle: "",
	})
}

func sweepStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// The sweep re-reads the whole directory, and a .json is re-read in full every
// time it is processed. Without a per-file mark, every .json left in the drop
// folder would be ingested again on every sweep — a single posted event turning
// into one row every few seconds for as long as the watcher runs.
func TestASecondSweepDoesNotReIngestTheSameJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.json"), []byte(offsetTestEvent), 0o600); err != nil {
		t.Fatal(err)
	}

	st := sweepStore(t)
	ing := newSweepIngestor(dir, st)
	ctx := context.Background()

	if err := ing.scanOnce(ctx, true); err != nil {
		t.Fatalf("initial scan: %v", err)
	}
	if n := countEvents(t, st); n != 1 {
		t.Fatalf("after the initial scan: got %d events, want 1", n)
	}

	for i := 0; i < 3; i++ {
		if err := ing.scanOnce(ctx, false); err != nil {
			t.Fatalf("sweep %d: %v", i, err)
		}
	}
	if n := countEvents(t, st); n != 1 {
		t.Fatalf("three sweeps over an unchanged file produced %d events, want 1", n)
	}
}

// The mark must not suppress a file that genuinely changed: a pipeline that
// rewrites the same filename has to be read again.
func TestASweepReReadsAChangedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rewritten.json")
	if err := os.WriteFile(path, []byte(offsetTestEvent), 0o600); err != nil {
		t.Fatal(err)
	}

	st := sweepStore(t)
	ing := newSweepIngestor(dir, st)
	ctx := context.Background()

	if err := ing.scanOnce(ctx, true); err != nil {
		t.Fatalf("initial scan: %v", err)
	}

	// A different event, and a size the mark cannot mistake for the old one.
	second := `{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,` +
		`"severity_id":3,"time":1700000001,"message":"rewritten in place",` +
		`"src_endpoint":{"ip":"10.0.0.6"}}`
	if err := os.WriteFile(path, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	// Some filesystems carry coarse modification times; make the change visible
	// even where only the second is recorded.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	if err := ing.scanOnce(ctx, false); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n := countEvents(t, st); n != 2 {
		t.Fatalf("a rewritten file produced %d events, want 2", n)
	}
}

// TailFromEnd exists to skip a backlog that was already on disk when the
// watcher started. Applying it on the periodic sweep would make a file that
// arrives later get skipped or ingested depending on whether the sweep or the
// fsnotify notification reached it first.
func TestTailFromEndAppliesOnlyToTheStartupPass(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "backlog.jsonl"),
		[]byte(offsetTestEvent+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	st := sweepStore(t)
	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir: dir, Watch: true, CaseTitle: "", TailFromEnd: true,
	})
	ctx := context.Background()

	if err := ing.scanOnce(ctx, true); err != nil {
		t.Fatalf("initial scan: %v", err)
	}
	if n := countEvents(t, st); n != 0 {
		t.Fatalf("the startup pass ingested %d events, want 0 — TailFromEnd skips backlog", n)
	}

	// A file that appears after startup is not backlog.
	if err := os.WriteFile(filepath.Join(dir, "arrived-later.jsonl"),
		[]byte(offsetTestEvent+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ing.scanOnce(ctx, false); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n := countEvents(t, st); n != 1 {
		t.Fatalf("a file that arrived after startup produced %d events, want 1", n)
	}
}

// The whole point of the sweep: watch mode reads the directory on its own
// schedule, so a create that fsnotify never reports is still picked up. The
// watcher is left running and nothing but the ticker is allowed to do the work.
func TestWatchModeSweepsWithoutAnyNotification(t *testing.T) {
	dir := t.TempDir()
	st := sweepStore(t)

	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir: dir, Watch: true, CaseTitle: "",
		SweepInterval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = ing.Run(ctx) }()

	// Let the watcher establish itself and make its startup pass.
	time.Sleep(200 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, "dropped.json"),
		[]byte(offsetTestEvent), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if countEvents(t, st) == 1 {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("a file dropped into a watched folder never reached the database")
}

// Writing a file emits Create and then Write. The watcher treated both as
// "re-read the whole file", so every .json dropped into the folder by a plain
// write was ingested twice. The HTTP receiver escaped it only because it writes
// to a .tmp- name and renames, which emits a single Create.
func TestADroppedJSONIsIngestedOnce(t *testing.T) {
	dir := t.TempDir()
	st := sweepStore(t)

	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir: dir, Watch: true, CaseTitle: "",
		SweepInterval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = ing.Run(ctx) }()
	time.Sleep(200 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, "dropped.json"),
		[]byte(offsetTestEvent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Long enough for both the Create and the Write notification to arrive and
	// for several sweeps to run over the file.
	time.Sleep(1 * time.Second)
	cancel()
	<-done

	if n := countEvents(t, st); n != 1 {
		t.Fatalf("one dropped file produced %d events, want 1", n)
	}
}

// The ticker in the watch loop used to only sync a case event count, so the
// directory was never re-read and a create fsnotify dropped meant the file was
// never ingested at all. Nothing on Linux notices, because fsnotify covers it —
// this asserts the sweep runs regardless of whether anything needed it.
func TestTheWatchLoopActuallySweeps(t *testing.T) {
	dir := t.TempDir()
	st := sweepStore(t)

	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir: dir, Watch: true, CaseTitle: "",
		SweepInterval: 20 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = ing.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&ing.sweeps) >= 3 {
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := atomic.LoadInt64(&ing.sweeps)
	cancel()
	<-done
	t.Fatalf("the watch loop swept %d times in 5s at a 20ms interval, want at least 3", got)
}

// SweepInterval is what bounds how long a missed notification can strand a
// file, so a zero value must not disable the sweep outright.
func TestZeroSweepIntervalFallsBackToTheDefault(t *testing.T) {
	ing := NewFolderIngestor(NewParser(), nil, bus.NewNullBus(nil), FolderOptions{
		Dir: t.TempDir(), Watch: true,
	})
	if ing.opts.SweepInterval != defaultSweepInterval {
		t.Fatalf("SweepInterval is %v, want the %v default", ing.opts.SweepInterval, defaultSweepInterval)
	}
}
