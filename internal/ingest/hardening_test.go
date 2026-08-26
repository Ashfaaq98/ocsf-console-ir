package ingest

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// A host-less bind listens on every interface, so it must demand a token just
// as 0.0.0.0 does. Classifying it as loopback handed an unauthenticated write
// into the analyst's cases to anyone who could reach the machine.
func TestHostlessBindIsNotLoopback(t *testing.T) {
	for _, bind := range []string{":8081", ":0", ":1234"} {
		if isLocalhostBind(bind) {
			t.Errorf("isLocalhostBind(%q) = true, but that listens on every interface", bind)
		}
		if _, err := NewHTTPIngestServer(HTTPIngestOptions{Bind: bind, Dir: t.TempDir()}); err == nil {
			t.Errorf("a token-less receiver on %q was accepted", bind)
		}
	}
	for _, bind := range []string{"127.0.0.1:8081", "localhost:8081", "[::1]:8081"} {
		if !isLocalhostBind(bind) {
			t.Errorf("isLocalhostBind(%q) = false, but it reaches only this machine", bind)
		}
	}
}

func startReceiver(t *testing.T) (*HTTPIngestServer, string) {
	t.Helper()
	srv, err := NewHTTPIngestServer(HTTPIngestOptions{Bind: "127.0.0.1:0", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })
	return srv, "http://" + srv.Address() + "/ingest"
}

// A loopback bind is not an authentication boundary: any page the analyst opens
// can post to it, and the body-shape sniffing means no preflight is triggered.
func TestCrossSiteAndReboundOriginsAreRefused(t *testing.T) {
	srv, url := startReceiver(t)
	body := `{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,"severity_id":3,"time":1700000000,"message":"x"}`

	post := func(hdr map[string]string) int {
		req, _ := http.NewRequest("POST", url, strings.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		for k, v := range hdr {
			if k == "Host" {
				req.Host = v
				continue
			}
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := post(map[string]string{"Origin": "https://evil.example"}); got != http.StatusForbidden {
		t.Errorf("a cross-site page got %d, want 403", got)
	}
	if got := post(map[string]string{"Origin": "null"}); got != http.StatusForbidden {
		t.Errorf("a file:// or sandboxed page got %d, want 403", got)
	}
	if got := post(map[string]string{"Host": "attacker.example:1234"}); got != http.StatusForbidden {
		t.Errorf("a DNS-rebound origin got %d, want 403", got)
	}
	// A forwarder sends no Origin and posts to the address it was given.
	if got := post(nil); got != http.StatusAccepted {
		t.Errorf("a plain forwarder got %d, want 202", got)
	}
	// The browser's own same-origin POST still works.
	if got := post(map[string]string{"Origin": "http://" + srv.Address()}); got != http.StatusAccepted {
		t.Errorf("a same-origin post got %d, want 202", got)
	}
}

// Nothing deletes an ingested payload and the startup scan reads everything it
// finds, so without a persisted mark every restart re-ingested the whole
// accumulated drop folder.
func TestAParkedJSONSurvivesRestartsWithoutDuplicating(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "parked.json"), []byte(offsetTestEvent), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.NewStore(filepath.Join(dir, "case.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	for start := 1; start <= 4; start++ {
		// A fresh ingestor is a fresh process.
		ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
			Dir: dir, Watch: true, CaseTitle: "",
		})
		ing.loadOffsets()
		ing.loadMarks()
		if err := ing.scanOnce(ctx, true); err != nil {
			t.Fatalf("start %d: %v", start, err)
		}
		ing.saveOffsets()
		events, err := st.GetAllEvents(ctx, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatalf("after %d starts the parked file had produced %d event rows, want 1", start, len(events))
		}
	}
}

// A changed payload must still be read again after a restart.
func TestARewrittenParkedJSONIsIngestedAgain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "parked.json")
	os.WriteFile(path, []byte(offsetTestEvent), 0o600)
	st, _ := store.NewStore(filepath.Join(dir, "case.db"))
	defer st.Close()
	ctx := context.Background()

	run := func() {
		ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
			Dir: dir, Watch: true, CaseTitle: "",
		})
		ing.loadOffsets()
		ing.loadMarks()
		if err := ing.scanOnce(ctx, true); err != nil {
			t.Fatal(err)
		}
	}
	run()
	os.WriteFile(path, []byte(`{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,`+
		`"severity_id":3,"time":1700000001,"message":"rewritten","src_endpoint":{"ip":"10.0.0.9"}}`), 0o600)
	run()

	events, _ := st.GetAllEvents(ctx, 1000)
	if len(events) != 2 {
		t.Fatalf("a rewritten parked file produced %d event rows, want 2", len(events))
	}
}

// The pattern match only ever looked at the name. A named pipe blocks the open
// forever inside the single ingest goroutine; a symlink to an endless device
// allocates until the runtime dies. Both must be refused before anything opens
// them — and the watcher must keep working afterwards.
func TestNonRegularEntriesAreRefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "endless.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	// A real payload alongside them: the poison must not stop the good file.
	os.WriteFile(filepath.Join(dir, "real.json"), []byte(offsetTestEvent), 0o600)

	st, _ := store.NewStore(":memory:")
	defer st.Close()
	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir: dir, Watch: true, CaseTitle: "",
	})

	done := make(chan error, 1)
	go func() { done <- ing.scanOnce(context.Background(), true) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
	case <-timeoutAfter():
		t.Fatal("the scan blocked — an entry was opened that should have been refused")
	}
	if n := countEvents(t, st); n != 1 {
		t.Fatalf("got %d events, want 1 (the real payload, with the poison skipped)", n)
	}
}

// An oversized regular file is refused rather than read into memory.
func TestAnOversizedFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: an apparent size far past the cap, costing no disk.
	if err := f.Truncate(maxIngestFileBytes + 1); err != nil {
		f.Close()
		t.Skipf("sparse file unavailable: %v", err)
	}
	f.Close()

	if err := ingestEntryOK(path); err == nil {
		t.Fatal("an oversized file was accepted for reading")
	}
	st, _ := store.NewStore(":memory:")
	defer st.Close()
	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir: dir, Watch: true, CaseTitle: "",
	})
	if err := ing.scanOnce(context.Background(), true); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if n := countEvents(t, st); n != 0 {
		t.Fatalf("got %d events from an oversized file, want 0", n)
	}
}

// json.Valid already proves a body well-formed; decoding it again into an
// interface{} only materialised it at many times its size in live heap.
func TestValidateJSONDoesNotMaterialiseTheBody(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 200000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"class_uid":1002,"a":1}`)
	}
	b.WriteString("]")
	body := []byte(b.String())

	before := allocatedBytes()
	if err := validateJSON(body); err != nil {
		t.Fatalf("a valid body was rejected: %v", err)
	}
	allocated := allocatedBytes() - before

	// Scanning the body allocates almost nothing; decoding it into an
	// interface{} allocates many times its size. One body's worth of headroom
	// separates the two by an order of magnitude.
	if allocated > uint64(len(body)) {
		t.Errorf("validateJSON allocated %d bytes for a %d byte body — it is decoding it, not scanning it",
			allocated, len(body))
	}
	t.Logf("allocated %d bytes validating a %d byte body", allocated, len(body))

	if err := validateJSON([]byte(`{"a":`)); err == nil {
		t.Error("a malformed body was accepted")
	}
	if err := validateJSON([]byte(`"a string"`)); err == nil {
		t.Error("a non-object, non-array body was accepted")
	}
}
