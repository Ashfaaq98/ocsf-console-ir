package ingest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// A posted event reaches the database with no terminal involved.
//
// The receiver does not write to the database: it writes each payload as a file
// and the folder watcher is what reads those files in. That watcher used to
// start only alongside the interface, so headless the sender was told 202
// Accepted and the events sat on disk unread — a pipeline pointed at it looked
// healthy while losing everything.
func TestPostedEventsReachTheDatabaseHeadless(t *testing.T) {
	dir := t.TempDir()
	drop := filepath.Join(dir, "incoming")
	if err := os.MkdirAll(drop, 0o755); err != nil {
		t.Fatal(err)
	}

	st, err := store.NewStore(filepath.Join(dir, "headless.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	logger := logging.New(io.Discard, logging.LevelError, "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Both halves, as a headless run now starts them.
	ing := NewFolderIngestor(NewParser(), st, nil, FolderOptions{
		Dir: drop, Watch: true, Patterns: []string{"*.jsonl", "*.json"},
		Logger: logger, TailFromEnd: false,
	})
	go func() { _ = ing.Run(ctx) }()

	srv, err := NewHTTPIngestServer(HTTPIngestOptions{
		Bind: "127.0.0.1:0", Dir: drop, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	event := `{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,` +
		`"severity_id":3,"time":` + fmt.Sprint(time.Now().UnixMilli()) +
		`,"message":"posted without a terminal","metadata":{"uid":"posted-1","version":"1.8.0"}}`

	resp, err := http.Post("http://"+srv.Address()+"/ingest", "application/json",
		strings.NewReader(event))
	if err != nil {
		t.Fatalf("posting failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("post returned %d: %s", resp.StatusCode, body)
	}
	if got := srv.Received(); got != 1 {
		t.Errorf("the receiver counted %d payloads, want 1", got)
	}

	// The watcher has to notice the file and read it in.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		events, err := st.GetEvents(ctx, store.EventFilter{Limit: 10})
		if err == nil {
			for _, e := range events {
				if strings.Contains(e.Message, "posted without a terminal") {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("a posted event never reached the database — accepted and left on disk")
}

// The listener can be closed and reopened without restarting the process, which
// is what a toggle in the interface needs.
func TestTheListenerStopsAndStartsAgain(t *testing.T) {
	dir := t.TempDir()
	logger := logging.New(io.Discard, logging.LevelError, "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := NewHTTPIngestServer(HTTPIngestOptions{
		Bind: "127.0.0.1:0", Dir: dir, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	if srv.Listening() {
		t.Fatal("a receiver reports itself listening before it was started")
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !srv.Listening() {
		t.Fatal("a started receiver does not report itself listening")
	}
	// It knows where it actually bound, not what it was asked for.
	if srv.Address() == "127.0.0.1:0" {
		t.Error("the receiver reports the port it was asked for rather than the one it got")
	}

	srv.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for srv.Listening() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Listening() {
		t.Fatal("the receiver was still listening after being stopped")
	}
}
