package ui

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// tview's queued updates block the caller until the event loop runs them.
//
// Both QueueUpdate and QueueUpdateDraw send on the application's update channel
// and then wait on an unbuffered done channel that only the event loop closes.
// Several comments in this package call QueueUpdate "non-blocking"; for the
// pinned version that is simply wrong, and the difference is a deadlock rather
// than a slow repaint.
//
// ui.queueUpdate (ui.go) is the guarded form: it runs the function inline when
// the loop is not running. Everything that can be reached from startup, from
// shutdown, or from a test has to go through it — which is nearly everything,
// because a load path does not know which of those it is on.
//
// These are the three places allowed to call the raw form, each for a reason
// that does not generalise.
var rawQueueUpdateAllowed = map[string]string{
	"the redraw heartbeat": "a repaint request with no work in it, already behind its own running check",
	"setStatus":            "does the same running check itself, one line above the call",
	"queueUpdate":          "is the guarded form",
}

// TestQueueUpdateGoesThroughTheGuard fails when a new raw call appears.
//
// Counting rather than forbidding: the case-management screen has its own set
// that this plan does not touch, and a budget makes the remaining debt visible
// instead of pretending it is not there.
func TestQueueUpdateGoesThroughTheGuard(t *testing.T) {
	budget := len(rawQueueUpdateAllowed)

	found := 0
	var where []string

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "ui.app.QueueUpdate") {
				found++
				where = append(where, name+":"+itoa(i+1)+"  "+strings.TrimSpace(line))
			}
		}
	}

	if found > budget {
		t.Errorf("%d raw ui.app.QueueUpdate calls, budget is %d — use ui.queueUpdate:\n  %s",
			found, budget, strings.Join(where, "\n  "))
	}
	if found < budget {
		t.Errorf("only %d raw calls left but the budget is still %d — lower it", found, budget)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A screen must be enterable without a running event loop.
//
// This is the test the whole guard exists for. Every later phase wants "seed a
// store, enter the screen, assert on what was rendered", and until now that
// deadlocked instead of failing: switchToAllEvents reaches updateCasesList and
// the load paths, which queued against a loop that was never going to run.
func TestScreensAreEnterableWithoutTheEventLoop(t *testing.T) {
	withTempConfig(t)

	st, err := store.NewStore(filepath.Join(t.TempDir(), "screens.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// One UI per screen. Driving three switches back to back through a single
	// UI races the load goroutine each one spawns against the next switch —
	// which is a real defect, but it is the shared load guard's, not this
	// test's, and it is repaired separately.
	for _, tc := range []struct {
		name string
		open func(*UI)
	}{
		{"events", (*UI).switchToAllEvents},
		{"cases", (*UI).switchToCases},
		{"indicators", (*UI).switchToIndicators},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			ui := NewUI(ctx, st, nil, logging.New(io.Discard, logging.LevelError, "test"), "test")

			done := make(chan string, 1)
			go func() {
				if err := ui.refreshCases(); err != nil {
					done <- "refreshCases: " + err.Error()
					return
				}
				tc.open(ui)
				done <- ""
			}()

			// A generous bound. The point is that this returns at all — before
			// the guard it blocked forever on a channel nothing was draining.
			select {
			case msg := <-done:
				if msg != "" {
					t.Fatal(msg)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("entering this screen blocked with no event loop running — " +
					"a load path is queueing against an application that will never drain it")
			}

			// Entering a screen spawns its load and returns. Leaving that
			// goroutine running past the subtest lets it write through a
			// temporary config directory that has already been cleaned up, and
			// into whichever test set one up next.
			awaitIdle(t, ui)
		})
	}
}

// awaitIdle waits for a screen's load goroutines to finish.
//
// Deterministic, not a poll: entering a screen spawns its load and returns
// before that goroutine has run, so polling a busy flag cannot tell "not
// started" from "finished" and lets the goroutine outlive the test.
func awaitIdle(t *testing.T, ui *UI) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		ui.waitForLoads()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("a load goroutine was still running when the screen test ended")
	}
}
