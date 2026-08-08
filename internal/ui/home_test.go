package ui

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// newTestHome builds a Home view over a real store, without running the
// application, so panels can be driven and read directly.
func newTestHome(t *testing.T) (*homeView, *store.Store) {
	t.Helper()
	withTempConfig(t)

	st, err := store.NewStore(filepath.Join(t.TempDir(), "home.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ui := NewUI(ctx, st, nil, logging.New(io.Discard, logging.LevelError, "test"), "test")
	h := newHomeView(ui)
	t.Cleanup(h.close)
	return h, st
}

// loadAndRender runs the queries synchronously and paints every panel, which is
// what start() does asynchronously.
func (h *homeView) loadAndRender(t *testing.T) {
	t.Helper()
	h.load()
	h.renderAll()
}

func seedTestFinding(t *testing.T, st *store.Store, uid string, risk, sevID, statusID int) {
	t.Helper()
	f := &ocsf.Finding{
		FindingInfo: ocsf.FindingInfo{UID: uid, Title: "finding " + uid},
		StatusID:    statusID,
		RiskScore:   risk,
	}
	f.ClassUID = ocsf.ClassDetectionFinding
	f.CategoryUID = ocsf.CategoryFindings
	f.SeverityID = sevID
	f.Time = time.Now()
	if _, err := st.SaveFinding(context.Background(), f); err != nil {
		t.Fatalf("seed %s: %v", uid, err)
	}
}

// A fresh database must not look broken. Every panel states what it is, why it
// is empty, and a way forward.
func TestHomeEmptyStates(t *testing.T) {
	h, _ := newTestHome(t)
	h.loadAndRender(t)

	lines := renderPrimitive(t, h.root, 140, 40)
	joined := strings.Join(lines, "\n")

	for _, want := range []string{
		"No findings yet.",
		"Press 3 to import events, or : then demo.",
		"No active investigations.",
		"no events yet",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("empty Home is missing %q\n%s", want, joined)
		}
	}

	// The cards read zero rather than blank.
	if !strings.Contains(joined, "00") {
		t.Errorf("metric cards do not show a zero count\n%s", joined)
	}
}

// The card is named for a count and a breakdown; both have to reach the screen.
// The card body has two rows, and a third line would silently never appear.
func TestHomeCardsRenderTheirNumbers(t *testing.T) {
	h, st := newTestHome(t)
	seedTestFinding(t, st, "a", 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	seedTestFinding(t, st, "b", 80, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	seedTestFinding(t, st, "c", 70, ocsf.SeverityHigh, ocsf.FindingStatusNew)
	h.loadAndRender(t)

	lines := renderPrimitive(t, h.root, 140, 40)
	joined := strings.Join(lines, "\n")

	if !strings.Contains(joined, "03") {
		t.Errorf("open findings card does not show the total\n%s", joined)
	}
	if !strings.Contains(joined, "2 critical · 1 high") {
		t.Errorf("open findings card does not show the breakdown\n%s", joined)
	}
}

// The priority queue is named for its ordering, so the ordering has to survive
// all the way to the screen — not just to the SQL.
func TestHomeQueueRendersInPriorityOrder(t *testing.T) {
	h, st := newTestHome(t)
	seedTestFinding(t, st, "low", 20, ocsf.SeverityLow, ocsf.FindingStatusNew)
	seedTestFinding(t, st, "top", 95, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	seedTestFinding(t, st, "mid", 60, ocsf.SeverityMedium, ocsf.FindingStatusNew)
	h.loadAndRender(t)

	lines := renderPrimitive(t, h.root, 140, 40)

	// First occurrence only: the selected finding also appears in the inspector
	// below the queue, and this test is about the queue's ordering.
	var order []string
	seen := map[string]bool{}
	for _, l := range lines {
		for _, uid := range []string{"finding top", "finding mid", "finding low"} {
			if strings.Contains(l, uid) && !seen[uid] {
				seen[uid] = true
				order = append(order, uid)
			}
		}
	}
	want := []string{"finding top", "finding mid", "finding low"}
	if len(order) != 3 {
		t.Fatalf("rendered %d findings, want 3\n%s", len(order), strings.Join(lines, "\n"))
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("screen order = %v, want %v", order, want)
		}
	}

	// The panel says how it is ordered, so the ranking is never a mystery.
	if _, ok := findLine(lines, "ranked by risk"); !ok {
		t.Error("the queue does not state its ordering")
	}
}

// One failing query degrades one panel. It must never blank the screen, and the
// panels that did answer must still show their answers.
func TestHomeOneFailingPanelDoesNotBlankTheScreen(t *testing.T) {
	h, st := newTestHome(t)
	seedTestFinding(t, st, "a", 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	h.loadAndRender(t)

	// Fail one panel and repaint.
	h.set(func(d *homeData) { d.queueErr = errPermission; d.queue = nil })
	h.renderAll()

	lines := renderPrimitive(t, h.root, 140, 40)
	joined := strings.Join(lines, "\n")

	if !strings.Contains(joined, "permission denied") {
		t.Errorf("the failing panel does not show its error\n%s", joined)
	}
	if _, ok := findLine(lines, "r Retry"); !ok {
		t.Errorf("the failing panel offers no retry\n%s", joined)
	}
	// The cards answered, so they still show their numbers.
	if !strings.Contains(joined, "01") {
		t.Errorf("a failing queue blanked the metric cards\n%s", joined)
	}
	if !strings.Contains(joined, "EVIDENCE PULSE") {
		t.Errorf("a failing queue removed the other panels\n%s", joined)
	}
}

// The evidence pulse repeats the counts the evidence card shows. They come from
// one query, and whichever panel painted last used to decide what each said.
func TestHomePulseAgreesWithTheEvidenceCard(t *testing.T) {
	h, st := newTestHome(t)

	ev := &ocsf.Event{
		Time: time.Now(), ClassUID: 4001, ActivityID: 1, TypeUID: 400101,
		SeverityID: ocsf.SeverityMedium, Message: "seed",
		SrcEndpoint: &ocsf.Endpoint{IP: "203.0.113.9"},
		Device:      &ocsf.Device{Hostname: "WS-1"},
	}
	ev.Metadata.UID = "seed-1"
	if _, err := st.SaveEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	h.loadAndRender(t)
	d, _ := h.snapshot()
	if d.observables == 0 {
		t.Fatal("no observables were derived; the fixture proves nothing")
	}

	lines := renderPrimitive(t, h.root, 140, 40)
	card, ok := findLine(lines, "indicators")
	if !ok {
		t.Fatal("no indicator count on screen")
	}
	pulse, ok := findLine(lines, "events today")
	if !ok {
		t.Fatal("no pulse on screen")
	}

	count := strings.TrimSpace(strings.Split(card, "indicators")[0])
	count = count[strings.LastIndexAny(count, " │")+1:]
	if !strings.Contains(pulse, count) {
		t.Errorf("card says %q indicators, pulse line is %q", count, pulse)
	}
}

// The clock ticks every second; the data must not.
func TestHomeClockTickDoesNotRequery(t *testing.T) {
	h, st := newTestHome(t)
	seedTestFinding(t, st, "a", 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	h.loadAndRender(t)

	before, _ := h.snapshot()

	// Close the store underneath. A header repaint that queried anything would
	// now fail and change the snapshot.
	st.Close()
	h.renderHeader()

	after, _ := h.snapshot()
	if after.findings.Total != before.findings.Total || after.queueErr != before.queueErr {
		t.Error("repainting the header changed the data, so the clock tick is querying")
	}
}

// Refresh returns every panel to its loading state, so the screen says it is
// working rather than presenting stale numbers as current.
func TestHomeRefreshShowsLoadingAgain(t *testing.T) {
	h, st := newTestHome(t)
	seedTestFinding(t, st, "a", 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	h.loadAndRender(t)

	if _, loading := h.snapshot(); loading[panelQueue] {
		t.Fatal("still loading after a completed load")
	}

	// Mark loading the way refresh does, without the reload it also starts.
	h.mu.Lock()
	for i := range h.loading {
		h.loading[i] = true
	}
	h.mu.Unlock()
	h.renderAll()

	lines := renderPrimitive(t, h.root, 140, 40)
	if _, ok := findLine(lines, "…"); !ok {
		t.Errorf("no loading indicator after refresh\n%s", strings.Join(lines, "\n"))
	}
}

// What disappears at each width is specified, and each tier keeps the panels an
// analyst acts on.
func TestHomeResponsiveTiers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		width, height int
		wantRecent    bool
		wantPulse     bool
	}{
		{"wide", 140, 40, true, true},
		{"standard", 100, 30, true, true},
		{"compact", 79, 24, false, false},
		{"short", 100, 20, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, st := newTestHome(t)
			for _, uid := range []string{"a", "b", "c", "d", "e"} {
				seedTestFinding(t, st, uid, 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
			}
			h.loadAndRender(t)
			h.rebuild(tc.width, tc.height)

			lines := renderPrimitive(t, h.root, tc.width, tc.height)
			joined := strings.Join(lines, "\n")

			// The queue survives every width — without it the screen has
			// nothing to act on. The keys are no longer Home's to draw: they
			// live on the one status bar the whole application shares, which
			// TestStatusBarOnHomeShowsHomesKeys covers.
			if !strings.Contains(joined, "PRIORITY QUEUE") {
				t.Errorf("%s dropped the priority queue\n%s", tc.name, joined)
			}
			// All five findings stay readable.
			for _, uid := range []string{"finding a", "finding e"} {
				if !strings.Contains(joined, uid) {
					t.Errorf("%s dropped %q from the queue\n%s", tc.name, uid, joined)
				}
			}

			if got := strings.Contains(joined, "RECENT CASES"); got != tc.wantRecent {
				t.Errorf("%s recent cases shown = %v, want %v", tc.name, got, tc.wantRecent)
			}
			if got := strings.Contains(joined, "EVIDENCE PULSE"); got != tc.wantPulse {
				t.Errorf("%s evidence pulse shown = %v, want %v", tc.name, got, tc.wantPulse)
			}

			// Nothing overflows its terminal.
			for i, l := range lines {
				if len([]rune(l)) > tc.width {
					t.Errorf("%s row %d is %d columns wide", tc.name, i, len([]rune(l)))
				}
			}
		})
	}
}

// A panel whose bottom border is off screen is a panel that has lost a row of
// content. The pulse is the one that gets squeezed, and the row it loses is the
// one carrying the last event time.
func TestHomePulseIsNeverClipped(t *testing.T) {
	for _, size := range [][2]int{{140, 40}, {120, 32}, {100, 30}, {100, 29}, {90, 26}} {
		h, st := newTestHome(t)
		if _, err := st.SaveEvent(context.Background(), &ocsf.Event{
			Time: time.Now(), ClassUID: 4001, ActivityID: 1, TypeUID: 400101,
			SeverityID: ocsf.SeverityLow, Message: "seed",
		}); err != nil {
			t.Fatal(err)
		}
		h.loadAndRender(t)
		h.rebuild(size[0], size[1])

		lines := renderPrimitive(t, h.root, size[0], size[1])
		joined := strings.Join(lines, "\n")

		if !strings.Contains(joined, "EVIDENCE PULSE") {
			continue // legitimately dropped at this size
		}
		if !strings.Contains(joined, "last event") {
			t.Errorf("%dx%d: the pulse is clipped and lost its second row\n%s",
				size[0], size[1], joined)
		}
	}
}

func TestHumanCount(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want string
	}{
		{0, "0"}, {7, "7"}, {999, "999"}, {1000, "1,000"},
		{1284, "1,284"}, {12840, "12,840"}, {1234567, "1,234,567"},
	} {
		if got := humanCount(tc.in); got != tc.want {
			t.Errorf("humanCount(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
