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
	// As showAnalystHome does. Without it the application does not know the
	// dashboard exists, and anything that reaches for the showing screen — the
	// key router, applyTheme, currentFinding — silently skips it.
	ui.home = h
	ui.destination = destHome
	// Close whichever view is live at cleanup, not this one.
	//
	// showAnalystHome replaces ui.home with a fresh view and starts its clock
	// and refresh tickers; closing the original leaves the replacement querying
	// a store whose temporary directory is being deleted out from under it.
	t.Cleanup(func() {
		if ui.home != nil {
			ui.home.close()
			ui.home.wait()
		}
		h.close()
		h.wait()
	})
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
		"no events yet",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("empty Home is missing %q\n%s", want, joined)
		}
	}

	// The cards read zero rather than blank.
	if !strings.Contains(joined, "0") {
		t.Errorf("metric cards do not show a zero count\n%s", joined)
	}
}

// The empty queue has to name something that exists.
//
// It used to say "Press 3 to import events" — and 3 is Cases. There is no
// import destination at all, so the one instruction the screen gave a new
// install sent them somewhere that could not help.
func TestHomeEmptyQueuePointsSomewhereReal(t *testing.T) {
	h, _ := newTestHome(t)
	h.loadAndRender(t)

	joined := strings.Join(renderPrimitive(t, h.root, 140, 40), "\n")

	if strings.Contains(joined, "Press 3 to import") {
		t.Errorf("the empty queue still sends the analyst to Cases to import:\n%s", joined)
	}
	// Both routes that actually exist: the drop folder, named, and the command.
	if !strings.Contains(joined, "console-ir ingest") {
		t.Errorf("the empty queue does not name the ingest command:\n%s", joined)
	}
	if !strings.Contains(joined, "Drop OCSF") {
		t.Errorf("the empty queue does not name the drop folder:\n%s", joined)
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

	if !strings.Contains(joined, "3") {
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
	if !strings.Contains(joined, "1") {
		t.Errorf("a failing queue blanked the metric cards\n%s", joined)
	}
	if !strings.Contains(joined, "EVIDENCE PULSE") {
		t.Errorf("a failing queue removed the other panels\n%s", joined)
	}
}

// The evidence numbers are stated once.
//
// They used to be on a card and again in a pulse panel four rows below it —
// "0 events / 0 indicators" beside "events today 0   indicators 0" — fed by one
// query, so whichever panel painted last decided what each said. The pulse is
// now the card.
func TestHomeStatesTheEvidenceCountsOnce(t *testing.T) {
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

	var indicatorRows int
	for _, l := range lines {
		if strings.Contains(l, "indicators") {
			indicatorRows++
		}
	}
	if indicatorRows != 1 {
		t.Errorf("the indicator count is on screen %d times, want once:\n%s",
			indicatorRows, strings.Join(lines, "\n"))
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
		wantInspector bool
	}{
		{"wide", 140, 40, true},
		{"standard", 100, 30, true},
		{"compact", 79, 24, false},
		{"short", 100, 20, false},
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

			if got := strings.Contains(joined, "SELECTED FINDING"); got != tc.wantInspector {
				t.Errorf("%s inspector shown = %v, want %v", tc.name, got, tc.wantInspector)
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
// content. The pulse card is two rows and the second one carries the pipeline
// state, which is the half worth having.
func TestHomePulseCardIsNeverClipped(t *testing.T) {
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
		if !strings.Contains(joined, "last") && !strings.Contains(joined, "watching") {
			t.Errorf("%dx%d: the pulse card is clipped and lost its second row\n%s",
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

// A dashboard checked ten times a shift has to say which findings are new since
// the last look — otherwise every glance re-reads the same queue.
func TestHomeMarksFindingsSinceTheLastVisit(t *testing.T) {
	h, st := newTestHome(t)

	// The previous visit was an hour ago; this finding arrived just now.
	h.ui.markSince = time.Now().Add(-time.Hour)
	seedTestFinding(t, st, "fresh", 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	h.loadAndRender(t)

	joined := strings.Join(renderPrimitive(t, h.root, 140, 40), "\n")
	if !strings.Contains(joined, "•") {
		t.Errorf("a finding newer than the last visit is not marked:\n%s", joined)
	}
}

// Against the previous visit, not against now: comparing with now would unmark
// everything ten seconds after opening, when the first refresh landed.
func TestHomeDoesNotMarkOlderFindings(t *testing.T) {
	h, st := newTestHome(t)

	seedTestFinding(t, st, "old", 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	h.ui.markSince = time.Now().Add(time.Hour) // everything predates this visit
	h.loadAndRender(t)

	joined := strings.Join(renderPrimitive(t, h.root, 140, 40), "\n")
	if strings.Contains(joined, "•") {
		t.Errorf("a finding older than the last visit is marked as new:\n%s", joined)
	}
}

// A first run has no previous visit. Marking the whole queue marks nothing.
func TestHomeMarksNothingOnAFirstRun(t *testing.T) {
	h, st := newTestHome(t)
	seedTestFinding(t, st, "a", 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	h.ui.markSince = time.Time{}
	h.loadAndRender(t)

	joined := strings.Join(renderPrimitive(t, h.root, 140, 40), "\n")
	if strings.Contains(joined, "•") {
		t.Errorf("a first run marked findings as new:\n%s", joined)
	}
}

// Opening Home banks the clock: what was new this visit is not new the next.
func TestOpeningHomeAdvancesTheVisitClock(t *testing.T) {
	h, _ := newTestHome(t)
	before := time.Now()

	h.ui.showAnalystHome()

	if h.ui.lastVisit.Before(before) {
		t.Errorf("lastVisit = %v, want it moved to now", h.ui.lastVisit)
	}
	// And the persisted copy survives a reload, or the mark resets every launch.
	if got := loadUISettings().LastVisit; got.IsZero() {
		t.Error("the visit clock was not persisted")
	}
}

// Changing the theme must recolour the dashboard, not just the chrome round it.
//
// Home builds its own widgets from the theme it was constructed with, so the
// application's applyTheme never reached them: pressing the theme key on the
// dashboard recoloured the navigation rail and the status bar around a
// dashboard still drawn in the old palette.
func TestHomeFollowsAThemeChange(t *testing.T) {
	h, st := newTestHome(t)
	// Otherwise every theme resolves to themeBasic and the test compares a
	// palette with itself.
	h.ui.hasTrueColor = true
	h.ui.setTheme("gruvbox")
	seedTestFinding(t, st, "a", 90, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	h.loadAndRender(t)

	before := h.queue.GetBackgroundColor()

	h.ui.setTheme("light")

	if h.queue.GetBackgroundColor() == before {
		t.Errorf("the queue kept its old background through a theme change: %v", before)
	}
	if got := h.inspector.GetBackgroundColor(); got != h.ui.theme.Surface {
		t.Errorf("the inspector background = %v, want the new theme's %v", got, h.ui.theme.Surface)
	}
}

// And it must not cost the analyst their place. Recolouring is not a reason to
// lose the cursor, the selected finding, or the record of what was new.
func TestAThemeChangeKeepsTheSelection(t *testing.T) {
	h, st := newTestHome(t)
	for i, uid := range []string{"a", "b", "c"} {
		seedTestFinding(t, st, uid, 90-i*10, ocsf.SeverityCritical, ocsf.FindingStatusNew)
	}
	h.loadAndRender(t)
	h.queue.Select(2, 0)
	want := h.selectedFinding()
	h.ui.markSince = time.Now().Add(-time.Hour)
	h.ui.hasTrueColor = true

	h.ui.setTheme("light")

	if row, _ := h.queue.GetSelection(); row != 2 {
		t.Errorf("the cursor moved to row %d during a theme change", row)
	}
	if got := h.selectedFinding(); got == nil || want == nil || got.ID != want.ID {
		t.Error("the selected finding was lost to a theme change")
	}
	if h.ui.markSince.IsZero() {
		t.Error("a theme change cleared the record of what was new")
	}
}

// The key has to be on screen. It was bound, it worked, and the only place it
// was written down was a description inside the command palette.
func TestStatusBarAdvertisesTheThemeKey(t *testing.T) {
	h, _ := newTestHome(t)
	h.ui.showAnalystHome()

	if got := stripTags(h.ui.composeStatus("Analyst Home")); !strings.Contains(got, "t theme") {
		t.Errorf("the theme key is not advertised:\n%s", got)
	}
}
