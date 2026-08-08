package ui

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Analyst Home answers one question: what requires my attention?
//
// It is a dashboard, not a navigation page, and it is the screen every session
// opens on. Two consequences drive the design below.
//
// First, every number is a shortcut — selecting a metric goes to the work it
// counts, so nothing here is decoration.
//
// Second, no panel may wait for another. The nine queries are issued
// concurrently and each panel paints the moment its own query returns, so total
// time is the slowest query rather than the sum, and one slow or failing query
// degrades one panel instead of blanking the screen.

// homePanel identifies a panel for loading, empty and error state tracking.
type homePanel int

const (
	panelFindings homePanel = iota
	panelCases
	panelEvidence
	panelQueue
	homePanelCount
)

// Cadence. The clock ticks once a second; the data refreshes every ten. They
// are deliberately separate: a header clock that re-queries the database every
// second is a dashboard that is permanently loading.
const (
	homeClockInterval   = time.Second
	homeRefreshInterval = 10 * time.Second

	// homeQueueFloor is the smallest useful queue, not a cap. The panel takes
	// whatever height the screen has left and asks for that many, so a tall
	// terminal triages twenty findings instead of showing five above a hole.
	homeQueueFloor = 5

	// homeQueueCeiling bounds the query on an unusually tall terminal. A queue
	// nobody can read in one glance is a list, and there is a whole screen for
	// that behind key 1.
	homeQueueCeiling = 40
)

// homeData is one complete snapshot of the dashboard.
//
// Each field carries its own error so a panel can fail alone. A single error
// for the whole struct would mean one unreachable table blanks five panels that
// had already answered.
type homeData struct {
	findings    store.OpenFindings
	findingsErr error

	cases    store.ActiveCases
	casesErr error

	eventsToday    int
	eventsTodayErr error

	observables    int
	observablesErr error

	// volume is the last day's event count per hour, oldest first.
	volume []int

	queue    []store.Finding
	queueErr error
	// queueTotal is how many open findings there are, so the panel can say what
	// it is not showing.
	queueTotal int

	lastEvent    time.Time
	hasLastEvent bool
	lastEventErr error

	watcher    WatcherStatus
	enrichment EnrichmentStatus

	// loadedAt is when this snapshot was taken, so the header can say how old
	// what you are looking at is.
	loadedAt time.Time
}

// WatcherStatus is what the evidence pulse shows about folder ingestion. The
// UI defines it rather than importing the ingest package, so the dashboard
// depends on a shape rather than on a subsystem.
type WatcherStatus struct {
	Dir      string
	Active   bool
	Errors   int
	LastErr  string
	Ingested int
}

// EnrichmentStatus is the in-process enrichment backlog.
type EnrichmentStatus struct {
	Pending int
	Failed  int
	Dropped int
}

// Idle reports whether there is nothing worth saying.
func (e EnrichmentStatus) Idle() bool {
	return e.Pending == 0 && e.Failed == 0 && e.Dropped == 0
}

// homeView is the Analyst Home screen.
type homeView struct {
	ui *UI

	root      *tview.Flex
	header    *tview.TextView
	cards     *tview.Flex
	cardBox   [3]*tview.TextView
	queue     *tview.Table
	inspector *tview.TextView

	mu      sync.Mutex
	data    homeData
	loading [homePanelCount]bool

	mode  LayoutMode
	short bool
	built bool
	// queueRows is the height the queue was last laid out at, including its
	// border. The query asks for what fits.
	queueRows int
	// width is the width the screen was last laid out at, so panels can wrap
	// text without asking a widget for a rect that is a frame out of date.
	width int

	// inspect holds the selected finding's context and its debounce timer.
	inspect homeInspector

	stop chan struct{}
	once sync.Once
}

// showAnalystHome opens the dashboard. It is the only destination the UI starts
// on: whether a database exists at all is settled in cmd, before the store is
// opened, so a first run never reaches here.
//
// Home renders its own empty states, so an existing but empty database is not a
// special case.
func (ui *UI) showAnalystHome() {
	// What was new last time stops being new now. The mark is read from the
	// previous visit and the clock is reset here, on the way in, so a finding
	// stays marked for the whole of the visit that first saw it.
	ui.markSince = ui.lastVisit
	ui.lastVisit = time.Now()
	ui.saveUISettings()

	ui.showFindings = false
	ui.showAll = false
	ui.selectedCaseID = ""
	ui.destination = destHome
	ui.renderNavRail()

	if ui.home != nil {
		ui.home.close()
	}
	ui.home = newHomeView(ui)
	ui.setMainView(ui.home.root)
	ui.home.start()
	ui.setStatusDirect("[%s]Analyst Home[-:-:-]", ui.theme.TagAccent)
}

func newHomeView(ui *UI) *homeView {
	h := &homeView{ui: ui, stop: make(chan struct{})}
	t := ui.theme

	h.header = homeText(t, tview.AlignLeft)

	for i := range h.cardBox {
		card := homeText(t, tview.AlignLeft)
		// A card is two rows and no more. Wrapped, an over-long first row
		// reflows onto the second and pushes it out of the panel — which is how
		// the pipeline line disappeared the moment a sparkline was added to the
		// row above it. Clipping loses the tail of one line; wrapping loses a
		// whole line, silently.
		card.SetWrap(false)
		stylePanel(card.Box, homeCardTitles[i], PanelRolePrimary, t)
		card.SetBackgroundColor(t.Surface)
		h.cardBox[i] = card
	}
	h.cards = tview.NewFlex()
	h.cards.SetBackgroundColor(t.Bg)

	h.queue = tview.NewTable().SetSelectable(true, false)
	stylePanel(h.queue.Box, "PRIORITY QUEUE  ·  ranked by risk", PanelRolePrimary, t)
	h.queue.SetBackgroundColor(t.Bg)
	h.queue.SetSelectedStyle(tcell.StyleDefault.
		Background(t.SelectionBg).Foreground(t.SelectionFg))

	h.inspector = homeText(t, tview.AlignLeft)
	// Two columns composed into one string per row, so a row that overran its
	// panel used to reflow onto the next and push the rows below it out. The
	// narrative wraps deliberately; nothing else may.
	h.inspector.SetWrap(false)
	stylePanel(h.inspector.Box, "SELECTED FINDING", PanelRoleInspector, t)
	h.inspector.SetBackgroundColor(t.Surface)

	h.root = tview.NewFlex().SetDirection(tview.FlexRow)
	h.root.SetBackgroundColor(t.Bg)

	// Every panel starts in its loading state, so the first paint says "working"
	// rather than "empty". A dashboard that shows zeroes before its queries
	// return has told the analyst something false.
	for i := range h.loading {
		h.loading[i] = true
	}

	h.root.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		h.relayout(width, height)
		return x, y, width, height
	})

	// Every number on this screen is a shortcut to the work it counts.
	h.queue.SetSelectedFunc(func(row, _ int) { h.openSelected() })
	h.queue.SetSelectionChangedFunc(func(row, _ int) { h.selectionChanged() })

	h.rebuild(100, 30)
	h.renderAll()
	return h
}

// openSelected opens the finding under the cursor in Triage.
//
// The selection travels with it. Jumping to a queue of a hundred findings with
// the cursor on the first one loses the very thing that was being looked at,
// which makes Enter a change of scenery rather than an action.
func (h *homeView) openSelected() {
	f := h.selectedFinding()
	if f == nil {
		return
	}
	h.ui.pendingFindingID = f.ID
	h.ui.jumpToFindings()
}

// homeCardTitles names the three metrics across the top.
//
// The third used to be EVIDENCE TODAY and stated the same two numbers as the
// evidence pulse four rows below it — "0 events / 0 indicators" beside "events
// today 0   indicators 0". The pulse is the better of the two and it is now the
// card, which is also where it belongs: pipeline health is something you check
// on the way in, not something buried under the fold.
var homeCardTitles = [3]string{"OPEN FINDINGS", "ACTIVE CASES", "EVIDENCE PULSE"}

func homeText(theme Theme, align int) *tview.TextView {
	tv := tview.NewTextView().SetDynamicColors(true).SetTextAlign(align)
	tv.SetBackgroundColor(theme.Bg)
	return tv
}

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

// start issues the first load and begins the clock and refresh timers.
func (h *homeView) start() {
	go h.load()

	go func() {
		clock := time.NewTicker(homeClockInterval)
		refresh := time.NewTicker(homeRefreshInterval)
		defer clock.Stop()
		defer refresh.Stop()

		for {
			select {
			case <-h.stop:
				return
			case <-h.ui.ctx.Done():
				return
			case <-clock.C:
				// Repaint the header only. This tick must never touch the
				// database: at one query per second the dashboard would spend
				// its life reloading, and the panels would flicker between
				// their loading and loaded states forever.
				h.ui.queueUpdate(h.renderHeader)
			case <-refresh.C:
				go h.load()
			}
		}
	}()
}

// close stops the timers. Safe to call more than once.
func (h *homeView) close() {
	h.once.Do(func() { close(h.stop) })
}

// load issues every query concurrently and paints each panel as its own query
// returns.
//
// Deliberately not a barrier: waiting for all nine would make the dashboard as
// slow as its slowest query even when eight had already answered.
func (h *homeView) load() {
	ctx := h.ui.ctx
	st := h.ui.store
	if st == nil {
		return
	}

	h.set(func(d *homeData) { d.loadedAt = time.Now() })

	var wg sync.WaitGroup
	run := func(panel homePanel, fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
			h.finish(panel)
		}()
	}

	run(panelFindings, func() {
		f, err := st.CountOpenFindings(ctx)
		h.set(func(d *homeData) { d.findings, d.findingsErr = f, err })
	})

	run(panelCases, func() {
		c, err := st.CountActiveCases(ctx)
		h.set(func(d *homeData) { d.cases, d.casesErr = c, err })
	})

	run(panelEvidence, func() {
		now := time.Now()
		n, err := st.CountEventsToday(ctx, now)
		o, oerr := st.CountObservables(ctx)
		// The shape of the day, which the total cannot carry. A failure here
		// costs the sparkline and nothing else.
		v, _ := st.EventVolumeBuckets(ctx, now, homeVolumeHours)
		h.set(func(d *homeData) {
			d.eventsToday, d.eventsTodayErr = n, err
			d.observables, d.observablesErr = o, oerr
			d.volume = v
		})
	})

	run(panelQueue, func() {
		// One more than the panel can show, so "and N more" can be truthful
		// without a second count query.
		q, err := st.GetPriorityQueue(ctx, h.queueWant()+1)
		h.set(func(d *homeData) {
			d.queueTotal = len(q)
			if len(q) > h.queueWant() {
				q = q[:h.queueWant()]
			}
			d.queue, d.queueErr = q, err
		})
	})

	run(panelEvidence, func() {
		ts, ok, err := st.GetLastEvent(ctx)
		// Watcher and enrichment are not store queries: they come from the
		// ingest package and the plugin manager, injected by cmd.
		w := h.ui.watcherStatus()
		e := h.ui.enrichmentStatus()
		h.set(func(d *homeData) {
			d.lastEvent, d.hasLastEvent, d.lastEventErr = ts, ok, err
			d.watcher, d.enrichment = w, e
		})
	})

	wg.Wait()
}

// set mutates the snapshot under the lock.
func (h *homeView) set(fn func(*homeData)) {
	h.mu.Lock()
	fn(&h.data)
	h.mu.Unlock()
}

// finish clears a panel's loading flag and repaints just that panel.
func (h *homeView) finish(panel homePanel) {
	h.mu.Lock()
	h.loading[panel] = false
	h.mu.Unlock()

	h.ui.queueUpdate(func() { h.renderPanel(panel) })
}

// snapshot returns a copy of the current data and loading flags.
func (h *homeView) snapshot() (homeData, [homePanelCount]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.data, h.loading
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

func (h *homeView) renderAll() {
	h.renderHeader()
	for p := homePanel(0); p < homePanelCount; p++ {
		h.renderPanel(p)
	}
}

func (h *homeView) renderPanel(p homePanel) {
	switch p {
	case panelFindings, panelCases:
		h.renderCards()
	case panelEvidence:
		h.renderCards()
	case panelQueue:
		h.renderQueue()
		h.renderInspector()
		// Freshness lives in the header and comes from the same query.
		h.renderHeader()
	}
}

// renderHeader paints the two header rows. Called on every clock tick, so it
// must not query anything.
func (h *homeView) renderHeader() {
	d, _ := h.snapshot()
	t := h.ui.theme

	// "connected" on its own answers nothing — connected to what? The only
	// connection this screen has is the database, and whether it is open is the
	// difference between an empty dashboard and a broken one.
	db := fmt.Sprintf("[%s]●[-:-:-] [%s]DB connected[-:-:-]", t.TagSuccess, t.TagMuted)
	if h.ui.store == nil {
		db = fmt.Sprintf("[%s]●[-:-:-] [%s]DB unavailable[-:-:-]", t.TagError, t.TagMuted)
	}

	// How old what you are looking at is. The dashboard re-queries every ten
	// seconds and never said so, so there was no way to tell a live screen from
	// one that had quietly stopped refreshing.
	age := fmt.Sprintf("[%s]⟳ %s[-:-:-]", t.TagMuted, renderRelativeTime(d.loadedAt))
	if d.loadedAt.IsZero() {
		age = fmt.Sprintf("[%s]⟳ loading[-:-:-]", t.TagMuted)
	}

	// No product name here. It is on the status bar, once.
	h.header.SetText(fmt.Sprintf(" [%s:-:b]Analyst Home[-:-:-]    %s    %s    [%s]%s[-:-:-]",
		t.TagAccent, db, age, t.TagMuted, time.Now().Format("15:04:05")))
}

// renderCards paints the three metric cards. Each is a shortcut to the work it
// counts, so each states its own destination.
//
// Exactly two content rows per card, which is what the card's height allows. A
// third line is not clipped visibly, it simply never appears, so the budget is
// enforced here rather than discovered on a narrow terminal.
func (h *homeView) renderCards() {
	d, loading := h.snapshot()
	t := h.ui.theme

	switch {
	case loading[panelFindings]:
		h.cardBox[0].SetText(homeCardLoading(t))
	case d.findingsErr != nil:
		h.cardBox[0].SetText(cardError(d.findingsErr, t))
	default:
		tone := "success"
		if d.findings.Critical > 0 {
			tone = "critical"
		} else if d.findings.High > 0 {
			tone = "high"
		}
		// Not %02d. It pads below ten and not above, so a screen showing "05"
		// beside "12" disagreed with itself about how counts are written.
		h.cardBox[0].SetText(h.homeCard(
			metric("", strconv.Itoa(d.findings.Total),
				h.severityBar(d.findings, homeSeverityBarWidth), tone, t),
			fmt.Sprintf("[%s]%d critical · %d high · %d medium · %d low[-:-:-]",
				t.TagMuted, d.findings.Critical, d.findings.High,
				d.findings.Medium, d.findings.Low)))
	}

	switch {
	case loading[panelCases]:
		h.cardBox[1].SetText(homeCardLoading(t))
	case d.casesErr != nil:
		h.cardBox[1].SetText(cardError(d.casesErr, t))
	default:
		// The second line is a fact about the cases or, when there are none, says
		// so. It used to fall back to the key hint "press 3", which put an
		// instruction in a slot that otherwise holds data.
		second := fmt.Sprintf("[%s]none open yet[-:-:-]", t.TagMuted)
		if !d.cases.OldestOpened.IsZero() {
			second = fmt.Sprintf("[%s]oldest opened %s[-:-:-]", t.TagMuted,
				renderRelativeTime(d.cases.OldestOpened))
		}
		h.cardBox[1].SetText(h.homeCard(
			metric("", strconv.Itoa(d.cases.Total),
				fmt.Sprintf("%d investigating", d.cases.Investigating), "accent", t),
			second))
	}

	switch {
	case loading[panelEvidence]:
		h.cardBox[2].SetText(homeCardLoading(t))
	case d.eventsTodayErr != nil:
		h.cardBox[2].SetText(cardError(d.eventsTodayErr, t))
	default:
		h.cardBox[2].SetText(h.homeCard(h.pulseTop(d), h.pulseBottom(d)))
	}
}

// pulseTop is what arrived today, and the shape it arrived in.
func (h *homeView) pulseTop(d homeData) string {
	t := h.ui.theme
	spark := ""
	if w := h.sparkWidth(); w > 0 {
		spark = fmt.Sprintf(" [%s]%s[-:-:-] ", t.TagAccent, sparkline(d.volume, w))
	}
	return fmt.Sprintf("[%s:-:b]%s[-:-:-] [%s]events[-:-:-]%s  [%s]%s indicators[-:-:-]",
		t.TagTextPrimary, humanCount(d.eventsToday), t.TagMuted, spark,
		t.TagMuted, humanCount(d.observables))
}

// sparkWidth is how much of the card the chart may have.
//
// Three sizes rather than a continuous fit: a chart that changes resolution
// with every column of window width cannot be compared against the one that was
// there a moment ago. Below the smallest it is dropped — the counts beside it
// are the part that must survive.
func (h *homeView) sparkWidth() int {
	card := h.width/len(h.cardBox) - 2
	switch {
	case card >= 46:
		return homeSparkWidth
	case card >= 34:
		return homeSparkWidth / 2
	default:
		return 0
	}
}

// pulseBottom is the state of the pipeline that produced it.
//
// Enrichment is silent while idle rather than spending a third of a two-row
// card to report that nothing is happening.
func (h *homeView) pulseBottom(d homeData) string {
	line := fmt.Sprintf("%s  %s", h.lastEventText(d), h.watcherText(d))
	if e := h.enrichmentText(d); e != "" {
		line += "  " + e
	}
	return line
}

func (h *homeView) lastEventText(d homeData) string {
	t := h.ui.theme
	if !d.hasLastEvent {
		return fmt.Sprintf("[%s]no events yet[-:-:-]", t.TagMuted)
	}
	// A bare clock time on a 929-day-old event reads as "just now". Show the
	// date as soon as the event is not from today.
	stamp := d.lastEvent.Format("2006-01-02 15:04")
	if sameDay(d.lastEvent, time.Now()) {
		stamp = d.lastEvent.Format("15:04:05")
	}
	return fmt.Sprintf("[%s]last[-:-:-] [%s]%s[-:-:-]", t.TagMuted, t.TagTextPrimary, stamp)
}

func (h *homeView) watcherText(d homeData) string {
	t := h.ui.theme
	if d.watcher.Dir == "" {
		return fmt.Sprintf("[%s]not watching[-:-:-]", t.TagMuted)
	}
	if d.watcher.Errors > 0 {
		reason := d.watcher.LastErr
		if strings.TrimSpace(reason) == "" {
			reason = plural(d.watcher.Errors, "error")
		}
		return fmt.Sprintf("[%s]▲[-:-:-] [%s]%s[-:-:-]",
			t.TagWarning, t.TagWarning, tview.Escape(truncate(reason, 34)))
	}
	// The folder's own name, not its path. The card is a third of the screen
	// and the path filled it end to end with the part that never changes.
	//
	// The watcher's own error text replaces all of this when there is one: it
	// was collected on every refresh and rendered nowhere, so a failing watcher
	// showed a glyph and a path — the symptom, never the reason.
	return fmt.Sprintf("[%s]●[-:-:-] [%s]%s %d[-:-:-]", t.TagSuccess, t.TagMuted,
		tview.Escape(filepath.Base(d.watcher.Dir)), d.watcher.Ingested)
}

func (h *homeView) enrichmentText(d homeData) string {
	t := h.ui.theme
	if d.enrichment.Idle() {
		return ""
	}
	parts := []string{}
	if d.enrichment.Pending > 0 {
		parts = append(parts, fmt.Sprintf("[%s]%d pending[-:-:-]", t.TagMuted, d.enrichment.Pending))
	}
	if d.enrichment.Failed > 0 {
		parts = append(parts, fmt.Sprintf("[%s]%d failed[-:-:-]", t.TagError, d.enrichment.Failed))
	}
	if d.enrichment.Dropped > 0 {
		parts = append(parts, fmt.Sprintf("[%s]%d dropped[-:-:-]", t.TagWarning, d.enrichment.Dropped))
	}
	return strings.Join(parts, " ")
}

// homeCard lays out a card body with a consistent left margin: two rows
// normally, folded onto one when the cards are stacked and each has a single
// line to work with.
func (h *homeView) homeCard(first, second string) string {
	if h.mode == LayoutCompact {
		return " " + first + "   " + second
	}
	return " " + first + "\n " + second
}

func homeCardLoading(theme Theme) string {
	return " " + loadingState("", theme)
}

func cardError(err error, theme Theme) string {
	return fmt.Sprintf(" [%s]unavailable[-:-:-]\n [%s]%s[-:-:-]",
		theme.TagError, theme.TagMuted, tview.Escape(truncate(err.Error(), 26)))
}

// renderQueue paints the priority queue.
//
// Severity, risk, title, age. Nothing else — every extra column is a column an
// analyst has to read past.
//
// Colour means one thing here, and that thing is severity. Risk used to carry a
// second scale of its own and status a third, so three palettes competed for
// the same eye and the screen read busier than it was. The leading bar is in
// the severity colour, which groups the queue into tiers without spending a row
// on a separator.
func (h *homeView) renderQueue() {
	d, loading := h.snapshot()
	t := h.ui.theme
	h.queue.Clear()

	if loading[panelQueue] {
		h.queue.SetCell(0, 0, tview.NewTableCell("  "+loadingState("", t)).SetSelectable(false))
		return
	}
	if d.queueErr != nil {
		h.queue.SetCell(0, 0, tview.NewTableCell(fmt.Sprintf("  [%s]%s[-:-:-]",
			t.TagError, tview.Escape(d.queueErr.Error()))).SetSelectable(false))
		h.queue.SetCell(1, 0, tview.NewTableCell("  "+renderKey("r", "Retry", t)).SetSelectable(false))
		return
	}
	if len(d.queue) == 0 {
		h.renderEmptyQueue()
		return
	}

	for i, f := range d.queue {
		colour := h.ui.getSeverityColor(severityLabel(f.SeverityID))

		h.queue.SetCell(i, 0, tview.NewTableCell(
			fmt.Sprintf(" [%s]▌[-:-:-] %s", colour, formatSeverityBadge(severityLabel(f.SeverityID), t))).
			SetSelectable(true))

		// Plain. The number is already ordered by the sort and coloured by the
		// badge beside it; a third colour scale on top of that said nothing new.
		h.queue.SetCell(i, 1, tview.NewTableCell(fmt.Sprintf("[%s]%3d[-:-:-]",
			t.TagTextPrimary, f.RiskScore)))

		// Arrived since the last visit. A dashboard checked ten times a shift
		// is only useful if it can say which of these are new.
		mark := "  "
		if h.isNew(f) {
			mark = fmt.Sprintf("[%s]• [-:-:-]", t.TagAccent)
		}
		h.queue.SetCell(i, 2, tview.NewTableCell(mark+tview.Escape(f.Title)).
			SetTextColor(t.TextPrimary).SetExpansion(1))

		// Whether somebody has already picked this up. Without it the queue
		// offers the same finding every time you look, with no sign that it is
		// already in an open case.
		picked := ""
		if strings.TrimSpace(f.CaseID) != "" {
			picked = fmt.Sprintf("[%s]▪ in case[-:-:-]", t.TagMuted)
		}
		h.queue.SetCell(i, 3, tview.NewTableCell(picked))

		h.queue.SetCell(i, 4, tview.NewTableCell(fmt.Sprintf("[%s]%s [-:-:-]",
			t.TagMuted, renderRelativeTime(f.LastSeen))))
	}

	// What the panel is not showing. The queue is a top-N view and nothing said
	// so, so a dashboard of five looked like a backlog of five.
	if more := d.queueTotal - len(d.queue); more > 0 {
		row := len(d.queue)
		h.queue.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("[%s]… and %s · press 1 for the full queue[-:-:-]",
			t.TagMuted, plural(more, "more"))).SetSelectable(false).SetExpansion(1))
	}
}

// isNew reports whether a finding arrived since the previous visit.
//
// Against the previous visit, not against this one: comparing with now would
// unmark everything the moment the screen refreshed, ten seconds after opening.
func (h *homeView) isNew(f store.Finding) bool {
	if h.ui.markSince.IsZero() {
		// No previous visit recorded. Marking every finding on a first run
		// would mark the whole queue, which marks nothing.
		return false
	}
	return f.CreatedAt.After(h.ui.markSince)
}

// renderEmptyQueue is a first run, or a database with nothing in it yet.
//
// The instruction has to name something that exists. It used to say "Press 3 to
// import events" — 3 is Cases, and there is no import destination at all, so
// the one direction the screen gave a new install sent them nowhere useful.
//
// The two routes that do exist are the drop folder and the command line, and
// the drop folder is named rather than described: "put files where the watcher
// is looking" is not an instruction anybody can follow.
func (h *homeView) renderEmptyQueue() {
	d, _ := h.snapshot()
	t := h.ui.theme

	h.queue.SetCell(0, 0, tview.NewTableCell(fmt.Sprintf("\n  [%s]No findings yet.[-:-:-]",
		t.TagTextPrimary)).SetSelectable(false))

	drop := strings.TrimSpace(d.watcher.Dir)
	if drop == "" {
		drop = h.ui.watchedDir()
	}
	if drop != "" {
		h.queue.SetCell(1, 0, tview.NewTableCell(fmt.Sprintf(
			"  [%s]Drop OCSF JSON or JSONL into[-:-:-] [%s]%s[-:-:-]",
			t.TagMuted, t.TagAccent, tview.Escape(shortenPath(drop, 48)))).SetSelectable(false))
	}
	h.queue.SetCell(2, 0, tview.NewTableCell(fmt.Sprintf(
		"  [%s]or run[-:-:-] [%s]console-ir ingest <file>[-:-:-]",
		t.TagMuted, t.TagAccent)).SetSelectable(false))
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04")
}

// evidenceCount counts the entries in a finding's evidences array without
// unmarshalling it: this runs on every cursor movement.
func evidenceCount(evidencesJSON string) int {
	s := strings.TrimSpace(evidencesJSON)
	if s == "" || s == "null" || s == "[]" {
		return 0
	}
	return strings.Count(s, "{")
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

// relayout rebuilds only when the responsive tier changed.
func (h *homeView) relayout(width, height int) {
	mode, short := GetLayoutMode(width, height)
	if h.built && mode == h.mode && short == h.short {
		return
	}
	h.rebuild(width, height)
}

// rebuild assembles the screen for the current tier.
//
// What disappears is specified and is not a judgement call: standard moves
// recent cases below the queue, compact drops recent cases and the pulse
// entirely, and a short screen drops the pulse first and then the cards. The
// priority queue always survives — without it the screen has nothing to act on.
// The keys live on the one status bar at the foot of the application, which is
// shared by every screen; Home used to carry a second bar of its own above it.
func (h *homeView) rebuild(width, height int) {
	h.mode, h.short = GetLayoutMode(width, height)
	h.width = width

	showInspector := !h.short && h.mode != LayoutCompact
	showCards := !(h.short && height < homeShortCardsBelow)

	h.cards.Clear()
	h.cards.SetDirection(tview.FlexColumn)
	if h.mode == LayoutCompact {
		h.cards.SetDirection(tview.FlexRow)
	}
	for _, c := range h.cardBox {
		h.cards.AddItem(c, 0, 1, false)
	}

	// The queue takes whatever is left.
	//
	// It used to be pinned to five rows while the panel beside it held three
	// cases in seventeen, so a tall terminal showed five findings and eleven
	// blank lines. It is the one panel with something to act on; the slack is
	// its by right.
	fixed := homeHeaderRows
	if showCards {
		fixed += h.cardRows()
	}
	if showInspector {
		fixed += homeInspectorRows
	}
	h.queueRows = clamp(height-fixed, homeQueueFloor+2, homeQueueCeiling+2)

	h.root.Clear()
	h.root.AddItem(h.header, homeHeaderRows, 0, false)
	if showCards {
		h.root.AddItem(h.cards, h.cardRows(), 0, false)
	}
	h.root.AddItem(h.queue, 0, 1, true)
	if showInspector {
		h.root.AddItem(h.inspector, homeInspectorRows, 0, false)
	}

	h.renderCards()
	h.renderQueue()
	h.built = true
}

// queueWant is how many findings to ask the database for: what the panel can
// show, within bounds, so the query follows the window rather than a constant.
func (h *homeView) queueWant() int {
	if h.queueRows <= 0 {
		return homeQueueFloor
	}
	return clamp(h.queueRows-2, homeQueueFloor, homeQueueCeiling)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Row budget.
const (
	homeHeaderRows = 1
	homeCardRows   = 4

	// The inspector's height. It reads a finding in full — the narrative, the
	// indicators worth pivoting on, the technique, and the record's own
	// metadata — which is what the rows freed by dropping the recent-cases
	// panel were spent on.
	homeInspectorRows = 15

	// Compact stacks the three cards, so three two-line cards would be half the
	// screen. One line each, and the second line's content moves into the first.
	homeCardRowsCompact = 3

	// Below this height the metric cards go. The queue speaks for itself.
	homeShortCardsBelow = 20

	// homeVolumeHours is the sparkline's window: a day, so the shape covers a
	// shift handover as well as the hour just gone.
	homeVolumeHours = 24

	// homeSparkWidth and homeSeverityBarWidth are drawn widths. Both sit inside
	// a card that is a third of the screen, so they are fixed rather than
	// elastic — a chart that changes resolution with the window is a chart you
	// cannot compare against the one you saw a minute ago.
	homeSparkWidth       = 16
	homeSeverityBarWidth = 14
)

// cardRows is the height of the metric row, which stacks when compact.
func (h *homeView) cardRows() int {
	if h.mode == LayoutCompact {
		return homeCardRowsCompact * len(h.cardBox)
	}
	return homeCardRows
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

// handleKey handles the keys Home owns.
//
// It is called from the application-wide capture before any global binding
// applies — see UI.screenKeys. Returning nil claims the key; returning the
// event lets navigation, the palette and the rest of the globals have it.
//
// Every key here would otherwise mean something else. j and k are the global
// move-selection pair, Tab is cycleFocus, r refreshes the Cases screen, and e
// and v are guarded by showFindings, which Home clears on the way in.
func (h *homeView) handleKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyTab, tcell.KeyBacktab:
		// Claimed and dropped. Unclaimed it reaches cycleFocus, which cycles
		// the sidebar, the event list and the event detail — none of which are
		// in Home's tree, so focus lands on a primitive that is not on screen
		// and the status bar announces a panel nobody can see.
		return nil

	case tcell.KeyEnter:
		h.openSelected()
		return nil

	case tcell.KeyRune:
		switch ev.Rune() {
		case 'j':
			h.moveQueue(1)
			return nil
		case 'k':
			h.moveQueue(-1)
			return nil
		case 'r':
			h.refresh()
			return nil
		case 'e':
			h.ui.escalateFindingToCase()
			return nil
		case 'v':
			h.ui.showFindingVerdictModal()
			return nil
		}
	}
	return ev
}

// moveQueue steps the queue cursor, which j and k would otherwise never reach.
func (h *homeView) moveQueue(delta int) {
	rows := h.queue.GetRowCount()
	if rows == 0 {
		return
	}
	row, col := h.queue.GetSelection()
	row += delta
	if row < 0 {
		row = 0
	}
	if row >= rows {
		row = rows - 1
	}
	h.queue.Select(row, col)
}

// refresh reloads every panel, returning each to its loading state so the
// screen says it is working rather than showing stale numbers as current.
func (h *homeView) refresh() {
	h.mu.Lock()
	for i := range h.loading {
		h.loading[i] = true
	}
	h.mu.Unlock()
	h.renderAll()
	go h.load()
}

// selectedFinding returns the finding under the cursor, if any.
func (h *homeView) selectedFinding() *store.Finding {
	d, _ := h.snapshot()
	row, _ := h.queue.GetSelection()
	if row < 0 || row >= len(d.queue) {
		return nil
	}
	return &d.queue[row]
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// humanCount groups thousands, because 1284 and 12840 are hard to tell apart at
// a glance and this is a number people glance at.
func humanCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// homeWatcherPathWidth is how much of the drop folder the evidence pulse shows.
const homeWatcherPathWidth = 24

// riskTag picks the colour band for a risk score.
func riskTag(score int, theme Theme) string {
	switch {
	case score >= 80:
		return theme.TagSeverityCritical
	case score >= 60:
		return theme.TagSeverityHigh
	case score >= 30:
		return theme.TagSeverityMedium
	default:
		return theme.TagMuted
	}
}

// severityLabel names a severity_id for the shared badge formatter, so Home
// and Triage colour the same level identically.
func severityLabel(severityID int) string {
	switch severityID {
	case ocsf.SeverityFatal, ocsf.SeverityCritical:
		return "CRITICAL"
	case ocsf.SeverityHigh:
		return "HIGH"
	case ocsf.SeverityMedium:
		return "MEDIUM"
	case ocsf.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// onHome reports whether Analyst Home is the screen currently showing.
//
// Derived from the main panel's contents rather than from a flag, because a
// flag would have to be cleared by every other screen and one that forgot would
// send Home's refresh to a screen that had already replaced it.
func (ui *UI) onHome() bool {
	if ui.home == nil || ui.mainPanel == nil {
		return false
	}
	return ui.mainPanel.GetItemCount() > 0 && ui.mainPanel.GetItem(0) == ui.home.root
}

// sameDay reports whether two times fall on the same local calendar day.
func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}
