package ui

import (
	"fmt"
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
	panelRecent
	panelPulse
	homePanelCount
)

// Cadence. The clock ticks once a second; the data refreshes every ten. They
// are deliberately separate: a header clock that re-queries the database every
// second is a dashboard that is permanently loading.
const (
	homeClockInterval   = time.Second
	homeRefreshInterval = 10 * time.Second
	homeQueueSize       = 5
	homeRecentCases     = 4
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

	queue    []store.Finding
	queueErr error

	recent    []store.Case
	recentErr error

	lastEvent    time.Time
	hasLastEvent bool
	lastEventErr error

	watcher    WatcherStatus
	enrichment EnrichmentStatus
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
	recent    *tview.TextView
	pulse     *tview.TextView
	inspector *tview.TextView
	footer    *tview.TextView

	// body holds the two responsive arrangements of queue and recent cases.
	body *tview.Flex

	mu      sync.Mutex
	data    homeData
	loading [homePanelCount]bool

	mode  LayoutMode
	short bool
	built bool

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
	h.footer = homeText(t, tview.AlignLeft)

	for i := range h.cardBox {
		card := homeText(t, tview.AlignLeft)
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

	h.recent = homeText(t, tview.AlignLeft)
	stylePanel(h.recent.Box, "RECENT CASES", PanelRolePrimary, t)
	h.recent.SetBackgroundColor(t.Surface)

	h.pulse = homeText(t, tview.AlignLeft)
	stylePanel(h.pulse.Box, "EVIDENCE PULSE", PanelRolePrimary, t)
	h.pulse.SetBackgroundColor(t.Surface)

	h.inspector = homeText(t, tview.AlignLeft)
	stylePanel(h.inspector.Box, "SELECTED FINDING", PanelRoleInspector, t)
	h.inspector.SetBackgroundColor(t.Surface)

	h.body = tview.NewFlex()
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
	h.queue.SetSelectionChangedFunc(func(row, _ int) { h.renderInspector() })

	h.rebuild(100, 30)
	h.renderAll()
	return h
}

// openSelected opens the finding under the cursor in Triage.
func (h *homeView) openSelected() {
	f := h.selectedFinding()
	if f == nil {
		return
	}
	h.ui.jumpToFindings()
}

var homeCardTitles = [3]string{"OPEN FINDINGS", "ACTIVE CASES", "EVIDENCE TODAY"}

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
		n, err := st.CountEventsToday(ctx, time.Now())
		o, oerr := st.CountObservables(ctx)
		h.set(func(d *homeData) {
			d.eventsToday, d.eventsTodayErr = n, err
			d.observables, d.observablesErr = o, oerr
		})
	})

	run(panelQueue, func() {
		q, err := st.GetPriorityQueue(ctx, homeQueueSize)
		h.set(func(d *homeData) { d.queue, d.queueErr = q, err })
	})

	run(panelRecent, func() {
		c, err := st.GetRecentCases(ctx, homeRecentCases)
		h.set(func(d *homeData) { d.recent, d.recentErr = c, err })
	})

	run(panelPulse, func() {
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
	h.renderFooter()
}

func (h *homeView) renderPanel(p homePanel) {
	switch p {
	case panelFindings, panelCases:
		h.renderCards()
	case panelEvidence:
		// The pulse repeats these counts, so it repaints with them. Otherwise
		// whichever of the two panels resolved last decided what each showed,
		// and the card could report 26 indicators beside a pulse reporting 0.
		h.renderCards()
		h.renderPulse()
	case panelQueue:
		h.renderQueue()
		h.renderInspector()
	case panelRecent:
		h.renderRecent()
	case panelPulse:
		h.renderPulse()
		// Freshness lives in the header and comes from the same query.
		h.renderHeader()
	}
}

// renderHeader paints the two header rows. Called on every clock tick, so it
// must not query anything.
func (h *homeView) renderHeader() {
	d, _ := h.snapshot()
	t := h.ui.theme

	connected := fmt.Sprintf("[%s]●[-:-:-] [%s]connected[-:-:-]", t.TagSuccess, t.TagMuted)
	if h.ui.store == nil {
		connected = fmt.Sprintf("[%s]●[-:-:-] [%s]disconnected[-:-:-]", t.TagError, t.TagMuted)
	}

	freshness := fmt.Sprintf("[%s]no events yet[-:-:-]", t.TagMuted)
	if d.hasLastEvent {
		freshness = fmt.Sprintf("[%s]last event %s ago[-:-:-]",
			t.TagMuted, renderRelativeTime(d.lastEvent))
	}

	h.header.SetText(fmt.Sprintf("[%s:-:b]Console-IR[-:-:-]   [%s]Analyst Home[-:-:-]   %s   %s   [%s]%s[-:-:-]",
		t.TagAccent, t.TagTextPrimary, connected, freshness,
		t.TagMuted, time.Now().Format("15:04:05")))
}

func (h *homeView) renderFooter() {
	h.footer.SetText(actionBar(h.ui.theme,
		keyHint{"Enter", "Open"},
		keyHint{"/", "Filter"},
		keyHint{":", "Command palette"},
		keyHint{"?", "Help"},
	))
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
		h.cardBox[0].SetText(h.homeCard(
			metric("", fmt.Sprintf("%02d", d.findings.Total),
				fmt.Sprintf("%d critical · %d high", d.findings.Critical, d.findings.High), tone, t),
			fmt.Sprintf("[%s]%d medium · %d low[-:-:-]", t.TagMuted, d.findings.Medium, d.findings.Low)))
	}

	switch {
	case loading[panelCases]:
		h.cardBox[1].SetText(homeCardLoading(t))
	case d.casesErr != nil:
		h.cardBox[1].SetText(cardError(d.casesErr, t))
	default:
		second := fmt.Sprintf("[%s]press 3[-:-:-]", t.TagMuted)
		if !d.cases.OldestOpened.IsZero() {
			second = fmt.Sprintf("[%s]oldest %s[-:-:-]", t.TagMuted,
				renderRelativeTime(d.cases.OldestOpened))
		}
		h.cardBox[1].SetText(h.homeCard(
			metric("", fmt.Sprintf("%02d", d.cases.Total),
				fmt.Sprintf("%d investigating", d.cases.Investigating), "accent", t),
			second))
	}

	switch {
	case loading[panelEvidence]:
		h.cardBox[2].SetText(homeCardLoading(t))
	case d.eventsTodayErr != nil:
		h.cardBox[2].SetText(cardError(d.eventsTodayErr, t))
	default:
		h.cardBox[2].SetText(h.homeCard(
			metric("", humanCount(d.eventsToday)+" events", "", "accent", t),
			fmt.Sprintf("[%s]%s indicators[-:-:-]", t.TagMuted, humanCount(d.observables))))
	}
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

// renderQueue paints the priority queue: severity, risk, title, age. Nothing
// else — every extra column is a column an analyst has to read past.
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
		h.queue.SetCell(0, 0, tview.NewTableCell(fmt.Sprintf("\n  [%s]No findings yet.[-:-:-]",
			t.TagTextPrimary)).SetSelectable(false))
		h.queue.SetCell(1, 0, tview.NewTableCell(fmt.Sprintf("  [%s]Press 3 to import events, or : then demo.[-:-:-]",
			t.TagMuted)).SetSelectable(false))
		return
	}

	for i, f := range d.queue {
		h.queue.SetCell(i, 0, tview.NewTableCell(" "+formatSeverityBadge(severityLabel(f.SeverityID), t)).
			SetSelectable(true))
		h.queue.SetCell(i, 1, tview.NewTableCell(fmt.Sprintf("[%s]%3d[-:-:-]",
			riskTag(f.RiskScore, t), f.RiskScore)))
		h.queue.SetCell(i, 2, tview.NewTableCell(tview.Escape(f.Title)).
			SetTextColor(t.TextPrimary).SetExpansion(1))
		h.queue.SetCell(i, 3, tview.NewTableCell(fmt.Sprintf("[%s]%s[-:-:-]",
			t.TagMuted, renderRelativeTime(f.LastSeen))))
	}
}

func (h *homeView) renderRecent() {
	d, loading := h.snapshot()
	t := h.ui.theme

	switch {
	case loading[panelRecent]:
		h.recent.SetText(" " + loadingState("", t))
	case d.recentErr != nil:
		h.recent.SetText(fmt.Sprintf("\n  [%s]%s[-:-:-]\n  %s",
			t.TagError, tview.Escape(d.recentErr.Error()), renderKey("r", "Retry", t)))
	case len(d.recent) == 0:
		h.recent.SetText(fmt.Sprintf("\n  [%s]No active investigations.[-:-:-]", t.TagMuted))
	default:
		var b strings.Builder
		for _, c := range d.recent {
			b.WriteString(fmt.Sprintf("\n [%s]▸[-:-:-] [%s]%s[-:-:-]  [%s]%s[-:-:-]",
				t.TagAccent, t.TagTextPrimary, tview.Escape(truncate(c.Title, 26)),
				t.TagMuted, renderRelativeTime(c.UpdatedAt)))
			b.WriteString(fmt.Sprintf("\n   [%s]%s · %s[-:-:-]",
				t.TagMuted, strings.ToLower(c.Status), plural(c.FindingCount, "finding")))
		}
		h.recent.SetText(b.String())
	}
}

// renderPulse paints the read-only evidence strip.
func (h *homeView) renderPulse() {
	d, loading := h.snapshot()
	t := h.ui.theme

	if loading[panelPulse] {
		h.pulse.SetText(" " + loadingState("", t))
		return
	}

	enrich := fmt.Sprintf("[%s]idle[-:-:-]", t.TagMuted)
	if !d.enrichment.Idle() {
		parts := []string{}
		if d.enrichment.Pending > 0 {
			parts = append(parts, fmt.Sprintf("%d pending", d.enrichment.Pending))
		}
		if d.enrichment.Failed > 0 {
			parts = append(parts, fmt.Sprintf("[%s]%d failed[-:-:-]", t.TagError, d.enrichment.Failed))
		}
		if d.enrichment.Dropped > 0 {
			parts = append(parts, fmt.Sprintf("[%s]%d dropped[-:-:-]", t.TagWarning, d.enrichment.Dropped))
		}
		enrich = strings.Join(parts, " ")
	}

	watcher := fmt.Sprintf("[%s]not watching[-:-:-]", t.TagMuted)
	if d.watcher.Dir != "" {
		glyph, colour := "●", t.TagSuccess
		if d.watcher.Errors > 0 {
			glyph, colour = "▲", t.TagWarning
		}
		watcher = fmt.Sprintf("[%s]%s[-:-:-] [%s]%s[-:-:-]",
			colour, glyph, t.TagMuted, tview.Escape(shortenPath(d.watcher.Dir)))
	}

	// A bare clock time on a 929-day-old event reads as "just now". Show the
	// date as soon as the event is not from today.
	last := "—"
	if d.hasLastEvent {
		if sameDay(d.lastEvent, time.Now()) {
			last = d.lastEvent.Format("15:04:05")
		} else {
			last = d.lastEvent.Format("2006-01-02 15:04")
		}
	}

	h.pulse.SetText(fmt.Sprintf(
		" [%s]events today[-:-:-] %s    [%s]indicators[-:-:-] %s    [%s]enrichment[-:-:-] %s    [%s]watcher[-:-:-] %s\n [%s]last event[-:-:-] [%s]%s[-:-:-]",
		t.TagMuted, humanCount(d.eventsToday),
		t.TagMuted, humanCount(d.observables),
		t.TagMuted, enrich,
		t.TagMuted, watcher,
		t.TagMuted, t.TagTextPrimary, last))
}

// renderInspector paints the selected finding.
//
// The order is Triage's order (§7), so a finding reads the same wherever it is
// seen, and the human explanation comes before the raw record — never the other
// way round.
func (h *homeView) renderInspector() {
	_, loading := h.snapshot()
	t := h.ui.theme

	if loading[panelQueue] {
		h.inspector.SetText(" " + loadingState("", t))
		return
	}
	f := h.selectedFinding()
	if f == nil {
		h.inspector.SetText(fmt.Sprintf("\n [%s]Select a finding to see why it matters.[-:-:-]", t.TagMuted))
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, " [%s:-:b]%s[-:-:-]\n", t.TagTextPrimary, tview.Escape(f.Title))
	fmt.Fprintf(&b, " [%s]risk[-:-:-] %s   %s   [%s]%s[-:-:-]\n",
		t.TagMuted, fmt.Sprintf("[%s]%d[-:-:-]", riskTag(f.RiskScore, t), f.RiskScore),
		formatSeverityBadge(severityLabel(f.SeverityID), t),
		t.TagTextPrimary, tview.Escape(orDash(f.Status)))

	fmt.Fprintf(&b, " [%s]analytic[-:-:-] %s      [%s]first seen[-:-:-] %s   [%s]last seen[-:-:-] %s\n",
		t.TagMuted, tview.Escape(orDash(f.AnalyticName)),
		t.TagMuted, stamp(f.FirstSeen), t.TagMuted, stamp(f.LastSeen))

	why := strings.TrimSpace(f.Message)
	if why == "" {
		why = "No description was supplied by the producer."
	}
	fmt.Fprintf(&b, "\n [%s]WHY IT MATTERS[-:-:-]  [%s]%s[-:-:-]\n",
		t.TagMuted, t.TagTextPrimary, tview.Escape(truncate(why, 110)))

	fmt.Fprintf(&b, " [%s]EVIDENCE[-:-:-] %d   [%s]CASE[-:-:-] %s        [%s]e[-:-:-] escalate   [%s]a[-:-:-] add to case   [%s]j[-:-:-] raw OCSF",
		t.TagMuted, evidenceCount(f.EvidencesJSON),
		t.TagMuted, tview.Escape(orNone(f.CaseID)),
		t.TagAccent, t.TagAccent, t.TagAccent)

	h.inspector.SetText(b.String())
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
// priority queue and the footer always survive — without them the screen has
// nothing to act on.
func (h *homeView) rebuild(width, height int) {
	h.mode, h.short = GetLayoutMode(width, height)

	showPulse := h.mode != LayoutCompact && !h.short
	showRecent := h.mode != LayoutCompact
	// Compact and short screens lose the inspector: §5 gives the whole screen
	// to the queue there, and an inspector that squeezes the queue to two rows
	// costs more than it explains. It is one keystroke away in Triage.
	showInspector := !h.short && h.mode != LayoutCompact
	showCards := true
	if h.short && height < homeShortCardsBelow {
		showCards = false
	}

	h.cards.Clear()
	h.cards.SetDirection(tview.FlexColumn)
	if h.mode == LayoutCompact {
		h.cards.SetDirection(tview.FlexRow)
	}
	for _, c := range h.cardBox {
		h.cards.AddItem(c, 0, 1, false)
	}

	h.body.Clear()
	bodyRows := homeQueueRows
	switch {
	case showRecent && h.mode == LayoutWide:
		h.body.SetDirection(tview.FlexColumn)
		h.body.AddItem(h.queue, 0, 2, true)
		h.body.AddItem(h.recent, 0, 1, false)
		bodyRows = max(homeQueueRows, homeRecentRows)
	case showRecent:
		// Stacked. The queue keeps its full height and recent cases absorbs the
		// squeeze, because the queue is the panel with something to act on.
		h.body.SetDirection(tview.FlexRow)
		h.body.AddItem(h.queue, homeQueueRows, 0, true)
		h.body.AddItem(h.recent, 0, 1, false)
		bodyRows = homeQueueRows + homeRecentRows
	default:
		h.body.SetDirection(tview.FlexRow)
		h.body.AddItem(h.queue, 0, 1, true)
	}

	// Does everything fit at its natural height? If so the body is fixed and the
	// slack goes below it, rather than inflating a queue that can never hold
	// more than five rows. If not, the body flexes and there is no spacer at
	// all — a proportional spacer beside a proportional body would take half the
	// remaining space and halve the queue.
	fixed := homeHeaderRows + homeFooterRows
	if showCards {
		fixed += h.cardRows()
	}
	if showPulse {
		fixed += homePulseRows
	}
	if showInspector {
		fixed += homeInspectorRows
	}
	// Strictly less than: the body is only pinned to its natural height when
	// there is room to spare. Fitting exactly leaves nothing for rounding, and
	// what gets squeezed is whatever comes after — which is the pulse, losing
	// its bottom border and the row carrying "last event".
	roomy := fixed+bodyRows < height

	h.root.Clear()
	h.root.AddItem(h.header, homeHeaderRows, 0, false)
	if showCards {
		h.root.AddItem(h.cards, h.cardRows(), 0, false)
	}
	// Slack goes to the list, not to the inspector. A list with room to spare
	// is what every list looks like; an inspector with eighteen blank rows
	// under four lines of text looks broken.
	//
	// It must go somewhere, though: a nil item in a tview Flex paints nothing,
	// so leftover space showed whatever had been on screen before it.
	if showInspector || !roomy {
		h.root.AddItem(h.body, 0, 1, true)
	} else {
		h.root.AddItem(h.body, bodyRows, 0, true)
		h.root.AddItem(homeFiller(h.ui.theme), 0, 1, false)
	}
	if showInspector {
		h.root.AddItem(h.inspector, homeInspectorRows, 0, false)
	}
	if showPulse {
		h.root.AddItem(h.pulse, homePulseRows, 0, false)
	}
	h.root.AddItem(h.footer, homeFooterRows, 0, false)

	h.renderCards()
	h.built = true
}

// Row budget.
const (
	homeHeaderRows = 2
	homeFooterRows = 1
	homePulseRows  = 4
	homeCardRows   = 4

	// The inspector's minimum: title, the risk line, the analytic line, a blank,
	// why it matters, the action line, and a border.
	homeInspectorRows = 8

	// Compact stacks the three cards, so three two-line cards would be half the
	// screen. One line each, and the second line's content moves into the first.
	homeCardRowsCompact = 3

	// The queue holds homeQueueSize rows plus its border. "ranked by risk" is
	// on the panel title, not a table row: as a row the cursor could land on it.
	homeQueueRows  = homeQueueSize + 2
	homeRecentRows = homeRecentCases*2 + 3

	// Below this height the metric cards go, after the pulse. Their numbers are
	// repeated in the pulse and the queue speaks for itself.
	homeShortCardsBelow = 20
)

// cardRows is the height of the metric row, which stacks when compact.
// homeFiller is a painted blank. tview draws nothing where a Flex holds a nil
// item, so slack has to be an actual widget or the previous frame shows
// through it.
func homeFiller(theme Theme) *tview.Box {
	b := tview.NewBox()
	b.SetBackgroundColor(theme.Bg)
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (h *homeView) cardRows() int {
	if h.mode == LayoutCompact {
		return homeCardRowsCompact * len(h.cardBox)
	}
	return homeCardRows
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

// handleKey handles the keys Home owns. Global navigation is handled upstream.
func (h *homeView) handleKey(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() != tcell.KeyRune {
		return ev
	}
	switch ev.Rune() {
	case 'r':
		h.refresh()
		return nil
	}
	return ev
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

// shortenPath keeps the tail of a path, which is the part that identifies it.
func shortenPath(p string) string {
	const max = 24
	if len([]rune(p)) <= max {
		return p
	}
	r := []rune(p)
	return "…" + string(r[len(r)-max+1:])
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

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
