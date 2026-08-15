package ui

import (
	"context"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// liveUI starts the real event loop against a simulated terminal.
//
// Every other test in this package runs with ui.running false, which makes
// queueUpdate call its function inline — so the one failure mode it cannot see
// is the one that matters most: queueUpdate blocks until the event loop drains
// it, and anything already running on that loop which queues instead of
// painting directly deadlocks the whole application.
func liveUI(t *testing.T) (*UI, *store.Store, tcell.SimulationScreen) {
	t.Helper()
	ui, st := newTestUI(t)

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("simulation screen: %v", err)
	}
	screen.SetSize(150, 40)

	ui.app.SetScreen(screen)
	ui.app.SetRoot(ui.mainRoot(), true)
	ui.running.Store(true)

	go func() { _ = ui.app.Run() }()
	t.Cleanup(func() {
		// Drain first, stop second. Anything still in flight finishes through
		// queueUpdate, and queueUpdate waits on the very loop Stop ends — so
		// stopping first strands every pending load forever.
		//
		// The budget is generous on purpose. It was five seconds, which a
		// loaded Windows agent could not always meet: settle gave up, Stop
		// killed the loop, and the *next* cleanup — the one that waits for
		// home — blocked on goroutines that could no longer finish. The test
		// binary then sat until Go's ten-minute timeout and blamed whichever
		// test was running at the time.
		if !settle(ui, 30*time.Second) {
			t.Error("the screen would not settle: a load was still queueing updates " +
				"when the event loop was about to stop")
		}
		ui.running.Store(false)
		ui.app.Stop()
	})

	// Do not inject anything until the loop is actually turning.
	if err := pingLoop(ui, 5*time.Second); err != nil {
		t.Fatalf("the event loop never started: %v", err)
	}
	return ui, st, screen
}

// pingLoop round-trips one function through the event loop.
func pingLoop(ui *UI, within time.Duration) error {
	done := make(chan struct{})
	go func() { ui.app.QueueUpdate(func() { close(done) }) }()
	select {
	case <-done:
		return nil
	case <-time.After(within):
		return context.DeadlineExceeded
	}
}

// No screen may freeze the application on the way in.
//
// Pressing 2 straight after start-up hung: switchToCases repainted the case
// list through queueUpdate, and a key handler runs on the very loop that call
// waits for.
func TestNoScreenFreezesTheEventLoop(t *testing.T) {
	ui, st, screen := liveUI(t)
	seedCases(t, ui, st, 3)
	seedTriageFinding(t, st, "a", "")

	for _, step := range []struct {
		key  rune
		want destinationID
	}{
		{'1', destTriage}, {'2', destCases}, {'3', destEvents},
		{'4', destIndicators}, {'5', destReports}, {'2', destCases}, {'1', destTriage},
	} {
		screen.InjectKey(tcell.KeyRune, step.key, tcell.ModNone)
		// Waiting for the screen to arrive, not merely for the loop to answer:
		// an update can be serviced ahead of a key that is still queued, so a
		// bare ping can pass for a key whose handler has not run yet.
		if !awaitDestination(ui, step.want, 5*time.Second) {
			t.Fatalf("pressing %q never reached %v — the event loop stopped responding",
				step.key, step.want)
		}
	}

	// And Esc, back to Home.
	screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	if err := pingLoop(ui, 5*time.Second); err != nil {
		t.Fatal("the event loop stopped responding after Esc")
	}
}

// The same for the keys that open something over a screen.
func TestNoModalFreezesTheEventLoop(t *testing.T) {
	ui, st, screen := liveUI(t)
	seedCases(t, ui, st, 2)
	seedTriageFinding(t, st, "a", "")

	for _, step := range []struct {
		screen rune
		key    rune
	}{
		{'1', 'f'}, // the triage filter panel
		{'1', '/'}, // the triage search
		{'2', 'f'}, // the case filter
		{'2', 'r'}, // refresh the case list
		{'2', 's'}, // the case summary, which announces itself from the handler
		{'1', 'v'}, // the verdict form
		{'1', 's'}, // the status form
	} {
		screen.InjectKey(tcell.KeyRune, step.screen, tcell.ModNone)
		if err := pingLoop(ui, 5*time.Second); err != nil {
			t.Fatalf("pressing %q froze the application", step.screen)
		}
		screen.InjectKey(tcell.KeyRune, step.key, tcell.ModNone)
		if err := pingLoop(ui, 5*time.Second); err != nil {
			t.Fatalf("pressing %q on screen %q froze the application", step.key, step.screen)
		}
		screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
		if err := pingLoop(ui, 5*time.Second); err != nil {
			t.Fatalf("Esc after %q on screen %q froze the application", step.key, step.screen)
		}
	}
}

// awaitDestination waits for a key to land on its screen.
func awaitDestination(ui *UI, want destinationID, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		got := make(chan destinationID, 1)
		go func() { ui.app.QueueUpdate(func() { got <- ui.destination }) }()
		select {
		case d := <-got:
			if d == want {
				return true
			}
		case <-time.After(time.Until(deadline)):
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// settle waits for the screens' background work while the loop can still
// service it.
// settle drains everything in flight and reports whether it managed to.
//
// The bool matters: a settle that quietly times out leaves work queued against
// an event loop that is about to stop, and every one of those goroutines then
// blocks forever.
func settle(ui *UI, within time.Duration) bool {
	done := make(chan struct{})
	go func() {
		// Home is taken from the screen on the loop and closed off it: the
		// field belongs to the UI goroutine, and close waits for a ticker that
		// queues its own updates.
		var h *homeView
		ui.app.QueueUpdate(func() {
			h, ui.home = ui.home, nil
		})
		if h != nil {
			h.close()
			h.wait()
		}
		ui.waitForLoads()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

// Arrowing an empty pane must not freeze the application.
//
// Every tab's empty state is a table of unselectable cells sitting in a
// selectable table, which is a shape tview can walk forever looking for
// something to land on.
func TestArrowingAnEmptyPaneDoesNotFreeze(t *testing.T) {
	ui, st, screen := liveUI(t)
	seedCases(t, ui, st, 1)

	// Into the first case.
	screen.InjectKey(tcell.KeyRune, '2', tcell.ModNone)
	if !awaitDestination(ui, destCases, 5*time.Second) {
		t.Fatal("never reached the Cases screen")
	}
	// Opened through the loop rather than by injecting Enter: which key opens a
	// case belongs to another test, and this one is about what the arrows do
	// once inside one.
	ui.app.QueueUpdateDraw(func() { ui.openCaseManagement(0) })
	if err := pingLoop(ui, 5*time.Second); err != nil {
		t.Fatal("opening the case froze the application")
	}
	_ = settle(ui, 15*time.Second)

	if ui.activeCM == nil {
		t.Fatal("the case screen never opened, so this test proved nothing")
	}

	// Every tab, empty, arrowed in both directions.
	for tab := 0; tab < len(caseTabNames); tab++ {
		screen.InjectKey(tcell.KeyTab, 0, tcell.ModNone)
		if err := pingLoop(ui, 5*time.Second); err != nil {
			t.Fatalf("reaching tab %d froze the application", tab)
		}
		if !awaitTab(ui, wrapTab(tab+1), 5*time.Second) {
			t.Fatalf("Tab %d left the strip on %d — the keys are not reaching the case",
				tab, ui.activeCM.activeTab)
		}

		for _, key := range []tcell.Key{
			tcell.KeyDown, tcell.KeyDown, tcell.KeyUp, tcell.KeyUp,
			tcell.KeyHome, tcell.KeyEnd, tcell.KeyPgDn, tcell.KeyPgUp,
		} {
			screen.InjectKey(key, 0, tcell.ModNone)
			if err := pingLoop(ui, 5*time.Second); err != nil {
				name := "?"
				if tab < len(caseTabNames) {
					name = caseTabNames[tab]
				}
				t.Fatalf("arrowing the empty %s tab froze the application (key %v)", name, key)
			}
		}
	}
}

// awaitTab waits for a Tab keypress to land on its tab.
//
// Waiting rather than asserting: an update queued behind a key can be serviced
// ahead of it, so a ping proves the loop is alive and not that the keystroke has
// been handled.
func awaitTab(ui *UI, want int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		got := -1
		done := make(chan struct{})
		go func() {
			ui.app.QueueUpdate(func() {
				if ui.activeCM != nil {
					got = ui.activeCM.activeTab
				}
				close(done)
			})
		}()
		select {
		case <-done:
		case <-time.After(within):
			return false
		}
		if got == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// Closing the command palette leaves the application usable.
//
// It closed itself with SetRoot(ui.layout) at three call sites rather than
// through closeModal, which does three things that matters: it clears
// activeModal, restores the root *with* the status bar, and gives focus back to
// the screen. Without it the application still believed a modal was open, so
// isDialogActive suppressed every global key — nothing worked, on any screen,
// for the rest of the session.
func TestClosingTheCommandPaletteLeavesTheAppUsable(t *testing.T) {
	ui, st, screen := liveUI(t)
	seedTriageFinding(t, st, "a", "")

	screen.InjectKey(tcell.KeyRune, '1', tcell.ModNone)
	if !awaitDestination(ui, destTriage, 5*time.Second) {
		t.Fatal("never reached Triage")
	}

	screen.InjectKey(tcell.KeyRune, ':', tcell.ModNone)
	if err := pingLoop(ui, 5*time.Second); err != nil {
		t.Fatal("opening the palette froze the application")
	}
	screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	if err := pingLoop(ui, 5*time.Second); err != nil {
		t.Fatal("closing the palette froze the application")
	}

	// The keys have to work afterwards, which is the actual complaint.
	screen.InjectKey(tcell.KeyRune, '2', tcell.ModNone)
	if !awaitDestination(ui, destCases, 5*time.Second) {
		t.Fatal("after the palette closed, the digits no longer moved between screens")
	}

	var modal tview.Primitive
	done := make(chan struct{})
	go func() {
		ui.app.QueueUpdate(func() {
			modal = ui.activeModal
			close(done)
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop stopped answering")
	}

	if modal != nil {
		t.Error("the palette closed but the application still thinks a modal is open")
	}
}

// The navigation rail is a legend, not a control.
//
// It was a scrollable TextView — tview's default — so a mouse click took focus
// and the arrow keys then scrolled a fixed list of five destinations, while the
// queue the analyst was reading stopped answering them because it no longer had
// focus.
func TestTheNavRailIsNotAControl(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	// A left click where the rail is drawn must not take focus from the queue.
	ui.app.SetFocus(ui.eventList)
	renderPrimitive(t, ui.mainRoot(), 150, 40)

	handler := ui.navRail.MouseHandler()
	consumed, _ := handler(tview.MouseLeftDown,
		tcell.NewEventMouse(3, 5, tcell.Button1, tcell.ModNone),
		func(p tview.Primitive) { ui.app.SetFocus(p) })

	if got := ui.app.GetFocus(); got != ui.eventList {
		t.Errorf("clicking the rail moved focus to %T; the queue should keep it", got)
	}
	_ = consumed

	// And there is nothing to scroll: a fixed list of destinations.
	if _, _, _, height := ui.navRail.GetInnerRect(); height > 0 {
		row, _ := ui.navRail.GetScrollOffset()
		ui.navRail.InputHandler()(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone), func(tview.Primitive) {})
		if after, _ := ui.navRail.GetScrollOffset(); after != row {
			t.Errorf("the rail scrolled from %d to %d; it is a fixed legend", row, after)
		}
	}
}

// Cleanup gives up rather than hanging.
//
// An unbounded wait in a test helper does not fail a test — it stops the whole
// binary until Go's ten-minute timeout, and the panic then names whichever test
// happened to be running rather than the one that leaked. That is exactly how a
// stranded home load presented: nine minutes inside an unrelated test, on
// Windows only, because a loaded agent could not drain inside the old
// five-second budget.
func TestTheHarnessGivesUpRatherThanHanging(t *testing.T) {
	if drained(func() { time.Sleep(2 * time.Second) }, 100*time.Millisecond) {
		t.Error("drained claimed success on work that had not finished")
	}
	if !drained(func() {}, time.Second) {
		t.Error("drained reported failure on work that finished at once")
	}
}

// And settle reports whether it drained, instead of timing out in silence and
// letting the caller stop an event loop that still has work queued against it.
func TestSettleSaysWhetherItDrained(t *testing.T) {
	ui, _, _ := liveUI(t)
	if !settle(ui, 15*time.Second) {
		t.Error("a quiet screen would not settle")
	}
}
