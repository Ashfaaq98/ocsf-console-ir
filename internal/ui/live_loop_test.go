package ui

import (
	"context"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
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
		settle(ui, 5*time.Second)
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
func settle(ui *UI, within time.Duration) {
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
	case <-time.After(within):
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
	settle(ui, 5*time.Second)

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
