package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// fakeListener stands in for the HTTP receiver.
type fakeListener struct {
	listening bool
	token     bool
	received  int
	startErr  error
	starts    int
	stops     int
}

func (f *fakeListener) Listening() bool { return f.listening }
func (f *fakeListener) Address() string { return "127.0.0.1:8081" }
func (f *fakeListener) HasToken() bool  { return f.token }
func (f *fakeListener) Received() int   { return f.received }
func (f *fakeListener) Stop()           { f.stops++; f.listening = false }
func (f *fakeListener) Start() error {
	f.starts++
	if f.startErr != nil {
		return f.startErr
	}
	f.listening = true
	return nil
}

func settingsFrame(t *testing.T, ui *UI) string {
	t.Helper()
	if ui.activeModal == nil {
		t.Fatal("the settings panel is not open")
	}
	return stripTags(strings.Join(renderPrimitive(t, ui.activeModal, 150, 34), "\n"))
}

// The panel says what the receiver is doing.
//
// Switched on with a flag, it reported itself in one line of a log file nobody
// reads: from inside the application there was no way to tell whether it was
// listening, where, or whether anything had arrived.
func TestSettingsShowsTheListenerState(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	l := &fakeListener{listening: true, token: true, received: 12}
	ui.SetIngestListener(l)

	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, ',', tcell.ModNone)) != nil {
		t.Fatal("the settings key was not claimed")
	}
	got := settingsFrame(t, ui)

	for _, want := range []string{"HTTP ingest", "listening on 127.0.0.1:8081", "12 payloads", "token required"} {
		if !strings.Contains(got, want) {
			t.Errorf("the panel does not say %q:\n%s", want, got)
		}
	}
	ui.closeModal()
}

// An open port with no token is said plainly, before it is opened.
func TestSettingsWarnsAboutAnOpenListener(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	ui.SetIngestListener(&fakeListener{listening: false, token: false})

	ui.showSettings()
	got := settingsFrame(t, ui)
	if !strings.Contains(got, "no token") {
		t.Errorf("the panel does not warn that anyone could post:\n%s", got)
	}
	ui.closeModal()
}

// The toggle starts and stops it, and says so.
func TestTheListenerToggles(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	l := &fakeListener{token: true}
	ui.SetIngestListener(l)

	ui.toggleIngestListener(func() {})
	if l.starts != 1 || !l.listening {
		t.Fatalf("the toggle did not start the listener (starts=%d listening=%v)", l.starts, l.listening)
	}
	if bar := stripTags(ui.statusBar.GetText(true)); !strings.Contains(bar, "listening on") {
		t.Errorf("starting it said nothing useful: %s", bar)
	}

	ui.toggleIngestListener(func() {})
	if l.stops != 1 || l.listening {
		t.Errorf("the toggle did not stop the listener (stops=%d listening=%v)", l.stops, l.listening)
	}
}

// Starting one with no token warns in the confirmation, where it is read.
func TestStartingAnOpenListenerWarns(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.SetIngestListener(&fakeListener{token: false})

	ui.toggleIngestListener(func() {})

	bar := stripTags(ui.statusBar.GetText(true))
	if !strings.Contains(bar, "no token") {
		t.Errorf("starting an unauthenticated listener did not say so: %s", bar)
	}
}

// A refusal to start is reported rather than shown as success.
func TestAListenerThatWillNotStartSaysWhy(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.SetIngestListener(&fakeListener{token: true, startErr: errors.New("address already in use")})

	ui.toggleIngestListener(func() {})

	bar := stripTags(ui.statusBar.GetText(true))
	if !strings.Contains(bar, "address already in use") {
		t.Errorf("a failed start was not reported: %s", bar)
	}
}

// A build without a receiver says so rather than offering a dead toggle.
func TestSettingsWithoutAListener(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	ui.showSettings()
	got := settingsFrame(t, ui)
	if !strings.Contains(got, "unavailable") {
		t.Errorf("a build with no receiver does not say so:\n%s", got)
	}
	ui.closeModal()
}
