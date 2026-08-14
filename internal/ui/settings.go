package ui

import (
	"fmt"
	"strings"
)

// Settings: what the application is doing, and the few things worth changing
// without restarting it.
//
// Status first. The HTTP receiver could be switched on with a flag and then
// reported itself in one line of a log file nobody reads — from inside the
// application there was no way to tell whether it was listening, on what
// address, whether anything had arrived, or whether it was open to anyone who
// could reach the port.
//
// Toggles second, and only where a toggle is honest. The listener's address and
// token stay on the command line: those are decisions about what to expose and
// to whom, and a panel that appeared to set them without persisting them would
// be worse than not offering them.

// IngestListener is the HTTP receiver, as much of it as this screen needs.
//
// An interface so the ui package depends on a shape rather than on the ingest
// package — the same arrangement the evidence pulse uses for the folder
// watcher.
type IngestListener interface {
	Listening() bool
	Address() string
	HasToken() bool
	Received() int
	Start() error
	Stop()
}

// SetIngestListener supplies the HTTP receiver. Without one the settings panel
// says the feature is unavailable, which is the truthful answer for a UI built
// without it.
func (ui *UI) SetIngestListener(l IngestListener) { ui.listener = l }

// listenerLabel is the receiver's state in one line, for the status bar.
func (ui *UI) listenerLabel() string {
	t := ui.theme
	switch {
	case ui.listener == nil:
		return fmt.Sprintf("HTTP ingest                [%s]unavailable[-:-:-]", t.TagMuted)
	case ui.listener.Listening():
		return fmt.Sprintf("HTTP ingest                [%s]listening on %s[-:-:-]",
			t.TagSuccess, ui.listener.Address())
	default:
		return fmt.Sprintf("HTTP ingest                [%s]off[-:-:-]", t.TagMuted)
	}
}

// listenerDetail is what an analyst needs to decide whether to switch it on.
func (ui *UI) listenerDetail() string {
	t := ui.theme
	if ui.listener == nil {
		return "   this build has no receiver"
	}
	if !ui.listener.Listening() {
		if !ui.listener.HasToken() {
			// Said before it is switched on, not after. Anything that can reach
			// the address can write into this analyst's case data.
			return fmt.Sprintf("   [%s]no token set — anything that can reach %s could post events[-:-:-]",
				t.TagWarning, ui.listener.Address())
		}
		return "   ⏎ starts it; posted events are ingested as if dropped in the folder"
	}

	auth := fmt.Sprintf("[%s]no token[-:-:-]", t.TagWarning)
	if ui.listener.HasToken() {
		auth = fmt.Sprintf("[%s]token required[-:-:-]", t.TagMuted)
	}
	return fmt.Sprintf("   %s · %s accepted", auth, plural(ui.listener.Received(), "payload"))
}

// toggleIngestListener starts or stops the receiver.
func (ui *UI) toggleIngestListener(refresh func()) {
	if ui.listener == nil {
		ui.setStatusDirect("[%s]This build has no HTTP receiver[-:-:-]", ui.theme.TagMuted)
		return
	}

	if ui.listener.Listening() {
		ui.listener.Stop()
		ui.setStatusDirect("[%s]HTTP ingest stopped[-:-:-]", ui.theme.TagAccent)
		refresh()
		return
	}

	if err := ui.listener.Start(); err != nil {
		ui.setStatusDirect("[%s]Could not start HTTP ingest: %v[-:-:-]", ui.theme.TagError, err)
		return
	}

	// The warning goes with the confirmation, where it is read, rather than
	// only in the panel behind it.
	if !ui.listener.HasToken() {
		ui.setStatusDirect("[%s]HTTP ingest listening on %s · no token — anyone who can reach it may post[-:-:-]",
			ui.theme.TagWarning, ui.listener.Address())
	} else {
		ui.setStatusDirect("[%s]HTTP ingest listening on %s[-:-:-]",
			ui.theme.TagSuccess, ui.listener.Address())
	}
	refresh()
}

// showThemeCycle moves to the next theme and says which.
//
// The settings panel names the current one, so the cycle is no longer blind
// even though it is still a cycle.
func (ui *UI) showThemeCycle() {
	ui.cycleTheme()
	ui.setStatusDirect("[%s]Theme: %s[-:-:-]", ui.theme.TagAccent,
		strings.ReplaceAll(ui.themeName, "-", " "))
}
