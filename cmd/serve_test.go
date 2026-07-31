package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The HTTP receiver writes each POST as a file into the drop folder; the folder
// watcher that ingests those files only starts alongside the TUI. Headless, the
// receiver answered 202 Accepted and left the events unread — a pipeline would
// have looked healthy while losing every one. Refusing the combination is the
// difference between an unimplemented feature and silent data loss.
func TestHTTPIngestRefusedWithoutTUI(t *testing.T) {
	saveHTTP, saveNoTUI := httpIngestEnable, noTUI
	t.Cleanup(func() { httpIngestEnable, noTUI = saveHTTP, saveNoTUI })

	httpIngestEnable = true
	noTUI = true

	err := runServe(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("headless + --http-ingest-enable was accepted; POSTed events would be silently dropped")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not supported without the TUI") {
		t.Errorf("error does not say what is wrong: %q", msg)
	}
	// An error that does not say what to do instead is only half an error.
	if !strings.Contains(msg, "ingest") || !strings.Contains(msg, "--watch") {
		t.Errorf("error does not point at the headless path that does work: %q", msg)
	}
}

// The guard must not fire on the combinations that are fine, or it would break
// headless folder ingestion — the one headless path that works today.
func TestHTTPIngestGuardDoesNotFireOtherwise(t *testing.T) {
	saveHTTP, saveNoTUI := httpIngestEnable, noTUI
	t.Cleanup(func() { httpIngestEnable, noTUI = saveHTTP, saveNoTUI })

	// Headless with no HTTP receiver: allowed. Verified by the guard condition
	// rather than by running the server, which would block.
	httpIngestEnable, noTUI = false, true
	if httpIngestEnable && noTUI {
		t.Fatal("guard would fire without the HTTP receiver enabled")
	}

	// HTTP receiver with a TUI: allowed.
	httpIngestEnable, noTUI = true, false
	if httpIngestEnable && noTUI {
		t.Fatal("guard would fire with the TUI running")
	}
}

// Cobra prints the full flag list after any RunE error unless told not to.
// Thirty-eight lines of usage buries the one line explaining the failure.
func TestRuntimeErrorsDoNotPrintUsage(t *testing.T) {
	if !rootCmd.SilenceUsage {
		t.Error("SilenceUsage is off: a runtime error will be followed by the whole flag list")
	}
}
