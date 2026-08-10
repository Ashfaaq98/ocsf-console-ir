package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Folder ingestion starts in both modes.
//
// The HTTP receiver writes each POST as a file and the folder watcher is what
// reads those files into the database. The watcher used to start only inside
// the TUI branch, so headless the receiver answered 202 Accepted and the events
// sat on disk unread — a pipeline pointed at it looked healthy while losing
// every one. v0.2.0 refused the combination rather than lose data; now the two
// halves start together and the refusal is gone.
//
// The end-to-end proof — post an event with no terminal and find it in SQLite —
// is TestPostedEventsReachTheDatabaseHeadless in internal/ingest, which can run
// both halves without runServe blocking on a shutdown signal.
func TestHeadlessHTTPIngestIsNoLongerRefused(t *testing.T) {
	body, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "not supported without the TUI") {
		t.Error("the guard is still in place, so headless HTTP ingestion still refuses to start")
	}
	// And the watcher is no longer started inside the branch that needs a
	// terminal.
	if strings.Contains(string(body), "Start background folder ingestion for the TUI") {
		t.Error("folder ingestion is still started only for the TUI")
	}
}

// Cobra prints the full flag list after any RunE error unless told not to.
// Thirty-eight lines of usage buries the one line explaining the failure.
func TestRuntimeErrorsDoNotPrintUsage(t *testing.T) {
	if !rootCmd.SilenceUsage {
		t.Error("SilenceUsage is off: a runtime error will be followed by the whole flag list")
	}
}

// Every command must say how many positionals it takes.
//
// Without a declaration cobra accepts any number and the command runs anyway:
// `console-ir reset something` reset the database, `console-ir list cases events`
// listed cases and ignored the rest, and `console-ir serve live-events` opened
// the interface instead of reporting a command that had just been removed. A
// stray word is a mistake, and a mistake should be reported rather than
// interpreted.
func TestEveryCommandDeclaresItsArity(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		// Cobra generates help and completion itself; their arity is not ours.
		if c.Name() != "help" && c.Name() != "completion" && !isGenerated(c) {
			if c.Args == nil {
				t.Errorf("%q declares no Args, so it accepts any number of positionals and ignores them",
					c.CommandPath())
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

// isGenerated reports whether cobra added the command rather than we did.
func isGenerated(c *cobra.Command) bool {
	for p := c; p != nil; p = p.Parent() {
		if p.Name() == "completion" || p.Name() == "help" {
			return true
		}
	}
	return false
}
