//go:build windows

package cmd

import "github.com/spf13/cobra"

// There is no pseudo-terminal recovery on Windows.
//
// The Unix path re-executes through /dev/tty when stdin is not a terminal.
// Windows has neither /dev/tty nor `script`, so the check that drove it — "can
// I open /dev/tty?" — was always false there, and every console that failed to
// initialise was sent down a recovery route built for another operating system.
// Saying so plainly is better than attempting it.

// needsPseudoTTY is always false here: there is nothing to re-execute through.
func needsPseudoTTY() bool { return false }

// runWithPseudoTTY is unreachable on Windows and exists to satisfy the caller.
func runWithPseudoTTY(_ *cobra.Command, _ []string) error { return nil }

// terminalAdvice is what to try when the interface will not start.
func terminalAdvice() []string {
	return []string{
		"Run it from Windows Terminal, PowerShell or the Command Prompt.",
		"A redirected or piped stdin has no console to draw on.",
	}
}
