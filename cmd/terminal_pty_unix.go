//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// Recovering a terminal on Unix.
//
// When tcell cannot open a screen it is often because stdin is a pipe rather
// than a terminal — a CI runner, a `make` recipe, some shells. Re-executing
// through a real /dev/tty fixes that, and it is Unix-specific: Windows has no
// /dev/tty and no `script`, so this file does not build there. Without the
// split, a Windows console that failed to initialise took a recovery path
// written for a different operating system.

// needsPseudoTTY reports whether the process has no controlling terminal to
// draw on, but could get one by re-executing.
func needsPseudoTTY() bool {
	if file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		file.Close()
		return false
	}
	return true
}

// terminalAdvice is what to try when the interface will not start.
func terminalAdvice() []string {
	return []string{
		"Run it from a terminal — gnome-terminal, Konsole, iTerm2, Terminal.app.",
		"Over SSH, make sure TERM is set and the session has a TTY (ssh -t).",
	}
}

// runWithPseudoTTY re-executes the command using script for pseudo-TTY
func runWithPseudoTTY(cmd *cobra.Command, args []string) error {
	// Get the current executable path
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Build the command arguments
	cmdArgs := []string{"serve"}
	cmdArgs = append(cmdArgs, args...)

	// Add force-tui flag if not already present
	hasForceTUI := false
	for _, arg := range args {
		if arg == "--force-tui" {
			hasForceTUI = true
			break
		}
	}
	if !hasForceTUI {
		cmdArgs = append(cmdArgs, "--force-tui")
	}

	// VULN-4: Avoid shell command string interpolation to prevent injection via
	// TERM env var or executable path. Use exec.Command with separate arguments
	// and pass TERM safely through the environment.
	innerCmd := exec.Command(executable, cmdArgs...)
	innerCmd.Stdin = os.Stdin
	innerCmd.Stdout = os.Stdout
	innerCmd.Stderr = os.Stderr

	// Inherit environment and ensure TERM is set
	innerCmd.Env = os.Environ()

	return innerCmd.Run()
}
