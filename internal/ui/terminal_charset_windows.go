//go:build windows

package ui

import (
	"os"
	"strings"
	"syscall"
)

// codePageUTF8 is what a console set to UTF-8 reports.
const codePageUTF8 = 65001

var (
	kernel32Charset        = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleOutputCP = kernel32Charset.NewProc("GetConsoleOutputCP")
)

// On Windows the console's output code page says it.
//
// Windows has no LC_ALL or LANG, so asking for them returned nothing and the
// whole interface fell back to ASCII on every Windows machine — frames drawn as
// +---+, scrollbars as pipes, the sparkline as underscores — on a platform
// whose default terminal renders UTF-8 perfectly well.
//
// Three answers, in order:
//
//  1. WT_SESSION is set by Windows Terminal, which is UTF-8 throughout
//     whatever the legacy console code page happens to say. Believed first
//     because the code page can still read 437 in a Windows Terminal tab.
//  2. The console output code page, asked of the console itself.
//  3. A Unix-style locale variable, because a Cygwin, MSYS or Git Bash shell
//     sets one and is running a terminal that honours it.
//
// The Glyphs preference overrides all of this, for a terminal that claims more
// than it can draw.
func platformSupportsUnicode() bool {
	if strings.TrimSpace(os.Getenv("WT_SESSION")) != "" {
		return true
	}

	if cp, ok := consoleOutputCP(); ok {
		return cp == codePageUTF8
	}

	// No console attached — a redirected or piped run. Nothing is being drawn
	// for a person to look at, so the answer does not matter much; UTF-8 is the
	// better default for anything capturing the output.
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if val := strings.ToLower(os.Getenv(key)); val != "" {
			return strings.Contains(val, "utf-8") || strings.Contains(val, "utf8")
		}
	}
	return true
}

// consoleOutputCP asks the console for its output code page. The bool is false
// when there is no console to ask.
func consoleOutputCP() (int, bool) {
	ret, _, _ := procGetConsoleOutputCP.Call()
	if ret == 0 {
		return 0, false
	}
	return int(ret), true
}
