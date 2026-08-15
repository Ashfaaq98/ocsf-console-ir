package cmd

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
)

const (
	// logName is the single file every subsystem logs to. Before v0.2.0 the
	// binary wrote console-ir-ui.log, console-ir-serve.log or
	// console-ir-live.log depending on how it was launched, which is sprawl for
	// a single-binary tool. Subsystems are distinguished by component tag.
	logName = "console-ir.log"

	// logMaxBytes caps one generation. A busy TUI session reached ~3 MB in
	// testing, so 5 MB keeps a whole session in the live file.
	logMaxBytes = 5 << 20

	// logKeep bounds total log disk use at (logKeep+1) * logMaxBytes = 20 MB.
	logKeep = 3
)

var (
	runtimeLogOnce  sync.Once
	runtimeLogFile  *logging.File
	runtimeLogRoot  *logging.Logger
	runtimeLogLevel logging.Level
)

// initRuntimeLog opens the shared log file once and builds the root logger at
// the level requested by --log-level.
func initRuntimeLog() {
	runtimeLogOnce.Do(func() {
		level, ok := logging.ParseLevel(logLevel)
		runtimeLogLevel = level

		f, err := logging.Open(paths.Current().LogFile(logName), logMaxBytes, logKeep)
		if err != nil {
			// Losing the log is worth saying out loud; it is the only place
			// TUI-mode failures are recorded.
			fmt.Fprintf(os.Stderr, "warning: could not open log file: %v\n", err)
			runtimeLogRoot = logging.New(io.Discard, level, "console-ir")
			return
		}
		runtimeLogFile = f
		runtimeLogRoot = logging.New(f, level, "console-ir")

		if !ok {
			runtimeLogRoot.Warn("unrecognised --log-level %q; using info", logLevel)
		}
		runtimeLogRoot.Info("log opened (level=%s path=%s)", level, f.Path())
	})
}

// runtimeLog returns the process-wide rotating log file, or nil if it could not
// be opened. Callers must not close it — Execute does, once, at exit.
func runtimeLog() *logging.File {
	initRuntimeLog()
	return runtimeLogFile
}

// runtimeLogger returns a logger for one component, writing to the shared file.
//
// Every component shares a single underlying writer and lock. Nothing is routed
// to io.Discard any more: subsystems used to be silenced so their output could
// not corrupt the TUI screen, which also silenced every enrichment failure. The
// log is a file now, so severity does the filtering instead.
func runtimeLogger(component string) *logging.Logger {
	initRuntimeLog()
	return runtimeLogRoot.With(component)
}

// runtimeLoggerConsole returns a component logger that writes to the shared
// file and mirrors to console as well — error-filtered stderr under the TUI,
// plain stderr when headless. The file is always written: a message must not be
// lost just because the terminal cannot show it.
func runtimeLoggerConsole(component string, console io.Writer) *logging.Logger {
	initRuntimeLog()
	if runtimeLogFile == nil {
		return logging.New(console, runtimeLogLevel, component)
	}
	return logging.New(io.MultiWriter(runtimeLogFile, console), runtimeLogLevel, component)
}

// runtimeLogPath is the file logs are being written to, for user-facing hints.
func runtimeLogPath() string {
	if f := runtimeLog(); f != nil {
		return f.Path()
	}
	return ""
}

// closeRuntimeLog releases the log file and lets it be opened again.
//
// Resetting the once matters as much as closing the handle. Without it the
// package still believes it is initialised, so runtimeLog hands out a closed
// file and initRuntimeLog will not reopen — every write after a close goes
// nowhere, silently.
//
// It also leaked a handle. On Unix an open file can still be deleted, so a test
// that opened the log and did not close it looked clean; Windows refuses, which
// is how the leak surfaced — "the process cannot access the file because it is
// being used by another process" during a temporary directory's cleanup.
func closeRuntimeLog() {
	if runtimeLogFile != nil {
		_ = runtimeLogFile.Close()
		runtimeLogFile = nil
	}
	runtimeLogRoot = nil
	runtimeLogOnce = sync.Once{}
}
