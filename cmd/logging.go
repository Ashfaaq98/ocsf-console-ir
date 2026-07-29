package cmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
)

const (
	// logName is the single file every subsystem logs to. Before v0.2.0 the
	// binary wrote console-ir-ui.log, console-ir-serve.log or
	// console-ir-live.log depending on how it was launched, which is sprawl for
	// a single-binary tool. Subsystems are distinguished by logger prefix.
	logName = "console-ir.log"

	// logMaxBytes caps one generation. A busy TUI session reached ~3 MB in
	// testing, so 5 MB keeps a whole session in the live file.
	logMaxBytes = 5 << 20

	// logKeep bounds total log disk use at (logKeep+1) * logMaxBytes = 20 MB.
	logKeep = 3
)

var (
	runtimeLogOnce sync.Once
	runtimeLogFile *logging.File
)

// runtimeLog returns the process-wide rotating log file, or nil if it could not
// be opened. Callers must not close it — Execute does, once, at exit.
func runtimeLog() *logging.File {
	runtimeLogOnce.Do(func() {
		f, err := logging.Open(paths.Current().LogFile(logName), logMaxBytes, logKeep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not open log file: %v\n", err)
			return
		}
		runtimeLogFile = f
	})
	return runtimeLogFile
}

// runtimeLogger returns a logger writing to the shared log file. If the file
// could not be opened it discards instead of falling back to stderr, because
// every caller is a TUI path where stray writes corrupt the terminal.
func runtimeLogger(prefix string) *log.Logger {
	if f := runtimeLog(); f != nil {
		return log.New(f, prefix, log.LstdFlags)
	}
	return log.New(io.Discard, prefix, log.LstdFlags)
}

// runtimeLogWriter returns the shared log file as an io.Writer, or io.Discard.
func runtimeLogWriter() io.Writer {
	if f := runtimeLog(); f != nil {
		return f
	}
	return io.Discard
}

// runtimeLogPath is the file logs are being written to, for user-facing hints.
func runtimeLogPath() string {
	if f := runtimeLog(); f != nil {
		return f.Path()
	}
	return ""
}

func closeRuntimeLog() {
	if runtimeLogFile != nil {
		_ = runtimeLogFile.Close()
	}
}
