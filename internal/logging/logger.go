package logging

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Level is a log severity. Messages below the configured threshold are dropped
// before they reach the file.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// ParseLevel maps a --log-level value to a Level, defaulting to info for
// anything unrecognised. It reports whether the input was understood so the
// caller can warn rather than silently ignoring a typo.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, true
	case "info", "":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error":
		return LevelError, true
	default:
		return LevelInfo, false
	}
}

// Logger writes levelled, component-tagged lines to a shared writer.
//
// Before v0.2.0 every subsystem held a plain *log.Logger and several were wired
// to io.Discard so their output could not corrupt the TUI screen. That silenced
// enrichment failures entirely. Logs now go to a file, so nothing needs
// discarding — but a busy TUI emits enough noise that severity has to be a real
// filter rather than a naming convention.
type Logger struct {
	mu        *sync.Mutex
	w         io.Writer
	level     Level
	component string
	now       func() time.Time
}

// New returns a Logger writing to w. A nil writer discards, which keeps callers
// free of nil checks.
func New(w io.Writer, level Level, component string) *Logger {
	if w == nil {
		w = io.Discard
	}
	return &Logger{
		mu:        &sync.Mutex{},
		w:         w,
		level:     level,
		component: component,
		now:       time.Now,
	}
}

// With returns a Logger sharing this one's writer, threshold and write lock but
// tagged with a different component. Sharing the lock matters: every component
// writes to the same file.
func (l *Logger) With(component string) *Logger {
	if l == nil {
		return nil
	}
	c := *l
	c.component = component
	return &c
}

// Level reports the current threshold.
func (l *Logger) Level() Level {
	if l == nil {
		return LevelInfo
	}
	return l.level
}

// Enabled reports whether a message at this level would be written. Callers use
// it to skip work that only exists to build a log line.
func (l *Logger) Enabled(level Level) bool {
	return l != nil && level >= l.level
}

func (l *Logger) Debug(format string, args ...any) { l.log(LevelDebug, format, args...) }
func (l *Logger) Info(format string, args ...any)  { l.log(LevelInfo, format, args...) }
func (l *Logger) Warn(format string, args ...any)  { l.log(LevelWarn, format, args...) }
func (l *Logger) Error(format string, args ...any) { l.log(LevelError, format, args...) }

// Printf logs at info. It exists so the call sites that predate levels keep
// working unchanged; new code should name a level.
func (l *Logger) Printf(format string, args ...any) { l.log(LevelInfo, format, args...) }

// Println logs at info, joining args the way log.Logger does.
func (l *Logger) Println(args ...any) {
	l.log(LevelInfo, "%s", strings.TrimSuffix(fmt.Sprintln(args...), "\n"))
}

func (l *Logger) log(level Level, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}

	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	// Multi-line messages would otherwise break the one-record-per-line contract
	// that makes the log greppable.
	msg = strings.ReplaceAll(strings.TrimRight(msg, "\n"), "\n", " ")

	line := fmt.Sprintf("%s %-5s [%s] %s\n",
		l.now().Format("2006-01-02 15:04:05"), level, l.component, msg)

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = io.WriteString(l.w, line)
}
