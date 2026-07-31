package logging

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedLogger(w *bytes.Buffer, level Level, component string) *Logger {
	l := New(w, level, component)
	l.now = func() time.Time { return time.Date(2026, 7, 30, 16, 19, 9, 0, time.UTC) }
	return l
}

// The point of levels: a failure must be findable without reading every
// keystroke. Before this, both were plain Printf lines.
func TestLevelThresholdFiltersBelowIt(t *testing.T) {
	var buf bytes.Buffer
	l := fixedLogger(&buf, LevelWarn, "ui")

	l.Debug("keystroke j")
	l.Info("loaded 4 events")
	l.Warn("lookup failed")
	l.Error("database is closed")

	out := buf.String()
	for _, dropped := range []string{"keystroke j", "loaded 4 events"} {
		if strings.Contains(out, dropped) {
			t.Errorf("%q was written despite being below the threshold:\n%s", dropped, out)
		}
	}
	for _, kept := range []string{"lookup failed", "database is closed"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q was dropped:\n%s", kept, out)
		}
	}
}

func TestDebugLevelKeepsEverything(t *testing.T) {
	var buf bytes.Buffer
	l := fixedLogger(&buf, LevelDebug, "ui")

	l.Debug("keystroke j")
	l.Error("boom")

	if n := strings.Count(buf.String(), "\n"); n != 2 {
		t.Errorf("got %d lines, want 2:\n%s", n, buf.String())
	}
}

func TestLineFormatIsGreppable(t *testing.T) {
	var buf bytes.Buffer
	fixedLogger(&buf, LevelDebug, "whois").Warn("lookup failed %s: %v", "icann.org", "timeout")

	got := strings.TrimRight(buf.String(), "\n")
	want := "2026-07-30 16:19:09 WARN  [whois] lookup failed icann.org: timeout"
	if got != want {
		t.Errorf("line =\n  %q\nwant\n  %q", got, want)
	}
}

// One record per line is what makes the file greppable; an embedded newline
// would split a record across two lines and orphan the second half.
func TestMultilineMessagesStayOnOneLine(t *testing.T) {
	var buf bytes.Buffer
	fixedLogger(&buf, LevelDebug, "ui").Error("failed:\nline two\nline three")

	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Errorf("got %d newlines, want 1:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "failed: line two line three") {
		t.Errorf("message content lost:\n%s", buf.String())
	}
}

// Printf keeps the pre-levels call sites compiling, and must behave as info.
func TestPrintfAndPrintlnLogAtInfo(t *testing.T) {
	var buf bytes.Buffer
	l := fixedLogger(&buf, LevelWarn, "ui")
	l.Printf("dropped %d", 1)
	l.Println("also dropped")
	if buf.Len() != 0 {
		t.Errorf("Printf/Println wrote below the warn threshold:\n%s", buf.String())
	}

	buf.Reset()
	l = fixedLogger(&buf, LevelInfo, "ui")
	l.Printf("kept %d", 1)
	l.Println("also", "kept")
	out := buf.String()
	if !strings.Contains(out, "INFO") || !strings.Contains(out, "kept 1") {
		t.Errorf("Printf did not log at info:\n%s", out)
	}
	if !strings.Contains(out, "also kept") {
		t.Errorf("Println did not join its arguments:\n%s", out)
	}
}

// Components share one file, so they must share the write lock.
func TestWithSharesTheWriterAndLock(t *testing.T) {
	var buf bytes.Buffer
	root := fixedLogger(&buf, LevelDebug, "serve")
	ui := root.With("ui")
	whois := root.With("whois")

	var wg sync.WaitGroup
	for _, l := range []*Logger{root, ui, whois} {
		wg.Add(1)
		go func(l *Logger) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				l.Info("message")
			}
		}(l)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 150 {
		t.Fatalf("got %d lines, want 150 — writes were interleaved or lost", len(lines))
	}
	for _, line := range lines {
		if !strings.HasSuffix(line, "] message") {
			t.Fatalf("interleaved write: %q", line)
		}
	}

	// The component tag must actually differ.
	out := buf.String()
	for _, c := range []string{"[serve]", "[ui]", "[whois]"} {
		if !strings.Contains(out, c) {
			t.Errorf("missing component tag %s", c)
		}
	}
}

// A nil logger is what callers get when logging is unconfigured; it must not
// panic, since the alternative is nil checks at every call site.
func TestNilLoggerIsSafe(t *testing.T) {
	var l *Logger
	l.Debug("x")
	l.Info("x")
	l.Warn("x")
	l.Error("x")
	l.Printf("x")
	l.Println("x")
	if l.With("ui") != nil {
		t.Error("With on a nil logger should stay nil")
	}
	if l.Enabled(LevelError) {
		t.Error("a nil logger should report nothing enabled")
	}
}

func TestNewWithNilWriterDiscards(t *testing.T) {
	l := New(nil, LevelDebug, "ui")
	l.Error("must not panic")
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug": LevelDebug, "DEBUG": LevelDebug,
		"info": LevelInfo, "": LevelInfo,
		"warn": LevelWarn, "warning": LevelWarn, " WARN ": LevelWarn,
		"error": LevelError,
	}
	for in, want := range cases {
		got, ok := ParseLevel(in)
		if !ok {
			t.Errorf("ParseLevel(%q) reported the input as unrecognised", in)
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}

	// An unrecognised value must be reported, not silently treated as info.
	got, ok := ParseLevel("verbose")
	if ok {
		t.Error("ParseLevel(\"verbose\") reported success")
	}
	if got != LevelInfo {
		t.Errorf("ParseLevel(\"verbose\") = %v, want the info fallback", got)
	}
}

func TestEnabledSkipsExpensiveWork(t *testing.T) {
	l := New(nil, LevelWarn, "ui")
	if l.Enabled(LevelDebug) {
		t.Error("debug reported enabled at the warn threshold")
	}
	if !l.Enabled(LevelError) {
		t.Error("error reported disabled at the warn threshold")
	}
}
