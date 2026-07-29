package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func tempLog(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "console-ir.log")
}

func size(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// The property that matters: a long-running install must not grow unbounded.
func TestRotationCapsTotalDiskUse(t *testing.T) {
	path := tempLog(t)
	const (
		maxBytes = 100
		keep     = 3
	)
	f, err := Open(path, maxBytes, keep)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// 400 records of 10 bytes = 4 KB written into a 100-byte cap.
	for i := 0; i < 400; i++ {
		if _, err := f.Write([]byte("0123456789")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	var total int64
	for _, p := range logGenerations(t, path) {
		s := size(t, p)
		if s > maxBytes {
			t.Errorf("%s is %d bytes, over the %d cap", p, s, maxBytes)
		}
		total += s
	}

	// (keep + 1) generations at the cap is the ceiling.
	if want := int64(maxBytes * (keep + 1)); total > want {
		t.Errorf("total log bytes = %d, want at most %d", total, want)
	}
}

func TestRotationKeepsExactlyKeepGenerations(t *testing.T) {
	path := tempLog(t)
	const keep = 2
	f, err := Open(path, 20, keep)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	for i := 0; i < 50; i++ {
		if _, err := f.Write([]byte("aaaaaaaaaaaaaaa\n")); err != nil {
			t.Fatal(err)
		}
	}

	if got := len(logGenerations(t, path)); got != keep+1 {
		t.Errorf("found %d files, want %d (the live log plus %d rotated)", got, keep+1, keep)
	}
	// The generation past the cap must have been dropped.
	if _, err := os.Stat(fmt.Sprintf("%s.%d", path, keep+1)); !os.IsNotExist(err) {
		t.Errorf("%s.%d survived, want it dropped", path, keep+1)
	}
}

// Rotation happens before the write, so no record is split across two files —
// a split record is unreadable in both.
func TestRecordsAreNeverSplitAcrossGenerations(t *testing.T) {
	path := tempLog(t)
	f, err := Open(path, 50, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	for i := 0; i < 30; i++ {
		if _, err := f.Write([]byte(fmt.Sprintf("record-%02d\n", i))); err != nil {
			t.Fatal(err)
		}
	}

	for _, p := range logGenerations(t, path) {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			if line == "" {
				continue
			}
			if len(line) != len("record-00") {
				t.Errorf("%s holds a truncated record %q", p, line)
			}
		}
	}
}

// Every subsystem shares one instance, so writes must be serialised.
func TestConcurrentWritesAreSerialised(t *testing.T) {
	path := tempLog(t)
	f, err := Open(path, 200, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := f.Write([]byte(fmt.Sprintf("w%d-%02d\n", n, j))); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	for _, p := range logGenerations(t, path) {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			if line == "" {
				continue
			}
			if len(line) != len("w0-00") {
				t.Errorf("%s holds an interleaved record %q", p, line)
			}
		}
	}
}

func TestOpenAppendsToAnExistingLog(t *testing.T) {
	path := tempLog(t)
	if err := os.WriteFile(path, []byte("earlier session\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := Open(path, 1<<20, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.Write([]byte("this session\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "earlier session") {
		t.Error("Open truncated the previous session's log")
	}
	if !strings.Contains(string(data), "this session") {
		t.Error("the new record was not appended")
	}
}

func TestKeepZeroTruncatesInsteadOfRotating(t *testing.T) {
	path := tempLog(t)
	f, err := Open(path, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	for i := 0; i < 20; i++ {
		if _, err := f.Write([]byte("aaaaaaaaaaaaaaa\n")); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(logGenerations(t, path)); got != 1 {
		t.Errorf("found %d files with keep=0, want 1", got)
	}
	if s := size(t, path); s > 20 {
		t.Errorf("log is %d bytes with keep=0, want at most 20", s)
	}
}

func TestWriteAfterCloseFails(t *testing.T) {
	f, err := Open(tempLog(t), 1<<20, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Close is idempotent: Execute closes the shared log unconditionally.
	if err := f.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := f.Write([]byte("x")); err != ErrClosed {
		t.Errorf("Write after Close = %v, want ErrClosed", err)
	}
}

// logGenerations returns the live log plus every rotated generation.
func logGenerations(t *testing.T, path string) []string {
	t.Helper()
	matches, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	return matches
}
