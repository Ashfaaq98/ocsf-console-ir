// Package logging provides the single size-rotated log file Console-IR writes
// to. Before v0.2.0 logs were opened in append mode with no rotation, so a
// long-running install grew unbounded, and three different files were written
// depending on how the binary was launched.
package logging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrClosed is returned by Write after Close.
var ErrClosed = errors.New("logging: file is closed")

// File is an append-only log file that rotates once it exceeds a size cap.
// It is safe for concurrent use: every subsystem in the process shares one
// instance, so two rotators can never fight over the same path.
type File struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

// Open opens path for appending, rotating it when a write would take it past
// maxBytes and keeping keep older generations. keep <= 0 truncates instead of
// rotating. maxBytes <= 0 disables rotation entirely.
func Open(path string, maxBytes int64, keep int) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &File{path: path, maxBytes: maxBytes, keep: keep, f: f, size: info.Size()}, nil
}

// Path is the file currently being written to.
func (r *File) Path() string { return r.path }

// Size is the number of bytes in the current generation.
func (r *File) Size() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// Write appends p, rotating first if it would not fit. Rotation happens before
// the write rather than after, so a single log record is never split across two
// generations — which would make it unreadable in both.
func (r *File) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		return 0, ErrClosed
	}
	// r.size > 0 keeps a single record larger than the cap in one piece rather
	// than rotating an empty file forever.
	if r.maxBytes > 0 && r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate shifts console-ir.log to console-ir.log.1, .1 to .2 and so on,
// dropping the oldest generation. The caller holds r.mu.
func (r *File) rotate() error {
	if err := r.f.Close(); err != nil {
		r.f = nil
		return err
	}
	r.f = nil

	if r.keep <= 0 {
		// No history wanted: start the file over.
		if err := os.Remove(r.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		// Renames are best-effort. A missing generation is normal (the log has
		// not rotated that many times yet), and a failure must not take down the
		// process that is only trying to log.
		_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
		for i := r.keep - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
		}
		_ = os.Rename(r.path, r.path+".1")
	}

	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

// Close closes the underlying file. It is safe to call more than once.
func (r *File) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
