package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// FolderOptions controls ingest-folder behavior.
type FolderOptions struct {
	Dir         string
	Watch       bool
	Patterns    []string // e.g. []string{"*.jsonl", "*.json"}
	CaseTitle   string   // default "Ingested Events"
	Logger      *log.Logger
	// When true and in Watch mode, start JSONL files at EOF on startup to avoid
	// re-ingesting existing lines each time the app starts.
	TailFromEnd bool
}

// FolderIngestor ingests OCSF events from a directory (one-shot or watch mode).
type FolderIngestor struct {
	parser *Parser
	store  *store.Store
	bus    bus.Bus
	opts   FolderOptions

	caseID  string
	offsets map[string]int64 // per-file tail offset for jsonl
	mu      sync.Mutex

	ingested int
	errors   int
}

// NewFolderIngestor constructs a folder ingestor.
func NewFolderIngestor(parser *Parser, st *store.Store, b bus.Bus, opts FolderOptions) *FolderIngestor {
	if opts.Logger == nil {
		opts.Logger = log.New(log.Writer(), "[ingest-folder] ", log.LstdFlags)
	}
	if len(opts.Patterns) == 0 {
		opts.Patterns = []string{"*.jsonl", "*.json"}
	}
	if opts.CaseTitle == "" {
		opts.CaseTitle = "Ingested Events"
	}
	return &FolderIngestor{
		parser:  parser,
		store:   st,
		bus:     b,
		opts:    opts,
		offsets: make(map[string]int64),
	}
}

// Run executes the ingestion per options (one-shot or watch).
func (fi *FolderIngestor) Run(ctx context.Context) error {
	// Only ensure/create case when a title is provided. If empty, skip case assignment.
	if fi.opts.CaseTitle != "" {
		if err := fi.ensureCase(ctx); err != nil {
			return err
		}
	}

	// One-shot initial pass
	if err := fi.scanOnce(ctx); err != nil {
		return err
	}

	if !fi.opts.Watch {
		// Final case count sync
		_ = fi.store.UpdateCaseEventCount(ctx, fi.caseID)
		fi.opts.Logger.Printf("Completed one-shot ingest: ingested=%d errors=%d", fi.ingested, fi.errors)
		return nil
	}

	// Watch mode
	return fi.watchLoop(ctx)
}

func (fi *FolderIngestor) matches(name string) bool {
	lower := strings.ToLower(name)
	for _, pat := range fi.opts.Patterns {
		p := strings.TrimSpace(strings.ToLower(pat))
		ok, _ := filepath.Match(p, lower)
		if ok {
			return true
		}
	}
	return false
}

func (fi *FolderIngestor) scanOnce(ctx context.Context) error {
	entries, err := os.ReadDir(fi.opts.Dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !fi.matches(e.Name()) {
			continue
		}
		path := filepath.Join(fi.opts.Dir, e.Name())
		if strings.HasSuffix(strings.ToLower(e.Name()), ".jsonl") {
			// If configured to tail from end in watch mode, initialize the offset to EOF
			// so we don't re-ingest existing lines on every startup.
			if fi.opts.Watch && fi.opts.TailFromEnd {
				if st, err := os.Stat(path); err == nil {
					fi.mu.Lock()
					fi.offsets[path] = st.Size()
					fi.mu.Unlock()
				}
				// Do not process existing content now; watchLoop will tail new lines.
				continue
			}
			if _, err := fi.processJSONL(ctx, path, 0); err != nil {
				fi.opts.Logger.Printf("error processing %s: %v", path, err)
				fi.errors++
			}
		} else if strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			if err := fi.processJSONFile(ctx, path); err != nil {
				fi.opts.Logger.Printf("error processing %s: %v", path, err)
				fi.errors++
			}
		}
	}
	return nil
}

func (fi *FolderIngestor) watchLoop(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}
	defer w.Close()

	if err := w.Add(fi.opts.Dir); err != nil {
		return fmt.Errorf("watch add: %w", err)
	}

	fi.opts.Logger.Printf("Watching directory: %s (patterns: %s)", fi.opts.Dir, strings.Join(fi.opts.Patterns, ","))
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if fi.caseID != "" {
				_ = fi.store.UpdateCaseEventCount(context.Background(), fi.caseID)
			}
			fi.opts.Logger.Printf("Watch stopping: ingested=%d errors=%d", fi.ingested, fi.errors)
			return ctx.Err()
		case ev := <-w.Events:
			// Only handle writes/creates on matching files
			name := filepath.Base(ev.Name)
			if !fi.matches(name) {
				continue
			}
			lower := strings.ToLower(name)

			if (ev.Op&fsnotify.Create) != 0 || (ev.Op&fsnotify.Write) != 0 {
				switch {
				case strings.HasSuffix(lower, ".jsonl"):
					// Tail from last offset (or 0 if new file)
					fi.mu.Lock()
					offset := fi.offsets[ev.Name]
					fi.mu.Unlock()

					newOffset, err := fi.processJSONL(ctx, ev.Name, offset)
					if err != nil {
						fi.opts.Logger.Printf("error tailing %s: %v", ev.Name, err)
						fi.errors++
						continue
					}
					fi.mu.Lock()
					fi.offsets[ev.Name] = newOffset
					fi.mu.Unlock()
				case strings.HasSuffix(lower, ".json"):
					// Re-process entire file on write
					if err := fi.processJSONFile(ctx, ev.Name); err != nil {
						fi.opts.Logger.Printf("error processing %s: %v", ev.Name, err)
						fi.errors++
					}
				}
			}
			if (ev.Op&fsnotify.Remove) != 0 || (ev.Op&fsnotify.Rename) != 0 {
				fi.mu.Lock()
				delete(fi.offsets, ev.Name)
				fi.mu.Unlock()
			}
		case err := <-w.Errors:
			if err != nil {
				fi.opts.Logger.Printf("watch error: %v", err)
			}
		case <-ticker.C:
			// Periodically sync case event count (only when using a case)
			if fi.caseID != "" {
				_ = fi.store.UpdateCaseEventCount(context.Background(), fi.caseID)
			}
		}
	}
}

func (fi *FolderIngestor) processJSONL(ctx context.Context, path string, startOffset int64) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		// File might be transiently missing (rename/rotate)
		return startOffset, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err == nil {
		// Handle truncation: if shrunk, reset offset
		if st.Size() < startOffset {
			startOffset = 0
		}
	}
	if startOffset > 0 {
		if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
			return startOffset, err
		}
	}

	reader := bufio.NewScanner(f)
	// Increase buffer for long JSON lines
	buf := make([]byte, 0, 1024*1024)
	reader.Buffer(buf, 10*1024*1024)

	var bytesRead int64 = startOffset
	for reader.Scan() {
		line := strings.TrimSpace(reader.Text())
		bytesRead += int64(len(reader.Bytes())) + 1 // include newline approx
		if line == "" {
			continue
		}
		if err := fi.processEventJSON(ctx, []byte(line)); err != nil {
			fi.opts.Logger.Printf("parse error in %s: %v", path, err)
			fi.errors++
			continue
		}
		fi.ingested++
	}
	if err := reader.Err(); err != nil {
		return bytesRead, err
	}
	return bytesRead, nil
}

func (fi *FolderIngestor) processJSONFile(ctx context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	trim := strings.TrimSpace(string(data))
	if trim == "" {
		return nil
	}

	// If array, iterate; else parse single
	if strings.HasPrefix(trim, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(trim), &arr); err != nil {
			return err
		}
		for _, raw := range arr {
			if err := fi.processEventJSON(ctx, raw); err != nil {
				fi.errors++
				continue
			}
			fi.ingested++
		}
		return nil
	}

	if err := fi.processEventJSON(ctx, []byte(trim)); err != nil {
		return err
	}
	fi.ingested++
	return nil
}

func (fi *FolderIngestor) processEventJSON(ctx context.Context, raw []byte) error {
	ocsfEvent, err := fi.parser.ParseEvent(raw)
	if err != nil {
		return err
	}

	eventID, err := fi.store.SaveEvent(ctx, ocsfEvent)
	if err != nil {
		return err
	}

		// Assign to the ingest case when configured
		if fi.caseID != "" {
			if err := fi.store.AssignEventToCase(ctx, eventID, fi.caseID); err != nil {
				return err
			}
		}

	// Best-effort publish to bus (optional, no-op on NullBus)
	_ = fi.bus.PublishEvent(ctx, bus.EventMessage{
		EventID:   eventID,
		EventType: string(ocsfEvent.GetEventType()),
		RawJSON:   string(raw),
		Timestamp: ocsfEvent.Time.Unix(),
	})

	return nil
}

func (fi *FolderIngestor) ensureCase(ctx context.Context) error {
	// Try to find existing case by title (simple scan)
	cases, err := fi.store.ListCases(ctx)
	if err != nil {
		return err
	}
	for _, c := range cases {
		if c.Title == fi.opts.CaseTitle {
			fi.caseID = c.ID
			return nil
		}
	}
	// Create new case
	newCase := store.Case{
		Title:       fi.opts.CaseTitle,
		Description: "Folder-ingested events",
		Severity:    "medium",
		Status:      "open",
	}
	id, err := fi.store.CreateOrUpdateCase(ctx, newCase)
	if err != nil {
		return err
	}
	if id == "" {
		return errors.New("failed to create ingest case")
	}
	fi.caseID = id
	return nil
}