package ingest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/fsnotify/fsnotify"
)

// FolderOptions controls ingest-folder behavior.
type FolderOptions struct {
	Dir       string
	Watch     bool
	Patterns  []string // e.g. []string{"*.jsonl", "*.json"}
	CaseTitle string   // default "Ingested Events"
	Logger    *logging.Logger
	// When true and in Watch mode, a JSONL file that has no persisted offset
	// (i.e. one never seen before) starts at EOF instead of being imported from
	// the beginning. Restart de-duplication is handled by persisted offsets
	// (see StateFile), so this is only needed to skip importing a large existing
	// backlog. Default false: pre-existing files are ingested once on startup.
	TailFromEnd bool
	// StateFile is where per-file byte offsets are persisted between runs so a
	// restart resumes where it left off instead of re-ingesting. Watch mode only.
	// Defaults to ".ingest-offsets.state" inside Dir when empty.
	StateFile string
	// Enricher, when set, receives each ingested event for in-process
	// enrichment by embedded core plugins. Optional; nil disables it.
	Enricher Enricher
	// MarksFile is where the digests of whole-file .json payloads are persisted
	// between runs. Watch mode only; defaults to ".ingest-marks.state" in Dir.
	//
	// Nothing ever deletes an ingested payload, and the startup scan reads every
	// file it finds, so without this a restart re-ingests the entire accumulated
	// drop folder — every event again, indistinguishable from new telemetry.
	// The byte offsets that give .jsonl this property have always been
	// persisted; this is the same guarantee for .json.
	MarksFile string
	// SweepInterval is how often watch mode re-reads the directory as a backstop
	// behind fsnotify. Defaults to defaultSweepInterval when zero.
	//
	// It is not an optimisation. fsnotify drops creates — most visibly on
	// Windows, where the watch is not fully established when Add returns — and
	// without a sweep a dropped notification means the file is never read at
	// all. The sender is told 202 Accepted and the events sit on disk.
	SweepInterval time.Duration
}

// defaultSweepInterval is how long a file can sit unread when fsnotify misses
// its create. Short enough that a pipeline stall is measured in seconds, long
// enough that an idle watcher is one ReadDir every few seconds.
const defaultSweepInterval = 3 * time.Second

// FolderIngestor ingests OCSF events from a directory (one-shot or watch mode).
// DefaultDir is the drop folder watched when none is configured.
//
// It sits beside the working directory rather than inside the database
// directory: the database is precious state written only by the app, while the
// inbox is a throwaway landing zone written by users and pipelines. Co-locating
// them made "clear the inbox" and "destroy the database" the same rm -rf.
//
// It stays working-directory-relative on purpose — a landing zone buried under
// ~/.local/share is one you cannot drop files into.
const DefaultDir = "./incoming"

type FolderIngestor struct {
	parser *Parser
	store  *store.Store
	bus    bus.Bus
	opts   FolderOptions

	caseID  string
	offsets map[string]int64 // per-file tail offset for jsonl
	marks   map[string]fileMark
	mu      sync.Mutex

	// Counters, read by the dashboard from the UI goroutine while ingestion
	// writes them. Atomic, and lastErr under mu, so the evidence pulse can show
	// watcher health without racing the watcher.
	ingested int64
	errors   int64
	lastErr  string
	// sweeps counts completed directory re-reads. The sweep is a backstop, so
	// it is invisible when fsnotify is working — which is every run on Linux,
	// and why a ticker that did nothing survived until Windows CI found it.
	sweeps int64
}

// maxIngestFileBytes bounds how much of one dropped file is read into memory.
// The drop folder is written by forwarders and scripts, some of which may be
// the very host under investigation, so an entry there is untrusted input.
const maxIngestFileBytes = 256 << 20

// ingestEntryOK rejects an entry before anything opens it.
//
// The pattern match only ever looked at the name, and os.ReadDir reports what
// lstat says, so a symlink or a named pipe called events.json passed straight
// through to a read. Opening a pipe with no writer blocks forever inside the
// single ingest goroutine — ingestion simply stops, with the watcher still
// reporting itself healthy — and reading a symlink to an endless device, or a
// sparse file the size of a disk, allocates until the runtime dies of it,
// taking the interface, the store and every service down with it.
//
// Lstat, not Stat: the point is to see the symlink rather than follow it.
func ingestEntryOK(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file (%s), skipped", path, info.Mode())
	}
	if info.Size() > maxIngestFileBytes {
		return fmt.Errorf("%s: %d bytes exceeds the %d byte ingest limit, skipped",
			path, info.Size(), maxIngestFileBytes)
	}
	return nil
}

// fileMark is what the ingestor remembers about a whole-file .json so it can
// tell "already ingested" from "changed since". A .jsonl needs none of this:
// its byte offset already says where reading stopped.
//
// sum is the authority, and it is a digest of the bytes that were actually
// ingested. Size and modification time alone cannot do this job: writing a file
// emits a creation and then a write, and the modification time recorded between
// them describes content that was never read. That mark then either failed to
// match — ingesting the file twice — or matched a file whose contents had not
// been read at all, stranding it permanently.
//
// size and modTime remain only as a cheap pre-filter, letting the sweep skip
// re-reading a file that is certainly unchanged. Correctness never rests on
// them: a mark that does not match simply means the file is read and hashed.
type fileMark struct {
	size    int64
	modTime time.Time
	sum     [sha256.Size]byte
}

func (m fileMark) unchanged(info os.FileInfo) bool {
	return m.size == info.Size() && m.modTime.Equal(info.ModTime())
}

// NewFolderIngestor constructs a folder ingestor.
func NewFolderIngestor(parser *Parser, st *store.Store, b bus.Bus, opts FolderOptions) *FolderIngestor {
	// A nil bus is a caller that does not want events published, not a caller
	// asking to crash on the first record ingested. Every publish here is
	// best-effort already; this makes "no bus" one of the ways it can be.
	if b == nil {
		b = bus.NewNullBus(opts.Logger)
	}
	if opts.Logger == nil {
		opts.Logger = nil
	}
	if len(opts.Patterns) == 0 {
		opts.Patterns = []string{"*.jsonl", "*.json"}
	}
	if opts.CaseTitle == "" {
		opts.CaseTitle = "Ingested Events"
	}
	if opts.StateFile == "" && opts.Dir != "" {
		// A ".state" name so it never matches the *.json / *.jsonl watch patterns.
		opts.StateFile = filepath.Join(opts.Dir, ".ingest-offsets.state")
	}
	if opts.MarksFile == "" && opts.Dir != "" {
		// A ".state" name so it never matches the *.json / *.jsonl patterns.
		opts.MarksFile = filepath.Join(opts.Dir, ".ingest-marks.state")
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = defaultSweepInterval
	}
	return &FolderIngestor{
		parser:  parser,
		store:   st,
		bus:     b,
		opts:    opts,
		offsets: make(map[string]int64),
		marks:   make(map[string]fileMark),
	}
}

// Run executes the ingestion per options (one-shot or watch).
func (fi *FolderIngestor) Run(ctx context.Context) error {
	// The case is created on the first record that lands in it, not here.
	// Creating it up front puts an empty "Ingested Events" case in the Cases
	// list of anyone who merely configures a watch folder — and it is the first
	// thing they see, ahead of the cases they actually opened.

	// In watch mode, resume from persisted offsets so a restart does not
	// re-ingest files that were already read.
	if fi.opts.Watch {
		fi.loadOffsets()
		fi.loadMarks()
	}

	// One-shot initial pass
	if err := fi.scanOnce(ctx, true); err != nil {
		return err
	}

	if !fi.opts.Watch {
		// Final case count sync, if anything created the case.
		if fi.caseID != "" {
			_ = fi.store.UpdateCaseEventCount(ctx, fi.caseID)
		}
		fi.opts.Logger.Printf("Completed one-shot ingest: ingested=%d errors=%d", atomic.LoadInt64(&fi.ingested), atomic.LoadInt64(&fi.errors))
		return nil
	}

	// Persist offsets reached by the initial pass before we begin tailing.
	fi.saveOffsets()

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

// scanOnce reads every matching file in the directory once.
//
// initial distinguishes the pass made at startup from the periodic sweep behind
// fsnotify. It only governs TailFromEnd, which exists to skip a backlog that was
// already on disk when the watcher started. A file that appears later is not
// backlog, and skipping it would mean whether its contents were ingested
// depended on whether the sweep or the notification reached it first.
func (fi *FolderIngestor) scanOnce(ctx context.Context, initial bool) error {
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
		if err := ingestEntryOK(path); err != nil {
			fi.opts.Logger.Printf("skipping %s: %v", path, err)
			fi.recordError(err)
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".jsonl") {
			fi.mu.Lock()
			offset, seen := fi.offsets[path]
			fi.mu.Unlock()

			// A brand-new file (no persisted offset) in tail-only mode starts at
			// EOF so an existing backlog isn't imported. Files already seen resume
			// from their offset; otherwise we ingest from the beginning.
			if !seen && initial && fi.opts.Watch && fi.opts.TailFromEnd {
				if st, err := os.Stat(path); err == nil {
					fi.mu.Lock()
					fi.offsets[path] = st.Size()
					fi.mu.Unlock()
				}
				continue
			}

			newOffset, err := fi.processJSONL(ctx, path, offset)
			if err != nil {
				fi.opts.Logger.Printf("error processing %s: %v", path, err)
				fi.recordError(err)
				continue
			}
			fi.mu.Lock()
			fi.offsets[path] = newOffset
			fi.mu.Unlock()
		} else if strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			// A whole-file .json is re-read in full every time it is processed,
			// so the sweep has to know it has already read this one. Without the
			// mark, every .json sitting in the drop folder would be ingested
			// again on every sweep.
			info, err := e.Info()
			if err != nil {
				continue
			}
			if mark, seen := fi.markOf(path); seen && mark.unchanged(info) {
				continue
			}
			if err := fi.ingestJSONFile(ctx, path); err != nil {
				fi.opts.Logger.Printf("error processing %s: %v", path, err)
				fi.recordError(err)
				continue
			}
		}
	}
	return nil
}

// markOf reports what was last ingested from a whole-file .json.
func (fi *FolderIngestor) markOf(path string) (fileMark, bool) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	m, ok := fi.marks[path]
	return m, ok
}

// setMark records the digest of the bytes ingested from path, together with the
// file's size and modification time as they stand now. A stat that fails leaves
// those two zero, which the pre-filter reads as "changed": the file is read
// again next sweep and the digest decides.
func (fi *FolderIngestor) setMark(path string, sum [sha256.Size]byte) {
	m := fileMark{sum: sum}
	if info, err := os.Stat(path); err == nil {
		m.size, m.modTime = info.Size(), info.ModTime()
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.marks[path] = m
}

// ingestJSONFile reads a whole-file .json and ingests it unless these exact
// bytes have already been ingested. Both the watcher and the sweep go through
// here, so neither can ingest the same content twice or record content it never
// read.
func (fi *FolderIngestor) ingestJSONFile(ctx context.Context, path string) error {
	if err := ingestEntryOK(path); err != nil {
		return err
	}
	// Bounded even though ingestEntryOK just checked the size: the file can grow
	// between the two, and this is the read that would allocate without end.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxIngestFileBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxIngestFileBytes {
		return fmt.Errorf("%s exceeds the %d byte ingest limit", path, maxIngestFileBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		// Nothing to ingest, and nothing to remember. A .json that is empty
		// right now is usually one still being written: marking it read here is
		// how a file gets acknowledged and then never ingested at all.
		return nil
	}

	sum := sha256.Sum256(data)
	if mark, seen := fi.markOf(path); seen && mark.sum == sum {
		// Already ingested these bytes. Re-record so the pre-filter matches the
		// file as it stands, since the write that closed it may have moved the
		// modification time past what was stored.
		fi.setMark(path, sum)
		return nil
	}

	if err := fi.processJSONBytes(ctx, data); err != nil {
		return err
	}
	fi.setMark(path, sum)
	// Persisted now rather than at shutdown: a process killed between the two
	// re-ingests this file on the next start, which is the defect being closed.
	fi.saveMarks()
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
	ticker := time.NewTicker(fi.opts.SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if fi.caseID != "" {
				_ = fi.store.UpdateCaseEventCount(context.Background(), fi.caseID)
			}
			fi.opts.Logger.Printf("Watch stopping: ingested=%d errors=%d", atomic.LoadInt64(&fi.ingested), atomic.LoadInt64(&fi.errors))
			return ctx.Err()
		case ev := <-w.Events:
			// Only handle writes/creates on matching files
			name := filepath.Base(ev.Name)
			if !fi.matches(name) {
				continue
			}
			lower := strings.ToLower(name)

			if (ev.Op&fsnotify.Create) != 0 || (ev.Op&fsnotify.Write) != 0 {
				if err := ingestEntryOK(ev.Name); err != nil {
					fi.opts.Logger.Printf("skipping %s: %v", ev.Name, err)
					fi.recordError(err)
					continue
				}
				switch {
				case strings.HasSuffix(lower, ".jsonl"):
					// Tail from last offset (or 0 if new file)
					fi.mu.Lock()
					offset := fi.offsets[ev.Name]
					fi.mu.Unlock()

					newOffset, err := fi.processJSONL(ctx, ev.Name, offset)
					if err != nil {
						fi.opts.Logger.Printf("error tailing %s: %v", ev.Name, err)
						fi.recordError(err)
						continue
					}
					fi.mu.Lock()
					fi.offsets[ev.Name] = newOffset
					fi.mu.Unlock()
					fi.saveOffsets()
				case strings.HasSuffix(lower, ".json"):
					// The digest decides whether this is new content. Writing a
					// file emits a creation and then a write, and treating both
					// as "re-read the whole file" ingested every dropped file
					// twice.
					if err := fi.ingestJSONFile(ctx, ev.Name); err != nil {
						fi.opts.Logger.Printf("error processing %s: %v", ev.Name, err)
						fi.recordError(err)
					}
				}
			}
			if (ev.Op&fsnotify.Remove) != 0 || (ev.Op&fsnotify.Rename) != 0 {
				fi.mu.Lock()
				delete(fi.offsets, ev.Name)
				delete(fi.marks, ev.Name)
				fi.mu.Unlock()
				fi.saveOffsets()
				fi.saveMarks()
			}
		case err := <-w.Errors:
			if err != nil {
				fi.opts.Logger.Printf("watch error: %v", err)
			}
		case <-ticker.C:
			// Re-read the directory. fsnotify is the fast path, not the only
			// one: a dropped create used to mean the file was never read at
			// all, so a pipeline posting into the drop folder was acknowledged
			// and then silently lost. Offsets and marks make this a no-op for
			// everything already ingested.
			if err := fi.scanOnce(ctx, false); err != nil {
				fi.opts.Logger.Printf("sweep of %s failed: %v", fi.opts.Dir, err)
				fi.recordError(err)
			} else {
				fi.saveOffsets()
			}
			atomic.AddInt64(&fi.sweeps, 1)
			// Periodically sync case event count (only when using a case)
			if fi.caseID != "" {
				_ = fi.store.UpdateCaseEventCount(context.Background(), fi.caseID)
			}
		}
	}
}

// persistedMark is the on-disk form of a fileMark. The digest is hex so the
// state file stays readable, and the modification time is nanoseconds since the
// epoch so it round-trips exactly rather than through a formatted string.
type persistedMark struct {
	Size int64  `json:"size"`
	Mod  int64  `json:"mod"`
	Sum  string `json:"sum"`
}

// loadMarks restores the digests of already-ingested .json payloads. A missing
// or unreadable file is not an error: the files are read and hashed again, and
// the worst case is the duplication this exists to prevent.
func (fi *FolderIngestor) loadMarks() {
	if fi.opts.MarksFile == "" {
		return
	}
	data, err := os.ReadFile(fi.opts.MarksFile)
	if err != nil {
		return
	}
	var m map[string]persistedMark
	if err := json.Unmarshal(data, &m); err != nil {
		fi.opts.Logger.Printf("ignoring corrupt ingest marks %s: %v", fi.opts.MarksFile, err)
		return
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	for k, v := range m {
		raw, err := hex.DecodeString(v.Sum)
		if err != nil || len(raw) != sha256.Size {
			continue
		}
		var sum [sha256.Size]byte
		copy(sum[:], raw)
		fi.marks[k] = fileMark{size: v.Size, modTime: time.Unix(0, v.Mod), sum: sum}
	}
}

// saveMarks atomically persists the marks. Best-effort: a failure is logged,
// not fatal, and costs a re-ingest of that file on the next start.
func (fi *FolderIngestor) saveMarks() {
	if fi.opts.MarksFile == "" {
		return
	}
	fi.mu.Lock()
	snapshot := make(map[string]persistedMark, len(fi.marks))
	for k, v := range fi.marks {
		snapshot[k] = persistedMark{Size: v.size, Mod: v.modTime.UnixNano(), Sum: hex.EncodeToString(v.sum[:])}
	}
	fi.mu.Unlock()

	data, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	tmp := fi.opts.MarksFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		fi.opts.Logger.Printf("could not persist ingest marks: %v", err)
		return
	}
	if err := os.Rename(tmp, fi.opts.MarksFile); err != nil {
		fi.opts.Logger.Printf("could not persist ingest marks: %v", err)
	}
}

// loadOffsets reads persisted per-file offsets from the state file into memory.
// A missing or unreadable file is not an error: ingestion simply starts fresh.
func (fi *FolderIngestor) loadOffsets() {
	if fi.opts.StateFile == "" {
		return
	}
	data, err := os.ReadFile(fi.opts.StateFile)
	if err != nil {
		return
	}
	var m map[string]int64
	if err := json.Unmarshal(data, &m); err != nil {
		fi.opts.Logger.Printf("ignoring corrupt ingest state %s: %v", fi.opts.StateFile, err)
		return
	}
	fi.mu.Lock()
	for k, v := range m {
		fi.offsets[k] = v
	}
	fi.mu.Unlock()
}

// saveOffsets atomically persists the current per-file offsets so a restart can
// resume without re-ingesting. Best-effort: failures are logged, not fatal.
func (fi *FolderIngestor) saveOffsets() {
	if fi.opts.StateFile == "" {
		return
	}
	fi.mu.Lock()
	snapshot := make(map[string]int64, len(fi.offsets))
	for k, v := range fi.offsets {
		snapshot[k] = v
	}
	fi.mu.Unlock()

	data, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	tmp := fi.opts.StateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		fi.opts.Logger.Printf("could not persist ingest offsets: %v", err)
		return
	}
	if err := os.Rename(tmp, fi.opts.StateFile); err != nil {
		fi.opts.Logger.Printf("could not persist ingest offsets: %v", err)
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
			fi.recordError(err)
			continue
		}
		atomic.AddInt64(&fi.ingested, 1)
	}
	if err := reader.Err(); err != nil {
		return bytesRead, err
	}
	return bytesRead, nil
}

// processJSONBytes ingests the contents of a whole-file .json: either a single
// record or an array of them.
func (fi *FolderIngestor) processJSONBytes(ctx context.Context, data []byte) error {
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
				fi.recordError(err)
				continue
			}
			atomic.AddInt64(&fi.ingested, 1)
		}
		return nil
	}

	if err := fi.processEventJSON(ctx, []byte(trim)); err != nil {
		return err
	}
	atomic.AddInt64(&fi.ingested, 1)
	return nil
}

func (fi *FolderIngestor) processEventJSON(ctx context.Context, raw []byte) error {
	rec, err := fi.parser.Parse(raw)
	if err != nil {
		return err
	}

	// There is something to put in it now, so it is worth existing.
	if fi.opts.CaseTitle != "" && fi.caseID == "" {
		if err := fi.ensureCase(ctx); err != nil {
			return err
		}
	}

	saved, err := fi.store.SaveRecord(ctx, rec)
	if err != nil {
		return err
	}

	// Assign to the ingest case when configured
	if fi.caseID != "" {
		if saved.EventID != "" {
			if err := fi.store.AssignEventToCase(ctx, saved.EventID, fi.caseID); err != nil {
				return err
			}
		}
		if saved.FindingID != "" {
			if err := fi.store.AssignFindingToCase(ctx, saved.FindingID, fi.caseID); err != nil {
				return err
			}
		}
	}

	msg := bus.EventMessage{
		EventID:   saved.EventID,
		EventType: rec.EventType(),
		RawJSON:   string(raw),
		Timestamp: rec.Timestamp(),
	}
	if msg.EventID == "" {
		msg.EventID = saved.FindingID
	}
	// Best-effort publish to bus (optional, no-op on NullBus)
	_ = fi.bus.PublishEvent(ctx, msg)
	// In-process enrichment by embedded core plugins (optional)
	if fi.opts.Enricher != nil {
		fi.opts.Enricher.EnqueueEvent(msg)
	}

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

// WatcherStatus is what the dashboard shows about folder ingestion: which
// directory is being watched, whether it is healthy, and what went wrong if not.
type WatcherStatus struct {
	Dir string
	// Watching is false for a one-shot ingest, which finishes rather than tails.
	Watching bool
	Ingested int
	Errors   int
	LastErr  string
}

// Healthy reports whether the watcher has anything to complain about.
func (s WatcherStatus) Healthy() bool { return s.Errors == 0 }

// Status returns a snapshot of the ingestor's health.
//
// Safe to call from any goroutine while ingestion is running. This is the only
// way the watcher's state leaves the ingest package; before it existed, a
// watcher that had failed on every file since startup looked identical to one
// that had nothing to do.
func (fi *FolderIngestor) Status() WatcherStatus {
	fi.mu.Lock()
	lastErr := fi.lastErr
	fi.mu.Unlock()

	return WatcherStatus{
		Dir:      fi.opts.Dir,
		Watching: fi.opts.Watch,
		Ingested: int(atomic.LoadInt64(&fi.ingested)),
		Errors:   int(atomic.LoadInt64(&fi.errors)),
		LastErr:  lastErr,
	}
}

// recordError counts a failure and remembers its message.
func (fi *FolderIngestor) recordError(err error) {
	atomic.AddInt64(&fi.errors, 1)
	if err == nil {
		return
	}
	fi.mu.Lock()
	fi.lastErr = err.Error()
	fi.mu.Unlock()
}
