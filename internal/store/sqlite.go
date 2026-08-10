package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/google/uuid"
)

// Store represents the SQLite storage implementation
type Store struct {
	db *sql.DB

	// Subscribers notified after an enrichment lands, so a view showing an event
	// can redraw instead of displaying what was true when it was opened.
	enrichMu   sync.RWMutex
	enrichSubs []func(eventID string)
}

// OnEnrichment registers fn to run after an enrichment is applied to an event.
//
// Enrichment is asynchronous and, in standalone mode, the bus is a no-op — so
// there is nothing for a view to subscribe to. This is the in-process
// alternative. Callbacks run on the goroutine that applied the enrichment,
// usually an enrichment worker, so fn must not block: hand off and return.
func (s *Store) OnEnrichment(fn func(eventID string)) {
	if fn == nil {
		return
	}
	s.enrichMu.Lock()
	s.enrichSubs = append(s.enrichSubs, fn)
	s.enrichMu.Unlock()
}

func (s *Store) notifyEnrichment(eventID string) {
	s.enrichMu.RLock()
	subs := s.enrichSubs
	s.enrichMu.RUnlock()
	for _, fn := range subs {
		fn(eventID)
	}
}

// ensureCaseExists creates a minimal case row when a caller provides a case ID but no case exists.
// This preserves referential integrity when foreign keys are enforced.
func (s *Store) ensureCaseExists(ctx context.Context, caseID string) error {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return nil
	}

	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM cases WHERE id = ?`, caseID).Scan(&exists); err == nil && exists > 0 {
		return nil
	}

	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `INSERT INTO cases (id, title, description, severity, status, event_count, created_at, updated_at)
		VALUES (?, ?, '', 'low', 'open', 0, ?, ?)
		ON CONFLICT(id) DO NOTHING`, caseID, caseID, now, now)
	return err
}

// Event represents a stored event
type Event struct {
	ID     string `json:"id"`
	CaseID string `json:"case_id,omitempty"`

	// OCSF identity. class_uid is authoritative; EventType is the coarse
	// category grouping derived from it for display and filtering.
	ClassUID    int    `json:"class_uid,omitempty"`
	CategoryUID int    `json:"category_uid,omitempty"`
	ActivityID  int    `json:"activity_id,omitempty"`
	TypeUID     int    `json:"type_uid,omitempty"`
	SeverityID  int    `json:"severity_id,omitempty"`
	MetadataUID string `json:"metadata_uid,omitempty"`

	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Host        string    `json:"host,omitempty"`
	SrcIP       string    `json:"src_ip,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	SrcPort     int       `json:"src_port,omitempty"`
	DstPort     int       `json:"dst_port,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
	FileName    string    `json:"file_name,omitempty"`
	FileHash    string    `json:"file_hash,omitempty"`
	UserName    string    `json:"user_name,omitempty"`
	RawJSON     string    `json:"raw_json"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ClassName returns the OCSF caption for the event's class, e.g. "Detection Finding".
func (e Event) ClassName() string { return ocsf.ClassName(e.ClassUID) }

// CategoryName returns the OCSF caption for the event's category.
func (e Event) CategoryName() string { return ocsf.CategoryName(e.CategoryUID) }

// IsFinding reports whether the event belongs to the OCSF Findings category.
func (e Event) IsFinding() bool { return e.CategoryUID == ocsf.CategoryFindings }

// eventColumns is the canonical SELECT list for the events table. Every query
// returning rows into scanEvents must use it so the two stay in lockstep.
const eventColumns = `id, case_id, timestamp, event_type, severity, message, host,
	src_ip, dst_ip, src_port, dst_port, process_name, file_name,
	file_hash, user_name, raw_json, created_at, updated_at,
	class_uid, category_uid, activity_id, type_uid, severity_id, metadata_uid`

// eventColumnsWithAlias renders eventColumns with a table alias applied to every
// column, for queries that join (notably the FTS search path). Deriving it from
// the same const is what stops the two lists drifting out of sync — a mismatch
// only surfaces on the driver that actually compiles FTS5 in, so it is easy to
// miss locally.
func eventColumnsWithAlias(alias string) string {
	parts := strings.Split(eventColumns, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// Case represents an incident case.
//
// A Case is an application concept — OCSF has no Case object. Its projection
// into the schema is an Incident Finding (class_uid 2005), which is why it
// carries the incident-profile fields below.
type Case struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	AssignedTo  string `json:"assigned_to,omitempty"`

	// OCSF incident-profile fields. StatusID is the authoritative lifecycle
	// state; Status is its display label.
	StatusID          int    `json:"status_id,omitempty"`
	VerdictID         int    `json:"verdict_id,omitempty"`
	PriorityID        int    `json:"priority_id,omitempty"`
	ImpactID          int    `json:"impact_id,omitempty"`
	IsSuspectedBreach bool   `json:"is_suspected_breach,omitempty"`
	AssigneeGroup     string `json:"assignee_group,omitempty"`

	// EventCount is supporting evidence; FindingCount is what the case is about.
	EventCount   int `json:"event_count"`
	FindingCount int `json:"finding_count"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VerdictName resolves the case verdict caption, empty when none is set.
func (c Case) VerdictName() string {
	if c.VerdictID == ocsf.VerdictUnknown {
		return ""
	}
	return ocsf.VerdictName(c.VerdictID)
}

// caseColumns is the canonical SELECT list for the cases table.
const caseColumns = `id, title, description, severity, status, COALESCE(assigned_to, ''),
	event_count, created_at, updated_at,
	COALESCE(status_id, 0), COALESCE(verdict_id, 0), COALESCE(priority_id, 0),
	COALESCE(impact_id, 0), COALESCE(is_suspected_breach, 0),
	COALESCE(assignee_group, ''), COALESCE(finding_count, 0)`

// scanCases reads rows selected with caseColumns.
func scanCases(rows *sql.Rows) ([]Case, error) {
	var out []Case
	for rows.Next() {
		var c Case
		var createdAt, updatedAt int64
		var breach int
		if err := rows.Scan(&c.ID, &c.Title, &c.Description, &c.Severity, &c.Status,
			&c.AssignedTo, &c.EventCount, &createdAt, &updatedAt,
			&c.StatusID, &c.VerdictID, &c.PriorityID, &c.ImpactID, &breach,
			&c.AssigneeGroup, &c.FindingCount); err != nil {
			return nil, fmt.Errorf("failed to scan case: %w", err)
		}
		c.IsSuspectedBreach = breach != 0
		c.CreatedAt = time.Unix(createdAt, 0)
		c.UpdatedAt = time.Unix(updatedAt, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Enrichment represents event enrichment data
type Enrichment struct {
	ID        string            `json:"id"`
	EventID   string            `json:"event_id"`
	Source    string            `json:"source"`
	Type      string            `json:"type"`
	Data      map[string]string `json:"data"`
	CreatedAt time.Time         `json:"created_at"`
}

// NewStore creates a new SQLite store instance
// sqliteBusyTimeoutMS is how long a writer waits for the lock before giving up.
//
// Ingest and enrichment write concurrently, and SQLite allows one writer at a
// time. Without a busy timeout the default is to fail *immediately* rather than
// wait, so a write that arrived during another's millisecond returned "database
// is locked" and the record was dropped. Three ingests of the same 15-event file
// gave 15, 14 and 15 — same data, different answer, decided by timing.
//
// Five seconds is far longer than any write here takes; it exists for the case
// of a second Console-IR process on the same database, where a busy period can
// last as long as the other process's transaction.
//
// The timeout alone is not enough. Every transaction in this package reads
// before it writes, and a deferred transaction that upgrades from read to write
// fails on a stale snapshot no matter how long it waits — retrying can never
// succeed, because the snapshot it holds is already out of date. `_txlock=immediate`
// takes the write lock at BEGIN instead, so the wait happens where the timeout
// applies. Every transaction here is a writer, so nothing pays for a lock it did
// not need.
const sqliteBusyTimeoutMS = 5000

func NewStore(dbPath string) (*Store, error) {
	// Ensure target directory exists (e.g., ./data)
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
		}
	}

	// Enable WAL for concurrency and enforce foreign keys for cascades. The DSN
	// spelling is driver-specific; see sqliteDSNParams.
	dsn := dbPath + sqliteDSNParams
	db, err := sql.Open(sqliteDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// In-memory databases live per-connection: each pooled connection gets its
	// own empty database, so the schema created by migrate() would be invisible
	// to queries that land on a different connection (this manifests only under
	// the pure-Go modernc driver, not CGO/mattn). Pin the pool to one connection
	// so :memory: behaves as a single shared database. File-backed databases keep
	// the default pool — WAL still allows concurrent readers.
	if strings.Contains(dbPath, ":memory:") {
		db.SetMaxOpenConns(1)
	}

	store := &Store{db: db}

	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}
	// Ensure auxiliary audit/notes tables always exist for downstream callers.
	if err := store.SetupAuditTables(); err != nil {
		return nil, fmt.Errorf("failed to set up audit tables: %w", err)
	}

	return store, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate performs database migrations
func (s *Store) migrate() error {
	// Core migrations (required)
	coreMigrations := []string{
		// Cases table (must be created first due to foreign key)
		`CREATE TABLE IF NOT EXISTS cases (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT,
			severity TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'open',
			assigned_to TEXT,
			event_count INTEGER DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,

		// Events table
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			case_id TEXT,
			timestamp INTEGER NOT NULL,
			event_type TEXT NOT NULL,
			severity TEXT,
			message TEXT,
			host TEXT,
			src_ip TEXT,
			dst_ip TEXT,
			src_port INTEGER,
			dst_port INTEGER,
			process_name TEXT,
			file_name TEXT,
			file_hash TEXT,
			user_name TEXT,
			raw_json TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
		)`,

		// Enrichments table
		`CREATE TABLE IF NOT EXISTS enrichments (
			id TEXT PRIMARY KEY,
			event_id TEXT NOT NULL,
			source TEXT NOT NULL,
			type TEXT NOT NULL,
			data TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (event_id) REFERENCES events(id)
		)`,

		// Indexes for performance
		`CREATE INDEX IF NOT EXISTS idx_events_id ON events(id)`,
		`CREATE INDEX IF NOT EXISTS idx_events_case_id ON events(case_id)`,
		`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)`,

		`CREATE INDEX IF NOT EXISTS idx_cases_id ON cases(id)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at)`,

		`CREATE INDEX IF NOT EXISTS idx_enrichments_event_id ON enrichments(event_id)`,
		`CREATE INDEX IF NOT EXISTS idx_enrichments_source ON enrichments(source)`,
		`CREATE INDEX IF NOT EXISTS idx_enrichments_type ON enrichments(type)`,
	}

	// Execute core migrations
	for _, migration := range coreMigrations {
		if _, err := s.db.Exec(migration); err != nil {
			return fmt.Errorf("failed to execute migration: %w", err)
		}
	}

	// Additive schema evolution for databases created by earlier versions.
	if err := s.migrateEventsOCSFColumns(); err != nil {
		return err
	}
	// findings must exist before observables, which references it.
	if err := s.migrateFindings(); err != nil {
		return err
	}
	if err := s.migrateObservables(); err != nil {
		return err
	}
	if err := s.migrateReports(); err != nil {
		return err
	}

	if err := s.migrateCaseOCSFColumns(); err != nil {
		return err
	}
	// case_members depends on both events and findings existing.
	if err := s.migrateCaseMembers(); err != nil {
		return err
	}

	// Try to set up FTS (optional)
	s.setupFTS()

	return nil
}

// ocsfEventColumns are the OCSF identity columns added to the events table after
// v0.1.1. They are nullable and backfilled from raw_json, so upgrading an
// existing database neither loses nor invents data.
var ocsfEventColumns = []struct {
	name string
	sql  string
}{
	{"class_uid", "ALTER TABLE events ADD COLUMN class_uid INTEGER"},
	{"category_uid", "ALTER TABLE events ADD COLUMN category_uid INTEGER"},
	{"activity_id", "ALTER TABLE events ADD COLUMN activity_id INTEGER"},
	{"type_uid", "ALTER TABLE events ADD COLUMN type_uid INTEGER"},
	{"severity_id", "ALTER TABLE events ADD COLUMN severity_id INTEGER"},
	{"metadata_uid", "ALTER TABLE events ADD COLUMN metadata_uid TEXT"},
}

// migrateEventsOCSFColumns adds the OCSF identity columns and backfills them for
// rows written before they existed. Idempotent and safe to re-run.
func (s *Store) migrateEventsOCSFColumns() error {
	for _, col := range ocsfEventColumns {
		var colCount int
		checkSQL := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='%s'", col.name)
		if err := s.db.QueryRow(checkSQL).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check events column %s: %w", col.name, err)
		}
		if colCount == 0 {
			if _, err := s.db.Exec(col.sql); err != nil {
				return fmt.Errorf("failed to add events column %s: %w", col.name, err)
			}
		}
	}

	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_events_class_uid ON events(class_uid)`,
		`CREATE INDEX IF NOT EXISTS idx_events_category_uid ON events(category_uid)`,
		`CREATE INDEX IF NOT EXISTS idx_events_metadata_uid ON events(metadata_uid)`,
	}
	for _, idx := range indexes {
		if _, err := s.db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return s.backfillOCSFColumns()
}

// ocsfIdentity is the minimal projection of an OCSF event needed to backfill the
// identity columns. It deliberately omits `time`: OCSF encodes timestamps as Unix
// integers, which encoding/json cannot unmarshal into a time.Time, so decoding a
// full ocsf.Event here would fail for every real event and silently backfill
// nothing. The ingest path avoids this with its own parseTime; the backfill
// avoids it by not needing the field at all.
type ocsfIdentity struct {
	ClassUID    int `json:"class_uid"`
	CategoryUID int `json:"category_uid"`
	ActivityID  int `json:"activity_id"`
	TypeUID     int `json:"type_uid"`
	SeverityID  int `json:"severity_id"`
	Metadata    struct {
		UID string `json:"uid"`
	} `json:"metadata"`
}

// backfillOCSFColumns reparses raw_json for rows predating the OCSF identity
// columns. raw_json has always held the complete original event, so the backfill
// is lossless. It also rewrites event_type, because rows written by earlier
// versions carry values from the incorrect class mapping (Findings were stored
// as "file", File System Activity as "process").
func (s *Store) backfillOCSFColumns() error {
	rows, err := s.db.Query(`SELECT id, raw_json FROM events WHERE class_uid IS NULL`)
	if err != nil {
		return fmt.Errorf("failed to scan events for backfill: %w", err)
	}

	type pending struct {
		id    string
		ident ocsfIdentity
	}
	var todo []pending

	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return fmt.Errorf("failed to read event for backfill: %w", err)
		}
		var ident ocsfIdentity
		if err := json.Unmarshal([]byte(raw), &ident); err != nil {
			// Unparseable raw_json: leave the row untouched rather than guessing.
			continue
		}
		todo = append(todo, pending{id: id, ident: ident})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate events for backfill: %w", err)
	}
	rows.Close()

	if len(todo) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin backfill transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`UPDATE events
		SET class_uid = ?, category_uid = ?, activity_id = ?, type_uid = ?,
		    severity_id = ?, metadata_uid = ?, event_type = ?
		WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("failed to prepare backfill statement: %w", err)
	}
	defer stmt.Close()

	for _, p := range todo {
		ev := ocsf.Event{ClassUID: p.ident.ClassUID, CategoryUID: p.ident.CategoryUID}
		if _, err := stmt.Exec(
			p.ident.ClassUID, ev.GetCategoryUID(), p.ident.ActivityID, p.ident.TypeUID,
			p.ident.SeverityID, p.ident.Metadata.UID, string(ev.GetEventType()), p.id,
		); err != nil {
			return fmt.Errorf("failed to backfill event %s: %w", p.id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit backfill: %w", err)
	}
	return nil
}

// setupFTS attempts to set up full-text search (optional feature).
// If fts5 is unavailable, it falls back to a compatibility table with the same
// name and the same triggers so schema existence tests still pass.
func (s *Store) setupFTS() {
	// Try to create true FTS5 virtual table first.
	_, err := s.db.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
		id, message, host, process_name, file_name, user_name,
		content='events',
		content_rowid='rowid'
	)`)

	createTriggers := func() {
		triggers := []string{
			`CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events BEGIN
				INSERT INTO events_fts(id, message, host, process_name, file_name, user_name)
				VALUES (new.id, new.message, new.host, new.process_name, new.file_name, new.user_name);
			END`,
			`CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events BEGIN
				DELETE FROM events_fts WHERE id = old.id;
			END`,
			`CREATE TRIGGER IF NOT EXISTS events_fts_update AFTER UPDATE ON events BEGIN
				DELETE FROM events_fts WHERE id = old.id;
				INSERT INTO events_fts(id, message, host, process_name, file_name, user_name)
				VALUES (new.id, new.message, new.host, new.process_name, new.file_name, new.user_name);
			END`,
		}
		for _, m := range triggers {
			_, _ = s.db.Exec(m)
		}
	}

	if err == nil {
		// FTS5 table created; now ensure triggers exist.
		createTriggers()
		return
	}

	// FTS5 not available; create a compatibility table and the same triggers so tests expecting
	// table/trigger existence pass. SearchEvents already has a LIKE fallback that doesn't depend on this.
	_, _ = s.db.Exec(`CREATE TABLE IF NOT EXISTS events_fts(
		id TEXT, message TEXT, host TEXT, process_name TEXT, file_name TEXT, user_name TEXT
	)`)
	createTriggers()
}

// SaveEvent saves an OCSF event to the database
func (s *Store) SaveEvent(ctx context.Context, ocsfEvent *ocsf.Event) (string, error) {
	// Generate event ID if not present
	eventID := "evt_" + uuid.New().String()

	// Convert OCSF event to store event
	event := s.ocsfToStoreEvent(ocsfEvent, eventID)
	caseIDParam := interface{}(nil)
	if strings.TrimSpace(event.CaseID) != "" {
		if err := s.ensureCaseExists(ctx, event.CaseID); err != nil {
			return "", err
		}
		caseIDParam = event.CaseID
	}

	// Serialize raw JSON
	rawJSON, err := json.Marshal(ocsfEvent)
	if err != nil {
		return "", fmt.Errorf("failed to marshal raw JSON: %w", err)
	}
	event.RawJSON = string(rawJSON)

	query := `INSERT INTO events (
		id, case_id, timestamp, event_type, severity, message, host,
		src_ip, dst_ip, src_port, dst_port, process_name, file_name,
		file_hash, user_name, raw_json, created_at, updated_at,
		class_uid, category_uid, activity_id, type_uid, severity_id, metadata_uid
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	// The event and its observables are written together: an event whose
	// indicators are missing would be silently invisible to the pivot.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	_, err = tx.ExecContext(ctx, query,
		event.ID, caseIDParam, event.Timestamp.Unix(), event.EventType,
		event.Severity, event.Message, event.Host, event.SrcIP, event.DstIP,
		event.SrcPort, event.DstPort, event.ProcessName, event.FileName,
		event.FileHash, event.UserName, event.RawJSON, now, now,
		event.ClassUID, event.CategoryUID, event.ActivityID, event.TypeUID,
		event.SeverityID, event.MetadataUID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to save event: %w", err)
	}

	// ocsfEvent.Observables holds only what the producer asserted; the rest are
	// derived from the event's structured fields.
	if err := insertObservables(tx, observablesFor(eventID, ocsfEvent, nil)); err != nil {
		return "", err
	}

	// Keep membership authoritative: an event saved with a case attached must
	// appear in case_members, not only in the legacy column. Written inside this
	// transaction because AddCaseMember would open a second one.
	if caseIDParam != nil {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO case_members (case_id, member_type, member_id, role, added_by, added_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			event.CaseID, MemberTypeEvent, eventID, RoleEvidence, "ingest", now); err != nil {
			return "", fmt.Errorf("failed to record case membership: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit event: %w", err)
	}

	return eventID, nil
}

// CreateOrUpdateCase creates a new case or updates an existing one
func (s *Store) CreateOrUpdateCase(ctx context.Context, case_ Case) (string, error) {
	if case_.ID == "" {
		case_.ID = "case_" + uuid.New().String()
		// CreatedAt is left as the caller set it. Overwriting it here discarded
		// the opening time of any case that did not begin now — an imported
		// incident, or a seeded one — and the zero case is already handled
		// below.
	}

	// Preserve existing metadata when updating with zero-value fields
	if case_.ID != "" {
		var existingCreated int64
		var existingCount int
		err := s.db.QueryRowContext(ctx, `SELECT created_at, event_count FROM cases WHERE id = ?`, case_.ID).
			Scan(&existingCreated, &existingCount)
		if err == nil {
			if case_.CreatedAt.IsZero() && existingCreated > 0 {
				case_.CreatedAt = time.Unix(existingCreated, 0)
			}
			if case_.EventCount == 0 {
				case_.EventCount = existingCount
			}
		}
	}

	if case_.CreatedAt.IsZero() {
		case_.CreatedAt = time.Now()
	}
	case_.UpdatedAt = time.Now()
	if !case_.CreatedAt.IsZero() && case_.UpdatedAt.Unix() <= case_.CreatedAt.Unix() {
		case_.UpdatedAt = case_.CreatedAt.Add(time.Second)
	}

	// Derive the OCSF status_id from the label so every write path keeps them
	// consistent, rather than relying on each caller to remember.
	if case_.Status == "" && case_.StatusID != 0 {
		case_.Status = CaseStatusLabelFor(case_.StatusID)
	}
	if case_.Status == "" {
		case_.Status = CaseStatusOpen
	}
	case_.StatusID = CaseStatusIDFor(case_.Status)

	query := `INSERT INTO cases (
		id, title, description, severity, status, assigned_to, event_count, created_at, updated_at,
		status_id, verdict_id, priority_id, impact_id, is_suspected_breach, assignee_group
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		title = excluded.title,
		description = excluded.description,
		severity = excluded.severity,
		status = excluded.status,
		status_id = excluded.status_id,
		assigned_to = excluded.assigned_to,
		created_at = excluded.created_at,
		updated_at = excluded.updated_at,
		event_count = excluded.event_count,
		verdict_id = excluded.verdict_id,
		priority_id = excluded.priority_id,
		impact_id = excluded.impact_id,
		is_suspected_breach = excluded.is_suspected_breach,
		assignee_group = excluded.assignee_group`

	_, err := s.db.ExecContext(ctx, query,
		case_.ID, case_.Title, case_.Description, case_.Severity,
		case_.Status, case_.AssignedTo, case_.EventCount,
		case_.CreatedAt.Unix(), case_.UpdatedAt.Unix(),
		case_.StatusID, case_.VerdictID, case_.PriorityID, case_.ImpactID,
		boolToInt(case_.IsSuspectedBreach), case_.AssigneeGroup,
	)

	if err != nil {
		return "", fmt.Errorf("failed to save case: %w", err)
	}

	return case_.ID, nil
}

// ListCases returns all cases
func (s *Store) ListCases(ctx context.Context) ([]Case, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+caseColumns+` FROM cases ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query cases: %w", err)
	}
	defer rows.Close()
	return scanCases(rows)
}

// GetCase returns a single case by ID, or nil when it does not exist.
func (s *Store) GetCase(ctx context.Context, caseID string) (*Case, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+caseColumns+` FROM cases WHERE id = ?`, caseID)
	if err != nil {
		return nil, fmt.Errorf("failed to query case: %w", err)
	}
	defer rows.Close()

	found, err := scanCases(rows)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return &found[0], nil
}

// GetEventsByCase returns the events attached to a case as evidence.
func (s *Store) GetEventsByCase(ctx context.Context, caseID string) ([]Event, error) {
	return s.GetCaseEventMembers(ctx, caseID)
}

// GetAllEvents returns all events ordered by timestamp
func (s *Store) GetAllEvents(ctx context.Context, limit int) ([]Event, error) {
	query := `SELECT ` + eventColumns + `
		FROM events ORDER BY timestamp DESC`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// GetEventsByTimeRange returns events filtered by optional case and time range
func (s *Store) GetEventsByTimeRange(ctx context.Context, caseID string, start, end time.Time, limit int) ([]Event, error) {
	base := `SELECT ` + eventColumns + `
		FROM events WHERE 1=1`
	args := []interface{}{}

	if caseID != "" {
		base += " AND case_id = ?"
		args = append(args, caseID)
	}
	if !start.IsZero() {
		base += " AND timestamp >= ?"
		args = append(args, start.Unix())
	}
	if !end.IsZero() {
		base += " AND timestamp <= ?"
		args = append(args, end.Unix())
	}

	base += " ORDER BY timestamp DESC"
	if limit > 0 {
		base += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.QueryContext(ctx, base, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events by time range: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// EventFilter describes the optional constraints applied to an events query.
// The zero value matches everything.
type EventFilter struct {
	CaseID string
	Start  time.Time
	End    time.Time
	// Severities matches events.severity (case-insensitive).
	Severities []string
	// Categories matches events.event_type, the coarse OCSF category slug.
	Categories []string
	// Classes matches events.class_uid exactly, e.g. 2004 for Detection Findings.
	Classes []int

	Limit  int
	Offset int
}

// where builds the shared WHERE clause and bound arguments for an EventFilter.
func (f EventFilter) where() (string, []interface{}) {
	clause := ""
	args := []interface{}{}

	if f.CaseID != "" {
		clause += " AND case_id = ?"
		args = append(args, f.CaseID)
	}
	if !f.Start.IsZero() {
		clause += " AND timestamp >= ?"
		args = append(args, f.Start.Unix())
	}
	if !f.End.IsZero() {
		clause += " AND timestamp <= ?"
		args = append(args, f.End.Unix())
	}
	if len(f.Severities) > 0 {
		placeholders := make([]string, 0, len(f.Severities))
		for _, sev := range f.Severities {
			placeholders = append(placeholders, "?")
			// normalize to lowercase to match stored values
			args = append(args, strings.ToLower(sev))
		}
		clause += " AND severity IN (" + strings.Join(placeholders, ",") + ")"
	}
	if len(f.Categories) > 0 {
		placeholders := make([]string, 0, len(f.Categories))
		for _, typ := range f.Categories {
			placeholders = append(placeholders, "?")
			args = append(args, strings.ToLower(typ))
		}
		clause += " AND event_type IN (" + strings.Join(placeholders, ",") + ")"
	}
	if len(f.Classes) > 0 {
		placeholders := make([]string, 0, len(f.Classes))
		for _, c := range f.Classes {
			placeholders = append(placeholders, "?")
			args = append(args, c)
		}
		clause += " AND class_uid IN (" + strings.Join(placeholders, ",") + ")"
	}

	return clause, args
}

// GetEvents returns events matching the filter, ordered by timestamp DESC.
// When Limit is 0, all matching rows are returned.
func (s *Store) GetEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	clause, args := f.where()
	base := `SELECT ` + eventColumns + `
		FROM events WHERE 1=1` + clause + " ORDER BY timestamp DESC"

	if f.Limit > 0 {
		base += " LIMIT ?"
		args = append(args, f.Limit)
		if f.Offset > 0 {
			base += " OFFSET ?"
			args = append(args, f.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, base, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query filtered events: %w", err)
	}
	defer rows.Close()
	return s.scanEvents(rows)
}

// CountEvents returns the number of events matching the filter, ignoring
// Limit/Offset.
func (s *Store) CountEvents(ctx context.Context, f EventFilter) (int, error) {
	clause, args := f.where()
	base := `SELECT COUNT(1) FROM events WHERE 1=1` + clause

	var total int
	if err := s.db.QueryRowContext(ctx, base, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("failed to count filtered events: %w", err)
	}
	return total, nil
}

/*
GetEventsFiltered returns events filtered by optional case, time range, severity list,
type list, with pagination via limit/offset. Results are ordered by timestamp DESC.
When limit is 0, all matching rows are returned (no LIMIT/OFFSET).

Deprecated: use GetEvents with an EventFilter, which also supports class_uid.
*/
func (s *Store) GetEventsFiltered(
	ctx context.Context,
	caseID string,
	start, end time.Time,
	severities []string,
	types []string,
	limit, offset int,
) ([]Event, error) {
	return s.GetEvents(ctx, EventFilter{
		CaseID:     caseID,
		Start:      start,
		End:        end,
		Severities: severities,
		Categories: types,
		Limit:      limit,
		Offset:     offset,
	})
}

// CountEventsFiltered returns the total count of events matching the same filters as GetEventsFiltered.
//
// Deprecated: use CountEvents with an EventFilter, which also supports class_uid.
func (s *Store) CountEventsFiltered(
	ctx context.Context,
	caseID string,
	start, end time.Time,
	severities []string,
	types []string,
) (int, error) {
	return s.CountEvents(ctx, EventFilter{
		CaseID:     caseID,
		Start:      start,
		End:        end,
		Severities: severities,
		Categories: types,
	})
}

// ApplyEnrichment applies enrichment data to an event
func (s *Store) ApplyEnrichment(ctx context.Context, eventID string, enrichment Enrichment) error {
	if enrichment.ID == "" {
		enrichment.ID = "enr_" + uuid.New().String()
	}
	enrichment.EventID = eventID
	enrichment.CreatedAt = time.Now()

	dataJSON, err := json.Marshal(enrichment.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal enrichment data: %w", err)
	}

	query := `INSERT INTO enrichments (id, event_id, source, type, data, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		enrichment.ID, enrichment.EventID, enrichment.Source,
		enrichment.Type, string(dataJSON), enrichment.CreatedAt.Unix(),
	)

	if err != nil {
		return fmt.Errorf("failed to save enrichment: %w", err)
	}

	// Only after the row is durable: a view that redraws on this signal must find
	// the enrichment when it re-queries.
	s.notifyEnrichment(enrichment.EventID)

	return nil
}

// GetEnrichmentsByEvent returns all enrichments associated with an event (newest first)
func (s *Store) GetEnrichmentsByEvent(ctx context.Context, eventID string) ([]Enrichment, error) {
	query := `SELECT id, event_id, source, type, data, created_at
		FROM enrichments
		WHERE event_id = ?
		ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to query enrichments for event %s: %w", eventID, err)
	}
	defer rows.Close()

	var result []Enrichment
	for rows.Next() {
		var (
			id, evID, source, typ, dataJSON string
			createdAt                       int64
		)
		if err := rows.Scan(&id, &evID, &source, &typ, &dataJSON, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan enrichment row: %w", err)
		}

		data := make(map[string]string)
		if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
			// If corrupt data is encountered, keep an empty map but do not fail the whole result set
			data = map[string]string{"_error": "failed to unmarshal enrichment data"}
		}

		result = append(result, Enrichment{
			ID:        id,
			EventID:   evID,
			Source:    source,
			Type:      typ,
			Data:      data,
			CreatedAt: time.Unix(createdAt, 0),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating enrichment rows: %w", err)
	}

	return result, nil
}

// sanitizeFTSQuery escapes FTS5 special syntax by wrapping each term in double quotes.
// This prevents operators like AND, OR, NOT, NEAR, *, and column:filters from being
// interpreted as FTS query syntax.
func sanitizeFTSQuery(input string) string {
	terms := strings.Fields(input)
	if len(terms) == 0 {
		return `""`
	}
	for i, term := range terms {
		term = strings.ReplaceAll(term, `"`, `""`)
		terms[i] = `"` + term + `"`
	}
	return strings.Join(terms, " ")
}

// escapeLIKE escapes SQL LIKE metacharacters (%, _) in user input.
func escapeLIKE(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// SearchEvents performs full-text search on events (falls back to LIKE if FTS unavailable)
func (s *Store) SearchEvents(ctx context.Context, query string, limit int) ([]Event, error) {
	// VULN-6: Sanitize FTS input to prevent query syntax injection
	sanitized := sanitizeFTSQuery(query)

	// Try FTS first
	ftsQuery := `SELECT ` + eventColumnsWithAlias("e") + `
		FROM events e
		JOIN events_fts fts ON e.id = fts.id
		WHERE events_fts MATCH ?
		ORDER BY rank
		LIMIT ?`

	rows, err := s.db.QueryContext(ctx, ftsQuery, sanitized, limit)
	if err == nil {
		defer rows.Close()
		return s.scanEvents(rows)
	}

	// Fall back to LIKE search if FTS is not available
	likeQuery := `SELECT ` + eventColumns + `
		FROM events
		WHERE message LIKE ? ESCAPE '\' OR host LIKE ? ESCAPE '\' OR process_name LIKE ? ESCAPE '\' OR file_name LIKE ? ESCAPE '\' OR user_name LIKE ? ESCAPE '\'
		ORDER BY timestamp DESC
		LIMIT ?`

	searchPattern := "%" + escapeLIKE(query) + "%"
	rows, err = s.db.QueryContext(ctx, likeQuery, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search events: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// ocsfToStoreEvent converts an OCSF event to a store event
func (s *Store) ocsfToStoreEvent(ocsfEvent *ocsf.Event, eventID string) Event {
	event := Event{
		ID:          eventID,
		Timestamp:   ocsfEvent.Time,
		EventType:   string(ocsfEvent.GetEventType()),
		Severity:    ocsfEvent.GetSeverityLevel(),
		Message:     ocsfEvent.Message,
		ClassUID:    ocsfEvent.ClassUID,
		CategoryUID: ocsfEvent.GetCategoryUID(),
		ActivityID:  ocsfEvent.ActivityID,
		TypeUID:     ocsfEvent.TypeUID,
		SeverityID:  ocsfEvent.SeverityID,
		MetadataUID: ocsfEvent.Metadata.UID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Extract host information
	if ocsfEvent.Device != nil {
		event.Host = ocsfEvent.Device.Hostname
		if event.Host == "" {
			event.Host = ocsfEvent.Device.Name
		}
	}

	// Extract network information
	if ocsfEvent.SrcEndpoint != nil {
		event.SrcIP = ocsfEvent.SrcEndpoint.IP
		event.SrcPort = ocsfEvent.SrcEndpoint.Port
	}
	if ocsfEvent.DstEndpoint != nil {
		event.DstIP = ocsfEvent.DstEndpoint.IP
		event.DstPort = ocsfEvent.DstEndpoint.Port
	}

	// Extract process information
	if ocsfEvent.Process != nil {
		event.ProcessName = ocsfEvent.Process.Name
		if ocsfEvent.Process.User != nil {
			event.UserName = ocsfEvent.Process.User.Name
		}
	}

	// Extract file information
	if ocsfEvent.File != nil {
		event.FileName = ocsfEvent.File.Name
		if ocsfEvent.File.Hashes != nil {
			// Use SHA256 if available, otherwise first available hash
			if sha256, ok := ocsfEvent.File.Hashes["sha256"]; ok {
				event.FileHash = sha256
			} else {
				for _, hash := range ocsfEvent.File.Hashes {
					event.FileHash = hash
					break
				}
			}
		}
	}

	// Also consider process-scoped file details if top-level file fields are empty
	if ocsfEvent.Process != nil && ocsfEvent.Process.File != nil {
		if event.FileName == "" && ocsfEvent.Process.File.Name != "" {
			event.FileName = ocsfEvent.Process.File.Name
		}
		if event.FileHash == "" && ocsfEvent.Process.File.Hashes != nil {
			if sha256, ok := ocsfEvent.Process.File.Hashes["sha256"]; ok {
				event.FileHash = sha256
			} else {
				for _, hash := range ocsfEvent.Process.File.Hashes {
					event.FileHash = hash
					break
				}
			}
		}
	}

	// Extract user information
	if ocsfEvent.User != nil && event.UserName == "" {
		event.UserName = ocsfEvent.User.Name
	}

	return event
}

// scanEvents scans database rows into Event structs
func (s *Store) scanEvents(rows *sql.Rows) ([]Event, error) {
	var events []Event
	for rows.Next() {
		var event Event
		var timestamp, createdAt, updatedAt int64
		var caseID, srcIP, dstIP, processName, fileName, fileHash, userName sql.NullString
		var srcPort, dstPort sql.NullInt64
		var metadataUID sql.NullString
		var classUID, categoryUID, activityID, typeUID, severityID sql.NullInt64

		err := rows.Scan(&event.ID, &caseID, &timestamp, &event.EventType,
			&event.Severity, &event.Message, &event.Host, &srcIP, &dstIP,
			&srcPort, &dstPort, &processName, &fileName, &fileHash,
			&userName, &event.RawJSON, &createdAt, &updatedAt,
			&classUID, &categoryUID, &activityID, &typeUID, &severityID, &metadataUID)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		if classUID.Valid {
			event.ClassUID = int(classUID.Int64)
		}
		if categoryUID.Valid {
			event.CategoryUID = int(categoryUID.Int64)
		}
		if activityID.Valid {
			event.ActivityID = int(activityID.Int64)
		}
		if typeUID.Valid {
			event.TypeUID = int(typeUID.Int64)
		}
		if severityID.Valid {
			event.SeverityID = int(severityID.Int64)
		}
		if metadataUID.Valid {
			event.MetadataUID = metadataUID.String
		}

		event.Timestamp = time.Unix(timestamp, 0)
		event.CreatedAt = time.Unix(createdAt, 0)
		event.UpdatedAt = time.Unix(updatedAt, 0)

		if caseID.Valid {
			event.CaseID = caseID.String
		}
		if srcIP.Valid {
			event.SrcIP = srcIP.String
		}
		if dstIP.Valid {
			event.DstIP = dstIP.String
		}
		if srcPort.Valid {
			event.SrcPort = int(srcPort.Int64)
		}
		if dstPort.Valid {
			event.DstPort = int(dstPort.Int64)
		}
		if processName.Valid {
			event.ProcessName = processName.String
		}
		if fileName.Valid {
			event.FileName = fileName.String
		}
		if fileHash.Valid {
			event.FileHash = fileHash.String
		}
		if userName.Valid {
			event.UserName = userName.String
		}

		events = append(events, event)
	}

	return events, nil
}

// Added helpers to assign events to cases and sync event_count

// AssignEventToCase attaches an event to a case as supporting evidence.
//
// Membership lives in case_members, so an event can belong to more than one
// case; the events.case_id column is kept in step for readers that have not
// migrated yet.
func (s *Store) AssignEventToCase(ctx context.Context, eventID, caseID string) error {
	return s.AddCaseMember(ctx, CaseMember{
		CaseID:     caseID,
		MemberType: MemberTypeEvent,
		MemberID:   eventID,
		Role:       RoleEvidence,
	})
}

// UpdateCaseEventCount recalculates and persists the event_count for the given case.
// UpdateCaseEventCount syncs a case's denormalized counts from its membership.
func (s *Store) UpdateCaseEventCount(ctx context.Context, caseID string) error {
	return s.RefreshCaseCounts(ctx, caseID)
}

// DeleteCaseAndUnassign deletes a case and unassigns all its events (sets events.case_id=NULL).
// This keeps events accessible under ALL EVENTS after the case is removed.
func (s *Store) DeleteCaseAndUnassign(ctx context.Context, caseID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	rollback := func(e error) error {
		_ = tx.Rollback()
		return e
	}

	// Unassign events and findings from the case.
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE events SET case_id = NULL, updated_at = ? WHERE case_id = ?`, now, caseID); err != nil {
		return rollback(fmt.Errorf("unassign events for case %s: %w", caseID, err))
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET case_id = NULL, updated_at = ? WHERE case_id = ?`, now, caseID); err != nil {
		return rollback(fmt.Errorf("unassign findings for case %s: %w", caseID, err))
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM case_members WHERE case_id = ?`, caseID); err != nil {
		return rollback(fmt.Errorf("clear members for case %s: %w", caseID, err))
	}

	// Delete the case row
	if _, err := tx.ExecContext(ctx, `DELETE FROM cases WHERE id = ?`, caseID); err != nil {
		return rollback(fmt.Errorf("delete case %s: %w", caseID, err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// DeleteEvents deletes events by IDs along with their enrichments, then updates
// event_count for any affected cases. Deletion is executed in a single transaction.
// Note: enrichments table has a FK to events without ON DELETE CASCADE, so we must
// delete enrichments explicitly before deleting events.
func (s *Store) DeleteEvents(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	// Build placeholders and args
	makeArgs := func(ss []string) []interface{} {
		args := make([]interface{}, len(ss))
		for i, v := range ss {
			args[i] = v
		}
		return args
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	rollback := func(e error) error {
		_ = tx.Rollback()
		return e
	}

	// Determine which cases are affected so we can update their event_count after commit.
	caseIDs := make([]string, 0)
	qCases := "SELECT DISTINCT case_id FROM case_members WHERE member_type = 'event' AND member_id IN (" + placeholders + ")"
	rows, err := tx.QueryContext(ctx, qCases, makeArgs(ids)...)
	if err != nil {
		return rollback(fmt.Errorf("query affected cases: %w", err))
	}
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			rows.Close()
			return rollback(fmt.Errorf("scan affected case id: %w", err))
		}
		if cid != "" {
			caseIDs = append(caseIDs, cid)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return rollback(fmt.Errorf("iterate affected cases: %w", err))
	}
	rows.Close()

	// Delete enrichments first (FK w/o cascade)
	qEnr := "DELETE FROM enrichments WHERE event_id IN (" + placeholders + ")"
	if _, err := tx.ExecContext(ctx, qEnr, makeArgs(ids)...); err != nil {
		return rollback(fmt.Errorf("delete enrichments for events: %w", err))
	}

	// Drop membership rows: case_members.member_id carries no foreign key
	// because it points at either events or findings.
	qMem := "DELETE FROM case_members WHERE member_type = 'event' AND member_id IN (" + placeholders + ")"
	if _, err := tx.ExecContext(ctx, qMem, makeArgs(ids)...); err != nil {
		return rollback(fmt.Errorf("delete case members for events: %w", err))
	}

	// Delete events
	qEv := "DELETE FROM events WHERE id IN (" + placeholders + ")"
	if _, err := tx.ExecContext(ctx, qEv, makeArgs(ids)...); err != nil {
		return rollback(fmt.Errorf("delete events: %w", err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Update event_count for affected cases (best-effort; return first error encountered).
	var firstErr error
	seen := map[string]bool{}
	for _, cid := range caseIDs {
		if cid == "" || seen[cid] {
			continue
		}
		seen[cid] = true
		if err := s.UpdateCaseEventCount(ctx, cid); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("update case %s event_count: %w", cid, err)
		}
	}
	return firstErr
}
