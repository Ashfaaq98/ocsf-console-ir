package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID        string                 `json:"id"`
	CaseID    string                 `json:"case_id"`
	EventID   string                 `json:"event_id,omitempty"`
	Action    string                 `json:"action"`    // "create_case", "assign_event", "copilot_query", "note_added", etc.
	Actor     string                 `json:"actor"`     // user or system identifier
	Details   map[string]interface{} `json:"details"`   // action-specific data
	Metadata  map[string]string      `json:"metadata"`  // tokens, cost, etc.
	Timestamp time.Time              `json:"timestamp"`
	CreatedAt time.Time              `json:"created_at"`
}

// Note represents a case note (enhanced for sticky notes and linking)
type Note struct {
	ID         string    `json:"id"`
	CaseID     string    `json:"case_id"`
	Content    string    `json:"content"`
	Author     string    `json:"author"`
	Color      string    `json:"color,omitempty"`        // hex color e.g. "#f1c40f"
	LinkedType string    `json:"linked_type,omitempty"`  // "event", "ioc", or ""
	LinkedID   string    `json:"linked_id,omitempty"`    // event_id or ioc unique value
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SetupAuditTables creates the audit and notes tables if they don't exist
func (s *Store) SetupAuditTables() error {
	migrations := []string{
		// Audit entries table
		`CREATE TABLE IF NOT EXISTS audit_entries (
			id TEXT PRIMARY KEY,
			case_id TEXT NOT NULL,
			event_id TEXT,
			action TEXT NOT NULL,
			actor TEXT NOT NULL,
			details TEXT NOT NULL,
			metadata TEXT,
			timestamp INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
		)`,

		// Indexes for performance
		`CREATE INDEX IF NOT EXISTS idx_audit_case_id ON audit_entries(case_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action)`,
	}

	for _, migration := range migrations {
		if _, err := s.db.Exec(migration); err != nil {
			return fmt.Errorf("failed to execute audit migration: %w", err)
		}
	}

	// Handle notes table creation/migration more carefully
	if err := s.migrateNotesTable(); err != nil {
		return fmt.Errorf("failed to migrate notes table: %w", err)
	}

	return nil
}

// migrateNotesTable handles notes table creation and column migrations
func (s *Store) migrateNotesTable() error {
	// Check if notes table exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='notes'").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check notes table existence: %w", err)
	}

	if count == 0 {
		// Create new table with all columns
		createSQL := `CREATE TABLE notes (
			id TEXT PRIMARY KEY,
			case_id TEXT NOT NULL,
			content TEXT NOT NULL,
			author TEXT NOT NULL,
			color TEXT DEFAULT '#f1c40f',
			linked_type TEXT DEFAULT '',
			linked_id TEXT DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
		)`
		if _, err := s.db.Exec(createSQL); err != nil {
			return fmt.Errorf("failed to create notes table: %w", err)
		}
	} else {
		// Table exists, check and add missing columns
		columns := []struct {
			name     string
			sql      string
			defValue string
		}{
			{"color", "ALTER TABLE notes ADD COLUMN color TEXT", "#f1c40f"},
			{"linked_type", "ALTER TABLE notes ADD COLUMN linked_type TEXT", ""},
			{"linked_id", "ALTER TABLE notes ADD COLUMN linked_id TEXT", ""},
		}

		for _, col := range columns {
			// Check if column exists
			var colCount int
			checkSQL := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('notes') WHERE name='%s'", col.name)
			err := s.db.QueryRow(checkSQL).Scan(&colCount)
			if err != nil {
				return fmt.Errorf("failed to check column %s: %w", col.name, err)
			}

			if colCount == 0 {
				// Add missing column
				if _, err := s.db.Exec(col.sql); err != nil {
					return fmt.Errorf("failed to add column %s: %w", col.name, err)
				}
				// Set default values for existing rows
				if col.defValue != "" {
					updateSQL := fmt.Sprintf("UPDATE notes SET %s = ? WHERE %s IS NULL", col.name, col.name)
					if _, err := s.db.Exec(updateSQL, col.defValue); err != nil {
						return fmt.Errorf("failed to set default values for %s: %w", col.name, err)
					}
				}
			}
		}
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_notes_case_id ON notes(case_id)`,
		`CREATE INDEX IF NOT EXISTS idx_notes_created_at ON notes(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_notes_linked_type ON notes(linked_type)`,
		`CREATE INDEX IF NOT EXISTS idx_notes_linked_id ON notes(linked_id)`,
	}

	for _, idx := range indexes {
		if _, err := s.db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// AddAuditEntry adds an audit entry to the database
func (s *Store) AddAuditEntry(ctx context.Context, entry AuditEntry) error {
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("audit_%d", time.Now().UnixNano())
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	entry.CreatedAt = time.Now()

	// Serialize details and metadata
	detailsJSON, err := json.Marshal(entry.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal audit details: %w", err)
	}

	var metadataJSON []byte
	if entry.Metadata != nil {
		metadataJSON, err = json.Marshal(entry.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal audit metadata: %w", err)
		}
	}

	query := `INSERT INTO audit_entries (
		id, case_id, event_id, action, actor, details, metadata, timestamp, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		entry.ID, entry.CaseID, entry.EventID, entry.Action, entry.Actor,
		string(detailsJSON), string(metadataJSON), entry.Timestamp.Unix(), entry.CreatedAt.Unix())

	if err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}

	return nil
}

// GetAuditEntries retrieves audit entries for a case
func (s *Store) GetAuditEntries(ctx context.Context, caseID string, limit int) ([]AuditEntry, error) {
	query := `SELECT id, case_id, event_id, action, actor, details, metadata, timestamp, created_at
		FROM audit_entries WHERE case_id = ? ORDER BY timestamp DESC`
	
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.QueryContext(ctx, query, caseID)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit entries: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		var eventID, metadataJSON *string
		var detailsJSON string
		var timestamp, createdAt int64

		err := rows.Scan(&entry.ID, &entry.CaseID, &eventID, &entry.Action,
			&entry.Actor, &detailsJSON, &metadataJSON, &timestamp, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}

		entry.Timestamp = time.Unix(timestamp, 0)
		entry.CreatedAt = time.Unix(createdAt, 0)

		if eventID != nil {
			entry.EventID = *eventID
		}

		// Unmarshal details
		if err := json.Unmarshal([]byte(detailsJSON), &entry.Details); err != nil {
			// If unmarshaling fails, store as string
			entry.Details = map[string]interface{}{"raw": detailsJSON}
		}

		// Unmarshal metadata if present
		if metadataJSON != nil {
			if err := json.Unmarshal([]byte(*metadataJSON), &entry.Metadata); err != nil {
				entry.Metadata = map[string]string{"raw": *metadataJSON}
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// AddNote adds or updates a note (supports color and linking)
func (s *Store) AddNote(ctx context.Context, note Note) (string, error) {
	if note.ID == "" {
		note.ID = fmt.Sprintf("note_%d", time.Now().UnixNano())
		note.CreatedAt = time.Now()
	}
	note.UpdatedAt = time.Now()

	// Defaults
	if note.Color == "" {
		note.Color = "#f1c40f"
	}

	query := `INSERT OR REPLACE INTO notes (
		id, case_id, content, author, color, linked_type, linked_id, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		note.ID, note.CaseID, note.Content, note.Author,
		note.Color, note.LinkedType, note.LinkedID,
		note.CreatedAt.Unix(), note.UpdatedAt.Unix())

	if err != nil {
		return "", fmt.Errorf("failed to save note: %w", err)
	}

	return note.ID, nil
}

// GetNotes retrieves notes for a case (returns color and linking metadata)
func (s *Store) GetNotes(ctx context.Context, caseID string) ([]Note, error) {
	query := `SELECT id, case_id, content, author, color, linked_type, linked_id, created_at, updated_at
		FROM notes WHERE case_id = ? ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, caseID)
	if err != nil {
		return nil, fmt.Errorf("failed to query notes: %w", err)
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var note Note
		var createdAt, updatedAt int64

		err := rows.Scan(&note.ID, &note.CaseID, &note.Content, &note.Author,
			&note.Color, &note.LinkedType, &note.LinkedID, &createdAt, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan note: %w", err)
		}

		if note.Color == "" {
			note.Color = "#f1c40f"
		}
		note.CreatedAt = time.Unix(createdAt, 0)
		note.UpdatedAt = time.Unix(updatedAt, 0)
		notes = append(notes, note)
	}

	return notes, nil
}

// DeleteNote deletes a note
func (s *Store) DeleteNote(ctx context.Context, noteID string) error {
	query := `DELETE FROM notes WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, noteID)
	if err != nil {
		return fmt.Errorf("failed to delete note: %w", err)
	}
	return nil
}

// Helper functions for common audit actions

// LogCaseAction logs a case-related action
func (s *Store) LogCaseAction(ctx context.Context, caseID, action, actor string, details map[string]interface{}) error {
	return s.AddAuditEntry(ctx, AuditEntry{
		CaseID:  caseID,
		Action:  action,
		Actor:   actor,
		Details: details,
	})
}

// LogEventAction logs an event-related action
func (s *Store) LogEventAction(ctx context.Context, caseID, eventID, action, actor string, details map[string]interface{}) error {
	return s.AddAuditEntry(ctx, AuditEntry{
		CaseID:  caseID,
		EventID: eventID,
		Action:  action,
		Actor:   actor,
		Details: details,
	})
}

// LogCopilotQuery logs a Copilot query with token/cost information
func (s *Store) LogCopilotQuery(ctx context.Context, caseID, actor, query, response string, tokens int, cost float64) error {
	return s.AddAuditEntry(ctx, AuditEntry{
		CaseID: caseID,
		Action: "copilot_query",
		Actor:  actor,
		Details: map[string]interface{}{
			"query":    query,
			"response": response,
		},
		Metadata: map[string]string{
			"tokens": fmt.Sprintf("%d", tokens),
			"cost":   fmt.Sprintf("%.4f", cost),
		},
	})
}