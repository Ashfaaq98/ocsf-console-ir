package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Generated reports, kept as records rather than as files on disk.
//
// A report is a snapshot of a database that keeps moving: regenerate last
// month's in November and cases have closed, statuses have changed and findings
// have been re-triaged, so the document that went to a client cannot be
// reproduced from the data. That makes the text itself the record.
//
// Listing files in a directory instead would be a screen that lies the moment
// someone moves or deletes one. Where a report was written is remembered as a
// note; what it said is stored here.

// Report kinds.
const (
	ReportKindCase    = "case"
	ReportKindWeekly  = "weekly"
	ReportKindMonthly = "monthly"
)

// Report is one generated document.
type Report struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Title string `json:"title"`

	// CaseID is set for a case report and empty for a periodic one.
	CaseID string `json:"case_id,omitempty"`
	// PeriodStart and PeriodEnd bound a periodic report. Zero for a case.
	PeriodStart time.Time `json:"period_start,omitempty"`
	PeriodEnd   time.Time `json:"period_end,omitempty"`

	// Content is the report itself, in Markdown.
	Content string `json:"content"`
	// WrittenPath is where it was last written out, if it ever was.
	WrittenPath string `json:"written_path,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// Covers describes a report's scope in one phrase, for a list of them.
func (r Report) Covers() string {
	switch {
	case r.Kind == ReportKindCase:
		return r.Title
	case !r.PeriodStart.IsZero() && !r.PeriodEnd.IsZero():
		return r.PeriodStart.Format("2 Jan") + " – " + r.PeriodEnd.Format("2 Jan 2006")
	default:
		return r.Title
	}
}

// Size is the report's length in bytes, for a list of them.
func (r Report) Size() int { return len(r.Content) }

func (s *Store) migrateReports() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS reports (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			title TEXT NOT NULL,
			case_id TEXT,
			period_start INTEGER,
			period_end INTEGER,
			content TEXT NOT NULL,
			written_path TEXT,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_reports_case_id ON reports(case_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to create reports schema: %w", err)
		}
	}
	return nil
}

// SaveReport stores a generated report and returns its id.
//
// Every generation is kept. Two monthly reports for July are two records
// because they may say different things, and which one was sent matters.
func (s *Store) SaveReport(ctx context.Context, r Report) (string, error) {
	if strings.TrimSpace(r.Content) == "" {
		return "", fmt.Errorf("refusing to store an empty report")
	}
	if r.ID == "" {
		r.ID = "rep_" + uuid.New().String()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO reports (id, kind, title, case_id, period_start, period_end,
			content, written_path, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Kind, r.Title, nullableString(r.CaseID),
		unixOrNil(r.PeriodStart), unixOrNil(r.PeriodEnd),
		r.Content, nullableString(r.WrittenPath), r.CreatedAt.Unix())
	if err != nil {
		return "", fmt.Errorf("failed to save report: %w", err)
	}
	return r.ID, nil
}

// ListReports returns every report, newest first.
//
// Without their content: a list of thirty reports does not need thirty
// documents in memory to draw a table.
func (s *Store) ListReports(ctx context.Context) ([]Report, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, title, case_id, period_start, period_end,
			LENGTH(content), written_path, created_at
		 FROM reports ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to list reports: %w", err)
	}
	defer rows.Close()

	out := []Report{}
	for rows.Next() {
		var (
			r                    Report
			caseID, writtenPath  sql.NullString
			start, end, createdA sql.NullInt64
			size                 int
		)
		if err := rows.Scan(&r.ID, &r.Kind, &r.Title, &caseID, &start, &end,
			&size, &writtenPath, &createdA); err != nil {
			return nil, fmt.Errorf("failed to scan report: %w", err)
		}
		r.CaseID = caseID.String
		r.WrittenPath = writtenPath.String
		r.PeriodStart = timeOrZero(start)
		r.PeriodEnd = timeOrZero(end)
		r.CreatedAt = timeOrZero(createdA)
		// The list shows a size, so the field carries one without the text.
		r.Content = strings.Repeat(" ", size)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetReport returns one report, with its text.
func (s *Store) GetReport(ctx context.Context, id string) (*Report, error) {
	var (
		r                    Report
		caseID, writtenPath  sql.NullString
		start, end, createdA sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, kind, title, case_id, period_start, period_end,
			content, written_path, created_at
		 FROM reports WHERE id = ?`, id).
		Scan(&r.ID, &r.Kind, &r.Title, &caseID, &start, &end,
			&r.Content, &writtenPath, &createdA)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("report %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read report: %w", err)
	}

	r.CaseID = caseID.String
	r.WrittenPath = writtenPath.String
	r.PeriodStart = timeOrZero(start)
	r.PeriodEnd = timeOrZero(end)
	r.CreatedAt = timeOrZero(createdA)
	return &r, nil
}

// RecordReportPath remembers where a report was written out.
func (s *Store) RecordReportPath(ctx context.Context, id, path string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE reports SET written_path = ? WHERE id = ?`, nullableString(path), id)
	if err != nil {
		return fmt.Errorf("failed to record report path: %w", err)
	}
	return nil
}

// DeleteReport removes a report. The file it was written to, if any, is left
// alone: this owns the record, not the analyst's filesystem.
func (s *Store) DeleteReport(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM reports WHERE id = ?`, id); err != nil {
		return fmt.Errorf("failed to delete report: %w", err)
	}
	return nil
}

func unixOrNil(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func timeOrZero(v sql.NullInt64) time.Time {
	if !v.Valid || v.Int64 == 0 {
		return time.Time{}
	}
	return time.Unix(v.Int64, 0)
}
