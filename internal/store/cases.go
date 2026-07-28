package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/google/uuid"
)

// Case status labels. These are what the UI shows and what the status column
// stores; status_id is the OCSF Incident Finding status the case projects onto.
//
// "contained" is not an OCSF status — it maps onto On Hold, which is the closest
// OCSF equivalent for "action taken, not yet finished". "resolved" is new: OCSF
// distinguishes Resolved (dealt with) from Closed (filed away), and the app
// previously had no way to say the former.
const (
	CaseStatusOpen          = "open"
	CaseStatusInvestigating = "investigating"
	CaseStatusContained     = "contained"
	CaseStatusResolved      = "resolved"
	CaseStatusClosed        = "closed"
)

// caseStatusToID maps the app's status labels onto OCSF incident status_id.
var caseStatusToID = map[string]int{
	CaseStatusOpen:          ocsf.IncidentStatusNew,
	CaseStatusInvestigating: ocsf.IncidentStatusInProgress,
	CaseStatusContained:     ocsf.IncidentStatusOnHold,
	CaseStatusResolved:      ocsf.IncidentStatusResolved,
	CaseStatusClosed:        ocsf.IncidentStatusClosed,
}

var caseIDToStatus = map[int]string{
	ocsf.IncidentStatusNew:        CaseStatusOpen,
	ocsf.IncidentStatusInProgress: CaseStatusInvestigating,
	ocsf.IncidentStatusOnHold:     CaseStatusContained,
	ocsf.IncidentStatusResolved:   CaseStatusResolved,
	ocsf.IncidentStatusClosed:     CaseStatusClosed,
}

// CaseStatuses lists the selectable case statuses in lifecycle order.
func CaseStatuses() []string {
	return []string{CaseStatusOpen, CaseStatusInvestigating, CaseStatusContained,
		CaseStatusResolved, CaseStatusClosed}
}

// CaseStatusIDFor resolves a status label to its OCSF status_id, defaulting to
// New for anything unrecognised.
func CaseStatusIDFor(label string) int {
	if id, ok := caseStatusToID[strings.ToLower(strings.TrimSpace(label))]; ok {
		return id
	}
	return ocsf.IncidentStatusNew
}

// CaseStatusLabelFor resolves an OCSF status_id to the app's label.
func CaseStatusLabelFor(statusID int) string {
	if label, ok := caseIDToStatus[statusID]; ok {
		return label
	}
	return CaseStatusOpen
}

// CaseTicket links a case to an external tracking system, mirroring the OCSF
// `tickets` attribute on the incident profile.
type CaseTicket struct {
	ID     string `json:"id"`
	CaseID string `json:"case_id"`
	UID    string `json:"uid"`
	Title  string `json:"title,omitempty"`
	Type   string `json:"type,omitempty"`
	SrcURL string `json:"src_url,omitempty"`
	Status string `json:"status,omitempty"`
}

// ocsfCaseColumns are the incident-profile fields added to cases in Phase 3.
// They are nullable and backfilled, so upgrading an existing database is safe.
var ocsfCaseColumns = []struct {
	name string
	sql  string
}{
	{"status_id", "ALTER TABLE cases ADD COLUMN status_id INTEGER"},
	{"verdict_id", "ALTER TABLE cases ADD COLUMN verdict_id INTEGER"},
	{"priority_id", "ALTER TABLE cases ADD COLUMN priority_id INTEGER"},
	{"impact_id", "ALTER TABLE cases ADD COLUMN impact_id INTEGER"},
	{"is_suspected_breach", "ALTER TABLE cases ADD COLUMN is_suspected_breach INTEGER DEFAULT 0"},
	{"assignee_group", "ALTER TABLE cases ADD COLUMN assignee_group TEXT"},
	{"finding_count", "ALTER TABLE cases ADD COLUMN finding_count INTEGER DEFAULT 0"},
}

// migrateCaseOCSFColumns adds the incident-profile fields and derives status_id
// for cases created before it existed.
func (s *Store) migrateCaseOCSFColumns() error {
	for _, col := range ocsfCaseColumns {
		var count int
		check := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('cases') WHERE name='%s'", col.name)
		if err := s.db.QueryRow(check).Scan(&count); err != nil {
			return fmt.Errorf("failed to check cases column %s: %w", col.name, err)
		}
		if count == 0 {
			if _, err := s.db.Exec(col.sql); err != nil {
				return fmt.Errorf("failed to add cases column %s: %w", col.name, err)
			}
		}
	}

	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS case_tickets (
		id TEXT PRIMARY KEY,
		case_id TEXT NOT NULL,
		uid TEXT NOT NULL,
		title TEXT,
		type TEXT,
		src_url TEXT,
		status TEXT,
		created_at INTEGER NOT NULL,
		UNIQUE(case_id, uid),
		FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("failed to create case_tickets: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_case_tickets_case_id ON case_tickets(case_id)`); err != nil {
		return fmt.Errorf("failed to index case_tickets: %w", err)
	}

	return s.backfillCaseStatusIDs()
}

// backfillCaseStatusIDs derives status_id from the existing status label for
// cases written before the column existed.
func (s *Store) backfillCaseStatusIDs() error {
	rows, err := s.db.Query(`SELECT id, status FROM cases WHERE status_id IS NULL`)
	if err != nil {
		return fmt.Errorf("failed to scan cases for status backfill: %w", err)
	}

	type pending struct {
		id       string
		statusID int
	}
	var todo []pending
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			rows.Close()
			return fmt.Errorf("failed to read case for status backfill: %w", err)
		}
		todo = append(todo, pending{id: id, statusID: CaseStatusIDFor(status)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate cases for status backfill: %w", err)
	}
	rows.Close()

	if len(todo) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin case status backfill: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, p := range todo {
		if _, err := tx.Exec(`UPDATE cases SET status_id = ? WHERE id = ?`, p.statusID, p.id); err != nil {
			return fmt.Errorf("failed to backfill status for case %s: %w", p.id, err)
		}
	}
	return tx.Commit()
}

// UpdateCaseStatus records a lifecycle transition, keeping the label and the
// OCSF status_id in step.
func (s *Store) UpdateCaseStatus(ctx context.Context, caseID string, statusID int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cases SET status_id = ?, status = ?, updated_at = ? WHERE id = ?`,
		statusID, CaseStatusLabelFor(statusID), time.Now().Unix(), caseID)
	if err != nil {
		return fmt.Errorf("failed to update case status: %w", err)
	}
	return nil
}

// UpdateCaseVerdict records the analyst's conclusion about a case.
func (s *Store) UpdateCaseVerdict(ctx context.Context, caseID string, verdictID int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cases SET verdict_id = ?, updated_at = ? WHERE id = ?`,
		verdictID, time.Now().Unix(), caseID)
	if err != nil {
		return fmt.Errorf("failed to update case verdict: %w", err)
	}
	return nil
}

// UpdateCaseTriage sets the incident-profile triage fields together.
func (s *Store) UpdateCaseTriage(ctx context.Context, caseID string, priorityID, impactID int, suspectedBreach bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cases SET priority_id = ?, impact_id = ?, is_suspected_breach = ?, updated_at = ? WHERE id = ?`,
		priorityID, impactID, boolToInt(suspectedBreach), time.Now().Unix(), caseID)
	if err != nil {
		return fmt.Errorf("failed to update case triage: %w", err)
	}
	return nil
}

// AddCaseTicket links a case to an external tracker.
func (s *Store) AddCaseTicket(ctx context.Context, t CaseTicket) error {
	if t.ID == "" {
		t.ID = "tkt_" + uuid.New().String()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO case_tickets (id, case_id, uid, title, type, src_url, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(case_id, uid) DO UPDATE SET
			title = excluded.title, type = excluded.type,
			src_url = excluded.src_url, status = excluded.status`,
		t.ID, t.CaseID, t.UID, t.Title, t.Type, t.SrcURL, t.Status, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to add case ticket: %w", err)
	}
	return nil
}

// GetCaseTickets returns the external trackers linked to a case.
func (s *Store) GetCaseTickets(ctx context.Context, caseID string) ([]CaseTicket, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, case_id, uid, COALESCE(title,''), COALESCE(type,''),
		        COALESCE(src_url,''), COALESCE(status,'')
		 FROM case_tickets WHERE case_id = ? ORDER BY created_at`, caseID)
	if err != nil {
		return nil, fmt.Errorf("failed to query case tickets: %w", err)
	}
	defer rows.Close()

	var out []CaseTicket
	for rows.Next() {
		var t CaseTicket
		if err := rows.Scan(&t.ID, &t.CaseID, &t.UID, &t.Title, &t.Type, &t.SrcURL, &t.Status); err != nil {
			return nil, fmt.Errorf("failed to scan case ticket: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
