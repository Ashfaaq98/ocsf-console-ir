package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Case member kinds and roles.
//
// The role distinction is the point of this table. A case is *about* its
// findings (members) and *supported by* its events (evidence). Collapsing both
// into one undifferentiated pile makes a case with 4 detections and 300
// corroborating log lines look like 304 equally important things.
const (
	MemberTypeFinding = "finding"
	MemberTypeEvent   = "event"

	// RoleMember is what the case is about — normally its findings.
	RoleMember = "member"
	// RoleEvidence is what supports it — normally raw events pulled in during
	// investigation.
	RoleEvidence = "evidence"
)

// CaseMember links a case to a finding or an event.
type CaseMember struct {
	CaseID     string    `json:"case_id"`
	MemberType string    `json:"member_type"`
	MemberID   string    `json:"member_id"`
	Role       string    `json:"role"`
	AddedBy    string    `json:"added_by,omitempty"`
	AddedAt    time.Time `json:"added_at"`
}

// DefaultRoleFor returns the role a member type takes unless overridden.
func DefaultRoleFor(memberType string) string {
	if memberType == MemberTypeFinding {
		return RoleMember
	}
	return RoleEvidence
}

// migrateCaseMembers creates the membership table and backfills it from the
// single-case foreign keys it replaces.
func (s *Store) migrateCaseMembers() error {
	stmts := []string{
		// member_id intentionally has no foreign key: it points at either
		// findings or events depending on member_type, and SQLite cannot express
		// a conditional reference. Deletes clean up explicitly instead.
		`CREATE TABLE IF NOT EXISTS case_members (
			case_id TEXT NOT NULL,
			member_type TEXT NOT NULL,
			member_id TEXT NOT NULL,
			role TEXT NOT NULL,
			added_by TEXT,
			added_at INTEGER NOT NULL,
			PRIMARY KEY (case_id, member_type, member_id),
			FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
		)`,
		// The reverse lookup — "which cases contain this item?" — is what makes
		// membership many-to-many useful.
		`CREATE INDEX IF NOT EXISTS idx_case_members_member ON case_members(member_type, member_id)`,
		`CREATE INDEX IF NOT EXISTS idx_case_members_case_role ON case_members(case_id, role)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to create case_members schema: %w", err)
		}
	}
	if err := s.migrateCaseMemberColumns(); err != nil {
		return err
	}
	return s.backfillCaseMembers()
}

// caseMemberColumns are fields added to case_members after it shipped. Additive
// with defaults, so an existing database upgrades without a backfill.
var caseMemberColumns = []struct {
	name string
	sql  string
}{
	// Pinned evidence is the analyst's judgement about which of forty-two
	// events actually prove the case. It surfaces on the briefing and in
	// exports, so it is data rather than presentation — which is why it is a
	// column rather than a rendering flag.
	{"pinned", "ALTER TABLE case_members ADD COLUMN pinned INTEGER DEFAULT 0"},
}

// migrateCaseMemberColumns adds the columns above if they are absent. Checking
// pragma_table_info first makes a re-run a no-op, matching migrateCaseOCSFColumns.
func (s *Store) migrateCaseMemberColumns() error {
	for _, col := range caseMemberColumns {
		var count int
		check := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('case_members') WHERE name='%s'", col.name)
		if err := s.db.QueryRow(check).Scan(&count); err != nil {
			return fmt.Errorf("failed to check case_members column %s: %w", col.name, err)
		}
		if count == 0 {
			if _, err := s.db.Exec(col.sql); err != nil {
				return fmt.Errorf("failed to add case_members column %s: %w", col.name, err)
			}
		}
	}
	return nil
}

// SetMemberPinned marks or unmarks a case member as pinned.
func (s *Store) SetMemberPinned(ctx context.Context, caseID, memberType, memberID string, pinned bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE case_members SET pinned = ? WHERE case_id = ? AND member_type = ? AND member_id = ?`,
		boolToInt(pinned), caseID, memberType, memberID)
	if err != nil {
		return fmt.Errorf("failed to set pinned on %s %s: %w", memberType, memberID, err)
	}
	return nil
}

// GetPinnedMemberIDs returns the pinned member ids of one type for a case.
//
// Ids rather than rows: the caller already holds the members, and the briefing
// needs only to know which of them carry a star.
func (s *Store) GetPinnedMemberIDs(ctx context.Context, caseID, memberType string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT member_id FROM case_members WHERE case_id = ? AND member_type = ? AND pinned = 1`,
		caseID, memberType)
	if err != nil {
		return nil, fmt.Errorf("failed to query pinned members: %w", err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan pinned member: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

// backfillCaseMembers copies existing single-case assignments into the
// membership table. Events become evidence and findings become members, matching
// the roles they would be given today.
func (s *Store) backfillCaseMembers() error {
	now := time.Now().Unix()
	stmts := []struct {
		sql  string
		args []interface{}
	}{
		{`INSERT OR IGNORE INTO case_members (case_id, member_type, member_id, role, added_by, added_at)
		  SELECT e.case_id, ?, e.id, ?, 'migration', ?
		  FROM events e
		  WHERE e.case_id IS NOT NULL AND e.case_id != ''
		    AND EXISTS (SELECT 1 FROM cases c WHERE c.id = e.case_id)`,
			[]interface{}{MemberTypeEvent, RoleEvidence, now}},
		{`INSERT OR IGNORE INTO case_members (case_id, member_type, member_id, role, added_by, added_at)
		  SELECT f.case_id, ?, f.id, ?, 'migration', ?
		  FROM findings f
		  WHERE f.case_id IS NOT NULL AND f.case_id != ''
		    AND EXISTS (SELECT 1 FROM cases c WHERE c.id = f.case_id)`,
			[]interface{}{MemberTypeFinding, RoleMember, now}},
	}
	for _, st := range stmts {
		if _, err := s.db.Exec(st.sql, st.args...); err != nil {
			return fmt.Errorf("failed to backfill case members: %w", err)
		}
	}
	return nil
}

// AddCaseMember links one finding or event to a case.
func (s *Store) AddCaseMember(ctx context.Context, m CaseMember) error {
	return s.AddCaseMembers(ctx, []CaseMember{m})
}

// AddCaseMembers links several items to a case in one transaction.
//
// The legacy single-case column is written alongside for compatibility with
// readers that have not moved over yet. It can only hold one case, so for an
// item that belongs to several it records the first — the membership table is
// the source of truth.
func (s *Store) AddCaseMembers(ctx context.Context, members []CaseMember) error {
	if len(members) == 0 {
		return nil
	}

	// Make sure the target cases exist BEFORE opening a transaction. An
	// in-memory database is pinned to a single connection, so any query issued
	// on s.db while a transaction is open waits for a connection that the
	// transaction itself is holding — a deadlock rather than an error.
	seenCases := map[string]bool{}
	for _, m := range members {
		if strings.TrimSpace(m.CaseID) == "" || strings.TrimSpace(m.MemberID) == "" {
			continue
		}
		if seenCases[m.CaseID] {
			continue
		}
		if err := s.ensureCaseExists(ctx, m.CaseID); err != nil {
			return err
		}
		seenCases[m.CaseID] = true
	}
	if len(seenCases) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, m := range members {
		if strings.TrimSpace(m.CaseID) == "" || strings.TrimSpace(m.MemberID) == "" {
			continue
		}
		if m.Role == "" {
			m.Role = DefaultRoleFor(m.MemberType)
		}
		if m.AddedAt.IsZero() {
			m.AddedAt = time.Now()
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO case_members (case_id, member_type, member_id, role, added_by, added_at)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(case_id, member_type, member_id) DO UPDATE SET role = excluded.role`,
			m.CaseID, m.MemberType, m.MemberID, m.Role, m.AddedBy, m.AddedAt.Unix()); err != nil {
			return fmt.Errorf("failed to add case member: %w", err)
		}

		// Compatibility write to the column this table replaces.
		table := "events"
		if m.MemberType == MemberTypeFinding {
			table = "findings"
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE `+table+` SET case_id = COALESCE(NULLIF(case_id, ''), ?), updated_at = ? WHERE id = ?`,
			m.CaseID, time.Now().Unix(), m.MemberID); err != nil {
			return fmt.Errorf("failed to write compatibility case_id: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit case members: %w", err)
	}

	for caseID := range seenCases {
		_ = s.RefreshCaseCounts(ctx, caseID)
	}
	return nil
}

// RemoveCaseMember unlinks an item from a case.
func (s *Store) RemoveCaseMember(ctx context.Context, caseID, memberType, memberID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM case_members WHERE case_id = ? AND member_type = ? AND member_id = ?`,
		caseID, memberType, memberID); err != nil {
		return fmt.Errorf("failed to remove case member: %w", err)
	}

	// Point the compatibility column at whatever case still holds this item.
	table := "events"
	if memberType == MemberTypeFinding {
		table = "findings"
	}
	var remaining sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT case_id FROM case_members WHERE member_type = ? AND member_id = ? LIMIT 1`,
		memberType, memberID).Scan(&remaining)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to resolve remaining membership: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE `+table+` SET case_id = ?, updated_at = ? WHERE id = ?`,
		nullableString(remaining.String), time.Now().Unix(), memberID); err != nil {
		return fmt.Errorf("failed to clear compatibility case_id: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit member removal: %w", err)
	}
	return s.RefreshCaseCounts(ctx, caseID)
}

// GetCaseMembers returns every membership row for a case.
func (s *Store) GetCaseMembers(ctx context.Context, caseID string) ([]CaseMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT case_id, member_type, member_id, role, COALESCE(added_by,''), added_at
		 FROM case_members WHERE case_id = ? ORDER BY role, added_at`, caseID)
	if err != nil {
		return nil, fmt.Errorf("failed to query case members: %w", err)
	}
	defer rows.Close()

	var out []CaseMember
	for rows.Next() {
		var m CaseMember
		var addedAt int64
		if err := rows.Scan(&m.CaseID, &m.MemberType, &m.MemberID, &m.Role, &m.AddedBy, &addedAt); err != nil {
			return nil, fmt.Errorf("failed to scan case member: %w", err)
		}
		m.AddedAt = time.Unix(addedAt, 0)
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetCasesForMember returns every case containing the given item.
//
// This is what one-to-one membership could not express: an alert routinely
// belongs to both the incident it triggered and a longer-running campaign case.
func (s *Store) GetCasesForMember(ctx context.Context, memberType, memberID string) ([]Case, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT c.id, c.title, c.description, c.severity, c.status, COALESCE(c.assigned_to,''),
		        c.event_count, c.created_at, c.updated_at
		 FROM cases c
		 JOIN case_members m ON m.case_id = c.id
		 WHERE m.member_type = ? AND m.member_id = ?
		 ORDER BY c.created_at DESC`, memberType, memberID)
	if err != nil {
		return nil, fmt.Errorf("failed to query cases for member: %w", err)
	}
	defer rows.Close()

	var out []Case
	for rows.Next() {
		var c Case
		var createdAt, updatedAt int64
		if err := rows.Scan(&c.ID, &c.Title, &c.Description, &c.Severity, &c.Status,
			&c.AssignedTo, &c.EventCount, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan case: %w", err)
		}
		c.CreatedAt = time.Unix(createdAt, 0)
		c.UpdatedAt = time.Unix(updatedAt, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCaseFindings returns the findings a case is about.
func (s *Store) GetCaseFindings(ctx context.Context, caseID string) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+findingColumnsWithAlias("f")+`
		 FROM findings f
		 JOIN case_members m ON m.member_id = f.id AND m.member_type = ?
		 WHERE m.case_id = ?
		 ORDER BY f.risk_score DESC, f.last_seen DESC`, MemberTypeFinding, caseID)
	if err != nil {
		return nil, fmt.Errorf("failed to query case findings: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// GetCaseEventMembers returns the events attached to a case as evidence.
func (s *Store) GetCaseEventMembers(ctx context.Context, caseID string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+eventColumnsWithAlias("e")+`
		 FROM events e
		 JOIN case_members m ON m.member_id = e.id AND m.member_type = ?
		 WHERE m.case_id = ?
		 ORDER BY e.timestamp DESC`, MemberTypeEvent, caseID)
	if err != nil {
		return nil, fmt.Errorf("failed to query case events: %w", err)
	}
	defer rows.Close()
	return s.scanEvents(rows)
}

// CaseCounts summarizes what a case holds.
type CaseCounts struct {
	Findings int `json:"findings"`
	Events   int `json:"events"`
}

// CountCaseMembers reports how many findings and events a case holds.
func (s *Store) CountCaseMembers(ctx context.Context, caseID string) (CaseCounts, error) {
	var counts CaseCounts
	rows, err := s.db.QueryContext(ctx,
		`SELECT member_type, COUNT(1) FROM case_members WHERE case_id = ? GROUP BY member_type`, caseID)
	if err != nil {
		return counts, fmt.Errorf("failed to count case members: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var memberType string
		var n int
		if err := rows.Scan(&memberType, &n); err != nil {
			return counts, fmt.Errorf("failed to scan member count: %w", err)
		}
		switch memberType {
		case MemberTypeFinding:
			counts.Findings = n
		case MemberTypeEvent:
			counts.Events = n
		}
	}
	return counts, rows.Err()
}

// RefreshCaseCounts syncs the denormalized counts on the case row.
func (s *Store) RefreshCaseCounts(ctx context.Context, caseID string) error {
	counts, err := s.CountCaseMembers(ctx, caseID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE cases SET event_count = ?, finding_count = ?, updated_at = ? WHERE id = ?`,
		counts.Events, counts.Findings, time.Now().Unix(), caseID)
	if err != nil {
		return fmt.Errorf("failed to refresh case counts: %w", err)
	}
	return nil
}

// pruneCaseMembers drops membership rows for items that no longer exist.
// member_id cannot carry a foreign key (it points at two tables), so deletes
// clean up here instead.
func (s *Store) pruneCaseMembers(ctx context.Context, memberType string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	ph := make([]string, len(ids))
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, memberType)
	for i, id := range ids {
		ph[i] = "?"
		args = append(args, id)
	}

	affected, err := s.casesHoldingMembers(ctx, memberType, ids)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM case_members WHERE member_type = ? AND member_id IN (`+strings.Join(ph, ",")+`)`,
		args...); err != nil {
		return fmt.Errorf("failed to prune case members: %w", err)
	}

	for _, caseID := range affected {
		_ = s.RefreshCaseCounts(ctx, caseID)
	}
	return nil
}

func (s *Store) casesHoldingMembers(ctx context.Context, memberType string, ids []string) ([]string, error) {
	ph := make([]string, len(ids))
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, memberType)
	for i, id := range ids {
		ph[i] = "?"
		args = append(args, id)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT case_id FROM case_members
		 WHERE member_type = ? AND member_id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve affected cases: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
