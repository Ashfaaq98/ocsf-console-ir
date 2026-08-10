package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/google/uuid"
)

// Finding is a stored OCSF Findings-category record — an analytic's conclusion,
// with a lifecycle. Unlike an event, a finding is mutable: it is keyed on
// FindingUID and updated in place as the producer revises it.
type Finding struct {
	ID         string `json:"id"`
	FindingUID string `json:"finding_uid"`
	CaseID     string `json:"case_id,omitempty"`

	ClassUID    int `json:"class_uid"`
	CategoryUID int `json:"category_uid"`
	ActivityID  int `json:"activity_id,omitempty"`
	TypeUID     int `json:"type_uid,omitempty"`

	Title   string `json:"title"`
	Message string `json:"message,omitempty"`
	// Desc is finding_info.desc: what the detection says it saw, in the
	// producer's words. Distinct from Message, which producers often set to the
	// title.
	Desc         string `json:"desc,omitempty"`
	AnalyticName string `json:"analytic_name,omitempty"`
	AnalyticUID  string `json:"analytic_uid,omitempty"`

	Status    string `json:"status,omitempty"`
	StatusID  int    `json:"status_id"`
	Verdict   string `json:"verdict,omitempty"`
	VerdictID int    `json:"verdict_id,omitempty"`

	Severity     string `json:"severity,omitempty"`
	SeverityID   int    `json:"severity_id,omitempty"`
	ConfidenceID int    `json:"confidence_id,omitempty"`
	RiskLevelID  int    `json:"risk_level_id,omitempty"`
	RiskScore    int    `json:"risk_score,omitempty"`
	ImpactID     int    `json:"impact_id,omitempty"`
	PriorityID   int    `json:"priority_id,omitempty"`

	IsAlert           bool   `json:"is_alert,omitempty"`
	IsSuspectedBreach bool   `json:"is_suspected_breach,omitempty"`
	Assignee          string `json:"assignee,omitempty"`
	MetadataUID       string `json:"metadata_uid,omitempty"`

	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedTime time.Time `json:"created_time,omitempty"`

	AttacksJSON         string `json:"attacks_json,omitempty"`
	EvidencesJSON       string `json:"evidences_json,omitempty"`
	RelatedEventsJSON   string `json:"related_events_json,omitempty"`
	FindingInfoListJSON string `json:"finding_info_list_json,omitempty"`
	RawJSON             string `json:"raw_json"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ClassName returns the OCSF caption for the finding's class.
func (f Finding) ClassName() string { return ocsf.ClassName(f.ClassUID) }

// StatusName resolves the lifecycle status caption for the finding's class.
func (f Finding) StatusName() string {
	if f.Status != "" {
		return f.Status
	}
	return ocsf.FindingStatusName(f.ClassUID, f.StatusID)
}

// VerdictName resolves the analyst verdict caption, empty when none is set.
func (f Finding) VerdictName() string {
	if f.Verdict != "" {
		return f.Verdict
	}
	if f.VerdictID == ocsf.VerdictUnknown {
		return ""
	}
	return ocsf.VerdictName(f.VerdictID)
}

// IsOpen reports whether the finding still needs analyst attention.
func (f Finding) IsOpen() bool {
	switch f.ClassUID {
	case ocsf.ClassIncidentFinding:
		return f.StatusID != ocsf.IncidentStatusResolved && f.StatusID != ocsf.IncidentStatusClosed
	default:
		return f.StatusID != ocsf.FindingStatusResolved &&
			f.StatusID != ocsf.FindingStatusSuppressed &&
			f.StatusID != ocsf.FindingStatusArchived &&
			f.StatusID != ocsf.FindingStatusDeleted
	}
}

// Attacks decodes the stored ATT&CK associations.
func (f Finding) Attacks() []ocsf.Attack {
	var out []ocsf.Attack
	if f.AttacksJSON != "" {
		_ = json.Unmarshal([]byte(f.AttacksJSON), &out)
	}
	return out
}

// Evidences decodes the stored evidence artifacts.
func (f Finding) Evidences() []ocsf.Evidence {
	var out []ocsf.Evidence
	if f.EvidencesJSON != "" {
		_ = json.Unmarshal([]byte(f.EvidencesJSON), &out)
	}
	return out
}

// RelatedEvents decodes the events the analytic examined — the documented route
// from a finding back to the telemetry that produced it.
func (f Finding) RelatedEvents() []ocsf.RelatedEvent {
	var out []ocsf.RelatedEvent
	if f.RelatedEventsJSON != "" {
		_ = json.Unmarshal([]byte(f.RelatedEventsJSON), &out)
	}
	return out
}

const findingColumns = `id, finding_uid, case_id, class_uid, category_uid, activity_id, type_uid,
	title, message, description, analytic_name, analytic_uid, status, status_id, verdict, verdict_id,
	severity, severity_id, confidence_id, risk_level_id, risk_score, impact_id, priority_id,
	is_alert, is_suspected_breach, assignee, metadata_uid,
	first_seen, last_seen, created_time,
	attacks_json, evidences_json, related_events_json, finding_info_list_json,
	raw_json, created_at, updated_at`

// sqlPlaceholders builds the "?, ?, ?" list for a column list.
//
// Counted from the columns rather than written out: the count was a literal 35,
// so adding a column produced "36 values for 37 columns" at runtime — from
// every caller at once, and only once a finding was actually saved.
func sqlPlaceholders(columns string) string {
	n := len(strings.Split(columns, ","))
	if n < 1 {
		return ""
	}
	return "?" + strings.Repeat(", ?", n-1)
}

// findingColumnsWithAlias renders findingColumns with a table alias, for joins.
// Deriving it from the same const keeps the SELECT list and scanFindings in step.
func findingColumnsWithAlias(alias string) string {
	parts := strings.Split(findingColumns, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// migrateFindings creates the findings table and its indexes.
func (s *Store) migrateFindings() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			finding_uid TEXT NOT NULL UNIQUE,
			case_id TEXT,
			class_uid INTEGER,
			category_uid INTEGER,
			activity_id INTEGER,
			type_uid INTEGER,
			title TEXT,
			message TEXT,
			description TEXT,
			analytic_name TEXT,
			analytic_uid TEXT,
			status TEXT,
			status_id INTEGER,
			verdict TEXT,
			verdict_id INTEGER,
			severity TEXT,
			severity_id INTEGER,
			confidence_id INTEGER,
			risk_level_id INTEGER,
			risk_score INTEGER,
			impact_id INTEGER,
			priority_id INTEGER,
			is_alert INTEGER,
			is_suspected_breach INTEGER,
			assignee TEXT,
			metadata_uid TEXT,
			first_seen INTEGER,
			last_seen INTEGER,
			created_time INTEGER,
			attacks_json TEXT,
			evidences_json TEXT,
			related_events_json TEXT,
			finding_info_list_json TEXT,
			raw_json TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_status_id ON findings(status_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity_id ON findings(severity_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_class_uid ON findings(class_uid)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to create findings schema: %w", err)
		}
	}
	return s.migrateFindingDescription()
}

// migrateFindingDescription adds the description column to an existing database
// and fills it in from what was already stored.
//
// Additive and re-runnable, like migrateCaseOCSFColumns: the column is added
// only when pragma_table_info says it is missing, and the backfill only touches
// rows that have nothing there.
func (s *Store) migrateFindingDescription() error {
	var count int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name='description'`,
	).Scan(&count); err != nil {
		return fmt.Errorf("failed to check findings.description: %w", err)
	}
	if count == 0 {
		if _, err := s.db.Exec(`ALTER TABLE findings ADD COLUMN description TEXT`); err != nil {
			return fmt.Errorf("failed to add findings.description: %w", err)
		}
	}
	return s.backfillFindingDescription()
}

// backfillFindingDescription recovers finding_info.desc from raw_json.
//
// The parser has always read it; nothing stored it. The text is in raw_json for
// every finding ever ingested, so the column starts full rather than filling up
// over the next few weeks of ingestion.
func (s *Store) backfillFindingDescription() error {
	rows, err := s.db.Query(
		`SELECT id, raw_json FROM findings WHERE (description IS NULL OR description = '') AND raw_json != ''`)
	if err != nil {
		return fmt.Errorf("failed to read findings for backfill: %w", err)
	}
	defer rows.Close()

	type update struct{ id, desc string }
	var pending []update
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return fmt.Errorf("failed to scan finding for backfill: %w", err)
		}
		var f ocsf.Finding
		// Unparseable raw_json is skipped rather than failing the migration: a
		// database that will not open is worse than a description that stays
		// empty.
		if err := json.Unmarshal([]byte(raw), &f); err != nil {
			continue
		}
		if d := strings.TrimSpace(f.FindingInfo.Desc); d != "" {
			pending = append(pending, update{id: id, desc: d})
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to read findings for backfill: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin backfill: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`UPDATE findings SET description = ? WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("failed to prepare backfill: %w", err)
	}
	defer stmt.Close()

	for _, u := range pending {
		if _, err := stmt.Exec(u.desc, u.id); err != nil {
			return fmt.Errorf("failed to backfill finding %s: %w", u.id, err)
		}
	}
	return tx.Commit()
}

// SaveFinding writes a finding, updating in place when one with the same
// finding_info.uid already exists.
//
// This is what makes activity_id meaningful: a finding arrives repeatedly as
// Create, then Update, then Close. Appending each arrival would turn a single
// alert into a queue full of near-duplicates.
func (s *Store) SaveFinding(ctx context.Context, f *ocsf.Finding) (string, error) {
	if f == nil {
		return "", fmt.Errorf("nil finding")
	}
	row, err := s.ocsfToStoreFinding(f)
	if err != nil {
		return "", err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Preserve identity and analyst-owned state across producer updates.
	var (
		existingID      sql.NullString
		existingCase    sql.NullString
		existingCreated sql.NullInt64
		existingVerdict sql.NullInt64
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, case_id, created_at, verdict_id FROM findings WHERE finding_uid = ?`,
		row.FindingUID).Scan(&existingID, &existingCase, &existingCreated, &existingVerdict)
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("failed to look up finding: %w", err)
	}

	if existingID.Valid {
		row.ID = existingID.String
		if existingCase.Valid {
			row.CaseID = existingCase.String
		}
		if existingCreated.Valid {
			row.CreatedAt = time.Unix(existingCreated.Int64, 0)
		}
		// A verdict is the analyst's judgement, not the producer's. Don't let a
		// routine update from the source erase it. Verdict 0 means "none set",
		// so restoring it would stamp the literal string "Unknown" onto findings
		// nobody has judged yet.
		if row.VerdictID == ocsf.VerdictUnknown &&
			existingVerdict.Valid && existingVerdict.Int64 != ocsf.VerdictUnknown {
			row.VerdictID = int(existingVerdict.Int64)
			row.Verdict = ocsf.VerdictName(row.VerdictID)
		}
	}

	if err := upsertFinding(ctx, tx, row); err != nil {
		return "", err
	}

	// Findings carry the indicators that matter most; keep them pivotable.
	obs := observablesForFinding(row.ID, f)
	if _, err := tx.ExecContext(ctx, `DELETE FROM observables WHERE finding_id = ?`, row.ID); err != nil {
		return "", fmt.Errorf("failed to refresh finding observables: %w", err)
	}
	if err := insertObservablesTx(ctx, tx, obs); err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit finding: %w", err)
	}
	return row.ID, nil
}

func upsertFinding(ctx context.Context, tx *sql.Tx, f Finding) error {
	placeholders := sqlPlaceholders(findingColumns)
	query := `INSERT INTO findings (` + findingColumns + `) VALUES (` + placeholders + `)
		ON CONFLICT(finding_uid) DO UPDATE SET
			case_id = excluded.case_id,
			class_uid = excluded.class_uid,
			category_uid = excluded.category_uid,
			activity_id = excluded.activity_id,
			type_uid = excluded.type_uid,
			title = excluded.title,
			message = excluded.message,
			description = excluded.description,
			analytic_name = excluded.analytic_name,
			analytic_uid = excluded.analytic_uid,
			status = excluded.status,
			status_id = excluded.status_id,
			verdict = excluded.verdict,
			verdict_id = excluded.verdict_id,
			severity = excluded.severity,
			severity_id = excluded.severity_id,
			confidence_id = excluded.confidence_id,
			risk_level_id = excluded.risk_level_id,
			risk_score = excluded.risk_score,
			impact_id = excluded.impact_id,
			priority_id = excluded.priority_id,
			is_alert = excluded.is_alert,
			is_suspected_breach = excluded.is_suspected_breach,
			assignee = excluded.assignee,
			metadata_uid = excluded.metadata_uid,
			first_seen = MIN(findings.first_seen, excluded.first_seen),
			last_seen = MAX(findings.last_seen, excluded.last_seen),
			created_time = excluded.created_time,
			attacks_json = excluded.attacks_json,
			evidences_json = excluded.evidences_json,
			related_events_json = excluded.related_events_json,
			finding_info_list_json = excluded.finding_info_list_json,
			raw_json = excluded.raw_json,
			updated_at = excluded.updated_at`

	_, err := tx.ExecContext(ctx, query,
		f.ID, f.FindingUID, nullableString(f.CaseID), f.ClassUID, f.CategoryUID, f.ActivityID, f.TypeUID,
		f.Title, f.Message, f.Desc, f.AnalyticName, f.AnalyticUID, f.Status, f.StatusID, f.Verdict, f.VerdictID,
		f.Severity, f.SeverityID, f.ConfidenceID, f.RiskLevelID, f.RiskScore, f.ImpactID, f.PriorityID,
		boolToInt(f.IsAlert), boolToInt(f.IsSuspectedBreach), f.Assignee, f.MetadataUID,
		f.FirstSeen.Unix(), f.LastSeen.Unix(), f.CreatedTime.Unix(),
		f.AttacksJSON, f.EvidencesJSON, f.RelatedEventsJSON, f.FindingInfoListJSON,
		f.RawJSON, f.CreatedAt.Unix(), f.UpdatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to save finding: %w", err)
	}
	return nil
}

func nullableString(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ocsfToStoreFinding flattens an OCSF finding for storage.
func (s *Store) ocsfToStoreFinding(f *ocsf.Finding) (Finding, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return Finding{}, fmt.Errorf("failed to marshal finding: %w", err)
	}

	now := time.Now()
	row := Finding{
		ID:          "fnd_" + uuid.New().String(),
		FindingUID:  f.UID(),
		ClassUID:    f.ClassUID,
		CategoryUID: f.GetCategoryUID(),
		ActivityID:  f.ActivityID,
		TypeUID:     f.TypeUID,

		Title:        f.Title(),
		Message:      f.Message,
		Desc:         f.FindingInfo.Desc,
		AnalyticName: f.AnalyticName(),

		Status:    f.StatusName(),
		StatusID:  f.StatusID,
		Verdict:   f.VerdictName(),
		VerdictID: f.VerdictID,

		Severity:     f.GetSeverityLevel(),
		SeverityID:   f.SeverityID,
		ConfidenceID: f.ConfidenceID,
		RiskLevelID:  f.RiskLevelID,
		RiskScore:    f.RiskScore,
		ImpactID:     f.ImpactID,
		PriorityID:   f.PriorityID,

		IsAlert:           f.IsAlert,
		IsSuspectedBreach: f.IsSuspectedBreach,
		Assignee:          f.Assignee,
		MetadataUID:       f.Metadata.UID,

		FirstSeen:   f.FirstSeen(),
		LastSeen:    f.LastSeen(),
		CreatedTime: f.FindingInfo.CreatedTime,

		RawJSON:   string(raw),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if f.FindingInfo.Analytic != nil {
		row.AnalyticUID = f.FindingInfo.Analytic.UID
	}
	if row.CreatedTime.IsZero() {
		row.CreatedTime = f.Time
	}

	// activity_id 3 (Close) without an explicit terminal status still means the
	// producer considers this finished.
	if f.ActivityID == ocsf.FindingActivityClose && row.IsOpen() {
		if f.ClassUID == ocsf.ClassIncidentFinding {
			row.StatusID = ocsf.IncidentStatusClosed
		} else {
			row.StatusID = ocsf.FindingStatusResolved
		}
		row.Status = ocsf.FindingStatusName(f.ClassUID, row.StatusID)
	}

	row.AttacksJSON = marshalOrEmpty(f.FindingInfo.Attacks)
	row.EvidencesJSON = marshalOrEmpty(f.Evidences)
	row.RelatedEventsJSON = marshalOrEmpty(f.FindingInfo.RelatedEvents)
	row.FindingInfoListJSON = marshalOrEmpty(f.FindingInfoList)

	return row, nil
}

func marshalOrEmpty(v interface{}) string {
	switch val := v.(type) {
	case []ocsf.Attack:
		if len(val) == 0 {
			return ""
		}
	case []ocsf.Evidence:
		if len(val) == 0 {
			return ""
		}
	case []ocsf.RelatedEvent:
		if len(val) == 0 {
			return ""
		}
	case []ocsf.FindingInfo:
		if len(val) == 0 {
			return ""
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// FindingFilter describes optional constraints on a findings query.
// The zero value matches everything.
type FindingFilter struct {
	CaseID string
	// Statuses matches status_id.
	Statuses []int
	// Severities matches the severity label (case-insensitive).
	Severities []string
	// Classes matches class_uid, e.g. 2004 for Detection Findings.
	Classes []int
	// OpenOnly restricts to findings still needing attention.
	OpenOnly bool
	Search   string

	// MinSeverityID keeps findings at or above a severity. Fatal counts as
	// critical; Other (99) is a sentinel and never satisfies a minimum.
	MinSeverityID int

	// SeenAfter and SeenBefore bound last_seen. SeenAfter backs "last 24h";
	// SeenBefore backs "stale", which is the same field read the other way.
	SeenAfter  time.Time
	SeenBefore time.Time

	// Assignee matches the owner exactly. Empty matches every owner.
	Assignee string

	// HasObservables keeps only findings carrying at least one indicator.
	HasObservables bool

	// Sort selects the ordering. The zero value keeps the historical
	// most-recently-seen-first, so existing callers are unaffected.
	Sort FindingSort

	Limit  int
	Offset int
}

// FindingSort names an ordering for a findings query.
type FindingSort int

const (
	// SortRecent is most recently seen first.
	SortRecent FindingSort = iota
	// SortPriority is the triage ordering: the same sequence the Analyst Home
	// priority queue applies, so the queue and its full version agree about
	// which finding matters most.
	SortPriority
)

// orderBy renders the sort as SQL, with the arguments its CASE expression needs.
func (f FindingFilter) orderBy() (string, []interface{}) {
	if f.Sort == SortPriority {
		return priorityOrder, []interface{}{ocsf.FindingStatusNew, ocsf.FindingStatusInProgress}
	}
	return " ORDER BY last_seen DESC, severity_id DESC", nil
}

func (f FindingFilter) where() (string, []interface{}) {
	clause := ""
	args := []interface{}{}

	if f.CaseID != "" {
		clause += " AND case_id = ?"
		args = append(args, f.CaseID)
	}
	if len(f.Statuses) > 0 {
		ph := make([]string, len(f.Statuses))
		for i, s := range f.Statuses {
			ph[i] = "?"
			args = append(args, s)
		}
		clause += " AND status_id IN (" + strings.Join(ph, ",") + ")"
	}
	if len(f.Severities) > 0 {
		ph := make([]string, len(f.Severities))
		for i, s := range f.Severities {
			ph[i] = "?"
			args = append(args, strings.ToLower(s))
		}
		clause += " AND severity IN (" + strings.Join(ph, ",") + ")"
	}
	if len(f.Classes) > 0 {
		ph := make([]string, len(f.Classes))
		for i, c := range f.Classes {
			ph[i] = "?"
			args = append(args, c)
		}
		clause += " AND class_uid IN (" + strings.Join(ph, ",") + ")"
	}
	if f.OpenOnly {
		// Terminal states differ between Incident Finding and the rest.
		clause += ` AND NOT (
			(class_uid = ? AND status_id IN (?, ?)) OR
			(class_uid != ? AND status_id IN (?, ?, ?, ?)))`
		args = append(args,
			ocsf.ClassIncidentFinding, ocsf.IncidentStatusResolved, ocsf.IncidentStatusClosed,
			ocsf.ClassIncidentFinding, ocsf.FindingStatusResolved, ocsf.FindingStatusSuppressed,
			ocsf.FindingStatusArchived, ocsf.FindingStatusDeleted)
	}
	if f.MinSeverityID > 0 {
		// Enumerated rather than `severity_id >= ?`: Other is 99, a sentinel
		// rather than the top of the scale, and would satisfy every minimum.
		levels := []int{}
		for _, id := range []int{
			ocsf.SeverityInformational, ocsf.SeverityLow, ocsf.SeverityMedium,
			ocsf.SeverityHigh, ocsf.SeverityCritical, ocsf.SeverityFatal,
		} {
			if id >= f.MinSeverityID {
				levels = append(levels, id)
			}
		}
		ph := make([]string, len(levels))
		for i, id := range levels {
			ph[i] = "?"
			args = append(args, id)
		}
		clause += " AND severity_id IN (" + strings.Join(ph, ",") + ")"
	}
	if !f.SeenAfter.IsZero() {
		clause += " AND last_seen >= ?"
		args = append(args, f.SeenAfter.Unix())
	}
	if !f.SeenBefore.IsZero() {
		clause += " AND last_seen < ?"
		args = append(args, f.SeenBefore.Unix())
	}
	if a := strings.TrimSpace(f.Assignee); a != "" {
		clause += " AND assignee = ?"
		args = append(args, a)
	}
	if f.HasObservables {
		clause += " AND EXISTS (SELECT 1 FROM observables o WHERE o.finding_id = findings.id)"
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		pattern := "%" + escapeLIKE(q) + "%"
		clause += ` AND (title LIKE ? ESCAPE '\' OR message LIKE ? ESCAPE '\' OR analytic_name LIKE ? ESCAPE '\')`
		args = append(args, pattern, pattern, pattern)
	}

	return clause, args
}

// GetFindings returns findings matching the filter, most recently seen first.
func (s *Store) GetFindings(ctx context.Context, f FindingFilter) ([]Finding, error) {
	clause, args := f.where()
	order, orderArgs := f.orderBy()
	args = append(args, orderArgs...)
	query := `SELECT ` + findingColumns + ` FROM findings WHERE 1=1` + clause + order

	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
		if f.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, f.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// CountFindings reports how many findings match the filter.
func (s *Store) CountFindings(ctx context.Context, f FindingFilter) (int, error) {
	clause, args := f.where()
	var total int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM findings WHERE 1=1`+clause, args...).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("failed to count findings: %w", err)
	}
	return total, nil
}

// GetFindingByUID looks a finding up by its OCSF finding_info.uid.
func (s *Store) GetFindingByUID(ctx context.Context, findingUID string) (*Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+findingColumns+` FROM findings WHERE finding_uid = ?`, findingUID)
	if err != nil {
		return nil, fmt.Errorf("failed to query finding: %w", err)
	}
	defer rows.Close()

	found, err := scanFindings(rows)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}
	return &found[0], nil
}

// UpdateFindingStatus records an analyst's triage decision.
func (s *Store) UpdateFindingStatus(ctx context.Context, findingID string, statusID int) error {
	var classUID int
	if err := s.db.QueryRowContext(ctx, `SELECT class_uid FROM findings WHERE id = ?`, findingID).
		Scan(&classUID); err != nil {
		return fmt.Errorf("failed to look up finding %s: %w", findingID, err)
	}

	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status_id = ?, status = ?, updated_at = ? WHERE id = ?`,
		statusID, ocsf.FindingStatusName(classUID, statusID), time.Now().Unix(), findingID)
	if err != nil {
		return fmt.Errorf("failed to update finding status: %w", err)
	}
	return nil
}

// UpdateFindingVerdict records an analyst's true/false-positive judgement.
func (s *Store) UpdateFindingVerdict(ctx context.Context, findingID string, verdictID int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET verdict_id = ?, verdict = ?, updated_at = ? WHERE id = ?`,
		verdictID, ocsf.VerdictName(verdictID), time.Now().Unix(), findingID)
	if err != nil {
		return fmt.Errorf("failed to update finding verdict: %w", err)
	}
	return nil
}

// AssignFindingToCase makes a finding one of the things a case is about.
//
// Findings join as members rather than evidence: a case is *about* its
// detections and merely *supported by* the raw events pulled in around them.
func (s *Store) AssignFindingToCase(ctx context.Context, findingID, caseID string) error {
	return s.AddCaseMember(ctx, CaseMember{
		CaseID:     caseID,
		MemberType: MemberTypeFinding,
		MemberID:   findingID,
		Role:       RoleMember,
	})
}

func scanFindings(rows *sql.Rows) ([]Finding, error) {
	var out []Finding
	for rows.Next() {
		var f Finding
		var caseID, status, verdict, severity sql.NullString
		var title, message, description, analyticName, analyticUID, assignee, metadataUID sql.NullString
		var attacks, evidences, relatedEvents, findingInfoList sql.NullString
		var firstSeen, lastSeen, createdTime, createdAt, updatedAt int64
		var isAlert, isBreach int

		err := rows.Scan(
			&f.ID, &f.FindingUID, &caseID, &f.ClassUID, &f.CategoryUID, &f.ActivityID, &f.TypeUID,
			&title, &message, &description, &analyticName, &analyticUID, &status, &f.StatusID, &verdict, &f.VerdictID,
			&severity, &f.SeverityID, &f.ConfidenceID, &f.RiskLevelID, &f.RiskScore, &f.ImpactID, &f.PriorityID,
			&isAlert, &isBreach, &assignee, &metadataUID,
			&firstSeen, &lastSeen, &createdTime,
			&attacks, &evidences, &relatedEvents, &findingInfoList,
			&f.RawJSON, &createdAt, &updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}

		for dst, src := range map[*string]sql.NullString{
			&f.CaseID: caseID, &f.Title: title, &f.Message: message, &f.Desc: description,
			&f.AnalyticName: analyticName, &f.AnalyticUID: analyticUID,
			&f.Status: status, &f.Verdict: verdict, &f.Severity: severity,
			&f.Assignee: assignee, &f.MetadataUID: metadataUID,
			&f.AttacksJSON: attacks, &f.EvidencesJSON: evidences,
			&f.RelatedEventsJSON: relatedEvents, &f.FindingInfoListJSON: findingInfoList,
		} {
			if src.Valid {
				*dst = src.String
			}
		}

		f.IsAlert = isAlert != 0
		f.IsSuspectedBreach = isBreach != 0
		f.FirstSeen = time.Unix(firstSeen, 0)
		f.LastSeen = time.Unix(lastSeen, 0)
		f.CreatedTime = time.Unix(createdTime, 0)
		f.CreatedAt = time.Unix(createdAt, 0)
		f.UpdatedAt = time.Unix(updatedAt, 0)

		out = append(out, f)
	}
	return out, rows.Err()
}

// DeleteFindings removes findings by ID.
func (s *Store) DeleteFindings(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	ph := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM findings WHERE id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return fmt.Errorf("failed to delete findings: %w", err)
	}
	// case_members.member_id carries no foreign key, so clean up explicitly.
	return s.pruneCaseMembers(ctx, MemberTypeFinding, ids)
}

// SavedRecord reports what SaveRecord persisted.
type SavedRecord struct {
	EventID   string
	FindingID string
}

// SaveRecord persists a parsed OCSF record, routing it to the events table, the
// findings table, or both. Ingest paths call this rather than SaveEvent so the
// routing decision lives in one place.
func (s *Store) SaveRecord(ctx context.Context, rec ingestRecord) (SavedRecord, error) {
	var out SavedRecord

	if f := rec.OCSFFinding(); f != nil {
		id, err := s.SaveFinding(ctx, f)
		if err != nil {
			return out, err
		}
		out.FindingID = id
	}
	if ev := rec.OCSFEvent(); ev != nil {
		id, err := s.SaveEvent(ctx, ev)
		if err != nil {
			return out, err
		}
		out.EventID = id
	}
	return out, nil
}

// ingestRecord is the store-side view of a parsed record. It is an interface so
// the store does not depend on the ingest package (which depends on the store).
type ingestRecord interface {
	OCSFEvent() *ocsf.Event
	OCSFFinding() *ocsf.Finding
}

// AttackTechniques returns the ATT&CK technique identifiers on the finding, for
// compact display (e.g. "T1059.001"). Sub-techniques win over their parent.
func (f Finding) AttackTechniques() []string {
	var out []string
	for _, a := range f.Attacks() {
		if a.SubTechnique != nil && a.SubTechnique.UID != "" {
			out = append(out, a.SubTechnique.UID)
			continue
		}
		if a.Technique != nil && a.Technique.UID != "" {
			out = append(out, a.Technique.UID)
		}
	}
	return out
}
