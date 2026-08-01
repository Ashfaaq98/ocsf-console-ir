package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

// Queries backing the Analyst Home dashboard.
//
// All are read-only, take a context, and are issued concurrently by the UI, so
// each one owns its own statement and holds no shared state. None of them is
// allowed to be slower than the panel it feeds: Home is the screen every
// session opens on, and a dashboard that arrives late is a dashboard nobody
// waits for.

// OpenFindings is the open-findings metric card.
type OpenFindings struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// CountOpenFindings returns the number of findings still needing attention,
// broken down by severity.
//
// One query rather than six: a card that shows a total and a breakdown taken at
// different instants can show a breakdown that does not sum to its own total.
func (s *Store) CountOpenFindings(ctx context.Context) (OpenFindings, error) {
	clause, args := FindingFilter{OpenOnly: true}.where()

	// Critical enumerates Critical and Fatal rather than testing `>= Critical`,
	// because Other is 99 and would otherwise be counted as the worst thing in
	// the database. Info absorbs Unknown and Other, so every finding lands in
	// exactly one bucket and the buckets sum to the total.
	row := s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(1),
			COALESCE(SUM(severity_id IN (?, ?)), 0),
			COALESCE(SUM(severity_id = ?), 0),
			COALESCE(SUM(severity_id = ?), 0),
			COALESCE(SUM(severity_id = ?), 0),
			COALESCE(SUM(severity_id NOT IN (?, ?, ?, ?, ?)), 0)
		FROM findings WHERE 1=1`+clause,
		append([]interface{}{
			ocsf.SeverityCritical, ocsf.SeverityFatal,
			ocsf.SeverityHigh, ocsf.SeverityMedium, ocsf.SeverityLow,
			ocsf.SeverityCritical, ocsf.SeverityFatal,
			ocsf.SeverityHigh, ocsf.SeverityMedium, ocsf.SeverityLow,
		}, args...)...)

	var f OpenFindings
	if err := row.Scan(&f.Total, &f.Critical, &f.High, &f.Medium, &f.Low, &f.Info); err != nil {
		return OpenFindings{}, fmt.Errorf("failed to count open findings: %w", err)
	}
	return f, nil
}

// ActiveCases is the active-cases metric card.
type ActiveCases struct {
	Total int
	// Investigating counts cases in progress, which is the number the card
	// shows: "3 active, 1 investigating" tells an analyst where the work is.
	Investigating int
	// OldestOpened is when the longest-running active case was created. Zero
	// when there are no active cases.
	OldestOpened time.Time
}

// activeCaseClause matches cases that are still open. Resolved and closed are
// the terminal states; anything else, including a case with no status at all,
// is still work.
const activeCaseClause = ` WHERE COALESCE(status_id, 0) NOT IN (?, ?)`

// CountActiveCases returns the active case count, how many are being
// investigated, and when the oldest was opened.
func (s *Store) CountActiveCases(ctx context.Context) (ActiveCases, error) {
	var (
		c      ActiveCases
		oldest sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1), COALESCE(SUM(status_id = ?), 0), MIN(created_at)
		FROM cases`+activeCaseClause,
		ocsf.IncidentStatusInProgress,
		ocsf.IncidentStatusResolved, ocsf.IncidentStatusClosed,
	).Scan(&c.Total, &c.Investigating, &oldest)
	if err != nil {
		return ActiveCases{}, fmt.Errorf("failed to count active cases: %w", err)
	}
	if oldest.Valid && oldest.Int64 > 0 {
		c.OldestOpened = time.Unix(oldest.Int64, 0)
	}
	return c, nil
}

// CountEventsToday returns the number of events since local midnight.
//
// Local midnight, not UTC: "today" on a dashboard means the analyst's today.
func (s *Store) CountEventsToday(ctx context.Context, now time.Time) (int, error) {
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	return s.CountEvents(ctx, EventFilter{Start: midnight, End: now})
}

// CountObservables returns the number of distinct indicators, counted by
// identity — `(type_id, value)` — not by sighting. The same IP seen in four
// hundred events is one indicator.
func (s *Store) CountObservables(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM (SELECT DISTINCT type_id, value FROM observables)`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count observables: %w", err)
	}
	return n, nil
}

// priorityOrder is the priority queue's ordering, in SQL so that it is applied
// by the index rather than by sorting whatever the first page happened to
// contain.
//
// The sequence is specified and is not a preference:
//
//  1. risk score, descending
//  2. severity, descending
//  3. age, newest first
//  4. status, New before In Progress
//  5. finding_uid, so the order is stable across renders
//
// Asset criticality is in the specification at position 4 but is not modelled
// yet; when it lands it goes between age and status, and this comment goes with
// it. Ties would otherwise reorder between two renders of unchanged data, which
// reads as the screen flickering.
const priorityOrder = `
	ORDER BY COALESCE(risk_score, 0) DESC,
	         COALESCE(severity_id, 0) DESC,
	         COALESCE(last_seen, 0) DESC,
	         CASE COALESCE(status_id, 0) WHEN ? THEN 0 WHEN ? THEN 1 ELSE 2 END,
	         finding_uid`

// GetPriorityQueue returns the highest-priority open findings, most urgent
// first.
func (s *Store) GetPriorityQueue(ctx context.Context, limit int) ([]Finding, error) {
	if limit <= 0 {
		limit = 5
	}
	clause, args := FindingFilter{OpenOnly: true}.where()

	args = append(args, ocsf.FindingStatusNew, ocsf.FindingStatusInProgress, limit)
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+findingColumns+` FROM findings WHERE 1=1`+clause+priorityOrder+` LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query the priority queue: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// GetRecentCases returns the most recently updated cases.
//
// By update rather than by creation, which is what ListCases orders on: the
// case an analyst touched ten minutes ago is the one they are resuming, not the
// one they opened first.
func (s *Store) GetRecentCases(ctx context.Context, limit int) ([]Case, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+caseColumns+` FROM cases`+activeCaseClause+`
		 ORDER BY updated_at DESC, created_at DESC LIMIT ?`,
		ocsf.IncidentStatusResolved, ocsf.IncidentStatusClosed, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent cases: %w", err)
	}
	defer rows.Close()
	return scanCases(rows)
}

// GetLastEvent returns the timestamp of the most recent event, and false when
// the database holds none.
//
// This is the freshness signal in the header. "No events yet" and "last event 4
// hours ago" are different problems, and both are different from a stalled
// watcher, so the caller needs to tell them apart.
func (s *Store) GetLastEvent(ctx context.Context) (time.Time, bool, error) {
	var ts sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(timestamp) FROM events`).Scan(&ts); err != nil {
		return time.Time{}, false, fmt.Errorf("failed to read the last event time: %w", err)
	}
	if !ts.Valid {
		return time.Time{}, false, nil
	}
	return time.Unix(ts.Int64, 0), true, nil
}
