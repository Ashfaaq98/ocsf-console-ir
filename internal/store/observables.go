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

// Observable provenance. OCSF observables are assertions made by the producer;
// anything Console-IR works out for itself is recorded separately so an analyst
// can tell a vouched-for indicator from an inferred one.
const (
	ObservableSourceAsserted = "asserted"
	ObservableSourceDerived  = "derived"
)

// Observable is a stored OCSF observable — the pivot element that makes
// "have I seen this indicator before?" an indexed lookup rather than a scan.
type Observable struct {
	ID         string           `json:"id"`
	EventID    string           `json:"event_id"`
	TypeID     int              `json:"type_id"`
	Type       string           `json:"type,omitempty"`
	Name       string           `json:"name,omitempty"`
	Value      string           `json:"value"`
	Source     string           `json:"source"`
	Reputation *ocsf.Reputation `json:"reputation,omitempty"`
	CreatedAt  time.Time        `json:"created_at"`
}

// IsAsserted reports whether the producer supplied this observable, as opposed
// to Console-IR deriving it from the event's fields.
func (o Observable) IsAsserted() bool { return o.Source == ObservableSourceAsserted }

const observableColumns = `id, event_id, type_id, type, name, value, source, reputation_json, created_at`

// migrateObservables creates the observables table and its indexes, then
// backfills rows for events ingested before it existed.
func (s *Store) migrateObservables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS observables (
			id TEXT PRIMARY KEY,
			event_id TEXT NOT NULL,
			type_id INTEGER NOT NULL,
			type TEXT,
			name TEXT,
			value TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT 'asserted',
			reputation_json TEXT,
			created_at INTEGER NOT NULL,
			UNIQUE(event_id, type_id, value),
			FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
		)`,
		// The pivot query is "every event touching this indicator", so
		// (type_id, value) is the index that matters. The value-only index
		// supports searching without knowing the type.
		`CREATE INDEX IF NOT EXISTS idx_observables_type_value ON observables(type_id, value)`,
		`CREATE INDEX IF NOT EXISTS idx_observables_value ON observables(value)`,
		`CREATE INDEX IF NOT EXISTS idx_observables_event_id ON observables(event_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to create observables schema: %w", err)
		}
	}

	return s.backfillObservables()
}

// observableDoc is the projection of a stored raw_json needed to reconstruct
// observables. It deliberately omits `time`: OCSF encodes timestamps as Unix
// integers in original payloads, which encoding/json cannot decode into
// time.Time, so decoding a full ocsf.Event here would fail on some inputs.
type observableDoc struct {
	Observables []ocsf.Observable `json:"observables"`
	RawData     json.RawMessage   `json:"raw_data"`
	Metadata    struct {
		UID string `json:"uid"`
	} `json:"metadata"`

	SrcEndpoint *ocsf.Endpoint `json:"src_endpoint"`
	DstEndpoint *ocsf.Endpoint `json:"dst_endpoint"`
	Device      *ocsf.Device   `json:"device"`
	File        *ocsf.File     `json:"file"`
	Process     *ocsf.Process  `json:"process"`
	User        *ocsf.User     `json:"user"`
}

// toEvent rebuilds enough of an ocsf.Event to run the derivation logic.
func (d observableDoc) toEvent() *ocsf.Event {
	ev := &ocsf.Event{
		SrcEndpoint: d.SrcEndpoint,
		DstEndpoint: d.DstEndpoint,
		Device:      d.Device,
		File:        d.File,
		Process:     d.Process,
		User:        d.User,
		Observables: d.Observables,
	}
	ev.Metadata.UID = d.Metadata.UID
	return ev
}

// backfillObservables populates the observables table for events stored before
// it existed. raw_json retains the complete event, including the original
// payload under raw_data, so provenance can be reconstructed rather than guessed:
// anything present in the original payload's observables array was asserted by
// the producer, everything else is derived.
func (s *Store) backfillObservables() error {
	rows, err := s.db.Query(`
		SELECT e.id, e.raw_json FROM events e
		WHERE NOT EXISTS (SELECT 1 FROM observables o WHERE o.event_id = e.id)`)
	if err != nil {
		return fmt.Errorf("failed to scan events for observable backfill: %w", err)
	}

	type pending struct {
		eventID string
		obs     []Observable
	}
	var todo []pending

	for rows.Next() {
		var eventID, raw string
		if err := rows.Scan(&eventID, &raw); err != nil {
			rows.Close()
			return fmt.Errorf("failed to read event for observable backfill: %w", err)
		}

		var doc observableDoc
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			// Unparseable raw_json: skip rather than invent observables.
			continue
		}

		obs := observablesFor(eventID, doc.toEvent(), assertedKeys(doc.RawData))
		if len(obs) > 0 {
			todo = append(todo, pending{eventID: eventID, obs: obs})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate events for observable backfill: %w", err)
	}
	rows.Close()

	if len(todo) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin observable backfill: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, p := range todo {
		if err := insertObservables(tx, p.obs); err != nil {
			return fmt.Errorf("failed to backfill observables for %s: %w", p.eventID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit observable backfill: %w", err)
	}
	return nil
}

// assertedKeys returns the (type_id, value) keys the producer asserted in the
// original payload, so a backfill can classify provenance correctly.
//
// It always returns a non-nil map. An empty result means "the original payload
// asserted nothing", which must be distinguishable from "provenance unknown":
// defaulting to asserted would credit the source with indicators Console-IR
// inferred itself, which is the more damaging error of the two.
func assertedKeys(rawData json.RawMessage) map[string]bool {
	keys := map[string]bool{}
	if len(rawData) == 0 {
		return keys
	}
	var original struct {
		Observables []ocsf.Observable `json:"observables"`
	}
	if err := json.Unmarshal(rawData, &original); err != nil {
		return keys
	}

	var ev ocsf.Event
	for _, o := range original.Observables {
		keys[observableKey(ev.NormalizeObservable(o))] = true
	}
	return keys
}

func observableKey(o ocsf.Observable) string {
	return fmt.Sprintf("%d\x00%s", o.TypeID, o.Value)
}

// observablesFor builds the rows to persist for an event: the producer's
// assertions first, then anything derived that is not already covered.
//
// assertedOverride, when non-nil, decides provenance instead of assuming every
// entry in ev.Observables was asserted — used by the backfill, where the stored
// list is a merge of both.
func observablesFor(eventID string, ev *ocsf.Event, assertedOverride map[string]bool) []Observable {
	now := time.Now()
	seen := make(map[string]bool)
	out := make([]Observable, 0, len(ev.Observables))

	add := func(o ocsf.Observable, source string) {
		o = ev.NormalizeObservable(o)
		if strings.TrimSpace(o.Value) == "" {
			return
		}
		k := observableKey(o)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, Observable{
			ID:         "obs_" + uuid.New().String(),
			EventID:    eventID,
			TypeID:     o.TypeID,
			Type:       o.Type,
			Name:       o.Name,
			Value:      o.Value,
			Source:     source,
			Reputation: o.Reputation,
			CreatedAt:  now,
		})
	}

	for _, o := range ev.Observables {
		source := ObservableSourceAsserted
		if assertedOverride != nil && !assertedOverride[observableKey(ev.NormalizeObservable(o))] {
			source = ObservableSourceDerived
		}
		add(o, source)
	}
	for _, o := range ev.DeriveObservables() {
		add(o, ObservableSourceDerived)
	}

	return out
}

type execer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

func insertObservables(tx execer, obs []Observable) error {
	if len(obs) == 0 {
		return nil
	}
	stmt := `INSERT OR IGNORE INTO observables (` + observableColumns + `)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	for _, o := range obs {
		var repJSON interface{}
		if o.Reputation != nil {
			b, err := json.Marshal(o.Reputation)
			if err != nil {
				return fmt.Errorf("failed to marshal reputation: %w", err)
			}
			repJSON = string(b)
		}
		if _, err := tx.Exec(stmt, o.ID, o.EventID, o.TypeID, o.Type, o.Name,
			o.Value, o.Source, repJSON, o.CreatedAt.Unix()); err != nil {
			return fmt.Errorf("failed to insert observable: %w", err)
		}
	}
	return nil
}

func scanObservables(rows *sql.Rows) ([]Observable, error) {
	var out []Observable
	for rows.Next() {
		var o Observable
		var createdAt int64
		var obsType, name, source, repJSON sql.NullString

		if err := rows.Scan(&o.ID, &o.EventID, &o.TypeID, &obsType, &name,
			&o.Value, &source, &repJSON, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan observable: %w", err)
		}
		if obsType.Valid {
			o.Type = obsType.String
		}
		if name.Valid {
			o.Name = name.String
		}
		if source.Valid {
			o.Source = source.String
		}
		if repJSON.Valid && repJSON.String != "" {
			var rep ocsf.Reputation
			if err := json.Unmarshal([]byte(repJSON.String), &rep); err == nil {
				o.Reputation = &rep
			}
		}
		o.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, o)
	}
	return out, rows.Err()
}

// GetObservablesByEvent returns every observable recorded for an event.
func (s *Store) GetObservablesByEvent(ctx context.Context, eventID string) ([]Observable, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+observableColumns+` FROM observables WHERE event_id = ? ORDER BY type_id, value`, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to query observables: %w", err)
	}
	defer rows.Close()
	return scanObservables(rows)
}

// GetObservablesForEvents returns observables for many events in one query,
// keyed by event ID. The IOC view needs the whole case at once; issuing a query
// per event would make it O(n) round trips.
func (s *Store) GetObservablesForEvents(ctx context.Context, eventIDs []string) (map[string][]Observable, error) {
	out := make(map[string][]Observable, len(eventIDs))
	if len(eventIDs) == 0 {
		return out, nil
	}

	// SQLite caps bound parameters (999 by default), so chunk.
	const chunkSize = 500
	for start := 0; start < len(eventIDs); start += chunkSize {
		end := start + chunkSize
		if end > len(eventIDs) {
			end = len(eventIDs)
		}
		chunk := eventIDs[start:end]

		placeholders := make([]string, len(chunk))
		args := make([]interface{}, len(chunk))
		for i, id := range chunk {
			placeholders[i] = "?"
			args[i] = id
		}

		rows, err := s.db.QueryContext(ctx,
			`SELECT `+observableColumns+` FROM observables
			 WHERE event_id IN (`+strings.Join(placeholders, ",")+`)
			 ORDER BY type_id, value`, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to query observables: %w", err)
		}
		obs, err := scanObservables(rows)
		rows.Close()
		if err != nil {
			return nil, err
		}
		for _, o := range obs {
			out[o.EventID] = append(out[o.EventID], o)
		}
	}

	return out, nil
}

// FindEventsByObservable returns every event carrying the given indicator.
// This is the indicator-pivot primitive: with the (type_id, value) index it is a
// single indexed lookup rather than a scan over every event's text.
//
// A typeID of ocsf.ObservableTypeUnknown matches on value alone.
func (s *Store) FindEventsByObservable(ctx context.Context, typeID int, value string, limit int) ([]Event, error) {
	query := `SELECT ` + eventColumnsWithAlias("e") + `
		FROM events e
		JOIN observables o ON o.event_id = e.id
		WHERE o.value = ?`
	args := []interface{}{value}

	if typeID != ocsf.ObservableTypeUnknown {
		query += " AND o.type_id = ?"
		args = append(args, typeID)
	}

	query += " GROUP BY e.id ORDER BY e.timestamp DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to pivot on observable: %w", err)
	}
	defer rows.Close()
	return s.scanEvents(rows)
}

// CountEventsByObservable reports how many events carry an indicator, for the
// "have I seen this before?" answer without loading the events.
func (s *Store) CountEventsByObservable(ctx context.Context, typeID int, value string) (int, error) {
	query := `SELECT COUNT(DISTINCT event_id) FROM observables WHERE value = ?`
	args := []interface{}{value}
	if typeID != ocsf.ObservableTypeUnknown {
		query += " AND type_id = ?"
		args = append(args, typeID)
	}

	var total int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("failed to count events by observable: %w", err)
	}
	return total, nil
}
