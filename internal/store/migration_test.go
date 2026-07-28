package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyEventsDDL is the events table exactly as v0.1.1 created it — before the
// OCSF identity columns existed.
const legacyEventsDDL = `CREATE TABLE events (
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
	updated_at INTEGER NOT NULL
)`

// seedLegacyDB builds a database in the pre-migration shape and populates it with
// rows carrying the *incorrect* event_type values the old class mapping produced.
func seedLegacyDB(t *testing.T, path string) {
	t.Helper()

	db, err := sql.Open(sqliteDriver, path)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE cases (
		id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT,
		severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
		assigned_to TEXT, event_count INTEGER DEFAULT 0,
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`)
	require.NoError(t, err)

	_, err = db.Exec(legacyEventsDDL)
	require.NoError(t, err)

	// event_type values here are what the old hardcoded ranges produced:
	// 2004 -> "file", 1001 -> "process", 3002 -> "authentication".
	rows := []struct {
		id        string
		eventType string
		raw       string
	}{
		{
			"evt_legacy_finding", "file",
			`{"class_uid":2004,"category_uid":2,"activity_id":1,"type_uid":200401,"severity_id":4,"time":1700000000,"message":"detection","metadata":{"uid":"meta-finding-1"}}`,
		},
		{
			"evt_legacy_fs", "process",
			`{"class_uid":1001,"category_uid":1,"activity_id":1,"type_uid":100101,"severity_id":2,"time":1700000001,"message":"file write","metadata":{"uid":"meta-fs-1"}}`,
		},
		{
			"evt_legacy_auth", "authentication",
			`{"class_uid":3002,"category_uid":3,"activity_id":1,"type_uid":300201,"severity_id":3,"time":1700000002,"message":"logon","metadata":{"uid":"meta-auth-1"}}`,
		},
		{
			"evt_legacy_net", "network",
			`{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,"severity_id":3,"time":1700000003,"message":"conn","metadata":{"uid":"meta-net-1"}}`,
		},
		// Deliberately unparseable raw_json: the backfill must skip it rather
		// than fail the whole migration or invent values.
		{"evt_legacy_broken", "unknown", `{not valid json`},
	}

	for _, r := range rows {
		_, err = db.Exec(`INSERT INTO events (id, timestamp, event_type, severity, message, host, raw_json, created_at, updated_at)
			VALUES (?, 1700000000, ?, 'medium', 'legacy', 'legacy-host', ?, 1700000000, 1700000000)`,
			r.id, r.eventType, r.raw)
		require.NoError(t, err)
	}
}

// TestMigrateBackfillsOCSFColumnsOnPopulatedDB is the upgrade path for an
// existing v0.1.1 database: opening it must add the OCSF identity columns,
// backfill them from raw_json, and correct the event_type values written by the
// old class mapping — without losing rows.
func TestMigrateBackfillsOCSFColumnsOnPopulatedDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	seedLegacyDB(t, path)

	store, err := NewStore(path)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// No rows lost.
	var count int
	require.NoError(t, store.db.QueryRow(`SELECT COUNT(1) FROM events`).Scan(&count))
	assert.Equal(t, 5, count, "migration must not drop rows")

	expected := map[string]struct {
		classUID    int
		categoryUID int
		typeUID     int
		severityID  int
		metadataUID string
		eventType   string
	}{
		"evt_legacy_finding": {2004, 2, 200401, 4, "meta-finding-1", "findings"},
		"evt_legacy_fs":      {1001, 1, 100101, 2, "meta-fs-1", "system"},
		"evt_legacy_auth":    {3002, 3, 300201, 3, "meta-auth-1", "iam"},
		"evt_legacy_net":     {4001, 4, 400101, 3, "meta-net-1", "network"},
	}

	for id, want := range expected {
		t.Run(id, func(t *testing.T) {
			var (
				classUID, categoryUID, typeUID, severityID int
				metadataUID, eventType                     string
			)
			err := store.db.QueryRow(`SELECT class_uid, category_uid, type_uid, severity_id,
				COALESCE(metadata_uid, ''), event_type FROM events WHERE id = ?`, id).
				Scan(&classUID, &categoryUID, &typeUID, &severityID, &metadataUID, &eventType)
			require.NoError(t, err)

			assert.Equal(t, want.classUID, classUID)
			assert.Equal(t, want.categoryUID, categoryUID)
			assert.Equal(t, want.typeUID, typeUID)
			assert.Equal(t, want.severityID, severityID)
			assert.Equal(t, want.metadataUID, metadataUID)
			assert.Equal(t, want.eventType, eventType, "event_type must be corrected from the old mapping")
		})
	}

	// The unparseable row keeps its original values rather than being guessed at.
	var brokenClass sql.NullInt64
	require.NoError(t, store.db.QueryRow(`SELECT class_uid FROM events WHERE id = ?`, "evt_legacy_broken").Scan(&brokenClass))
	assert.False(t, brokenClass.Valid, "unparseable raw_json must be left untouched")

	// Findings are now queryable by class — the capability the old schema lacked.
	findings, err := store.GetEvents(ctx, EventFilter{Classes: []int{2004}})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "evt_legacy_finding", findings[0].ID)
	assert.True(t, findings[0].IsFinding())
	assert.Equal(t, "Detection Finding", findings[0].ClassName())

	// And by category slug.
	byCategory, err := store.CountEvents(ctx, EventFilter{Categories: []string{"findings"}})
	require.NoError(t, err)
	assert.Equal(t, 1, byCategory)
}

// TestMigrateIsIdempotent guards against the migration failing or duplicating
// work when a database is opened repeatedly.
func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	seedLegacyDB(t, path)

	for i := 0; i < 3; i++ {
		store, err := NewStore(path)
		require.NoError(t, err, "open #%d", i+1)

		var count int
		require.NoError(t, store.db.QueryRow(`SELECT COUNT(1) FROM events`).Scan(&count))
		assert.Equal(t, 5, count)

		var eventType string
		require.NoError(t, store.db.QueryRow(`SELECT event_type FROM events WHERE id = ?`, "evt_legacy_finding").Scan(&eventType))
		assert.Equal(t, "findings", eventType)

		require.NoError(t, store.Close())
	}
}

// TestEventFilterByClass covers class-level filtering on a fresh database.
func TestEventFilterByClass(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	for _, classUID := range []int{2004, 2004, 2005, 4001, 1007} {
		_, err := store.SaveEvent(ctx, newTestEvent(classUID))
		require.NoError(t, err)
	}

	detections, err := store.CountEvents(ctx, EventFilter{Classes: []int{2004}})
	require.NoError(t, err)
	assert.Equal(t, 2, detections, "should isolate Detection Findings by class_uid")

	allFindings, err := store.CountEvents(ctx, EventFilter{Categories: []string{"findings"}})
	require.NoError(t, err)
	assert.Equal(t, 3, allFindings, "2004 + 2004 + 2005")

	multi, err := store.CountEvents(ctx, EventFilter{Classes: []int{2004, 4001}})
	require.NoError(t, err)
	assert.Equal(t, 3, multi)

	none, err := store.CountEvents(ctx, EventFilter{Classes: []int{9999}})
	require.NoError(t, err)
	assert.Equal(t, 0, none)
}

// newTestEvent builds a minimal OCSF event for a given class.
func newTestEvent(classUID int) *ocsf.Event {
	return &ocsf.Event{
		Time:       time.Now(),
		ClassUID:   classUID,
		ActivityID: 1,
		TypeUID:    classUID*100 + 1,
		SeverityID: 3,
		Message:    fmt.Sprintf("test event for class %d", classUID),
	}
}
