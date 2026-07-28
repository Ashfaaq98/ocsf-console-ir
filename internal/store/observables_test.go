package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func observableEvent() *ocsf.Event {
	ev := &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    4001,
		ActivityID:  1,
		TypeUID:     400101,
		SeverityID:  3,
		Message:     "outbound connection",
		SrcEndpoint: &ocsf.Endpoint{IP: "192.168.1.100"},
		DstEndpoint: &ocsf.Endpoint{IP: "8.8.8.8"},
		Device:      &ocsf.Device{Hostname: "workstation-07"},
		// Asserted by the producer, with a reputation object.
		Observables: []ocsf.Observable{
			{
				Name:   "dst_endpoint.ip",
				Type:   "IP Address",
				TypeID: ocsf.ObservableTypeIPAddress,
				Value:  "8.8.8.8",
				Reputation: &ocsf.Reputation{
					Provider:  "acme-intel",
					Score:     "Suspicious",
					ScoreID:   4,
					BaseScore: 72.5,
				},
			},
		},
	}
	ev.Metadata.UID = "meta-obs-1"
	return ev
}

// TestSaveEventPersistsObservables covers the core Phase 1 behaviour: observables
// are written alongside the event, provenance is recorded, and the reputation
// object survives.
func TestSaveEventPersistsObservables(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	eventID, err := store.SaveEvent(ctx, observableEvent())
	require.NoError(t, err)

	obs, err := store.GetObservablesByEvent(ctx, eventID)
	require.NoError(t, err)
	require.NotEmpty(t, obs)

	byValue := map[string]Observable{}
	for _, o := range obs {
		byValue[o.Value] = o
	}

	// The producer's assertion is recorded as such, with its reputation intact.
	asserted, ok := byValue["8.8.8.8"]
	require.True(t, ok, "asserted observable must be persisted")
	assert.Equal(t, ObservableSourceAsserted, asserted.Source)
	assert.True(t, asserted.IsAsserted())
	assert.Equal(t, ocsf.ObservableTypeIPAddress, asserted.TypeID)
	assert.Equal(t, "IP Address", asserted.Type)
	require.NotNil(t, asserted.Reputation, "reputation object must survive; it was previously dropped")
	assert.Equal(t, "acme-intel", asserted.Reputation.Provider)
	assert.Equal(t, 72.5, asserted.Reputation.BaseScore)
	assert.Equal(t, 4, asserted.Reputation.ScoreID)

	// Fields the producer did not assert are derived.
	derived, ok := byValue["192.168.1.100"]
	require.True(t, ok, "src_endpoint.ip must be derived")
	assert.Equal(t, ObservableSourceDerived, derived.Source)
	assert.Equal(t, ocsf.ObservableTypeIPAddress, derived.TypeID)

	host, ok := byValue["workstation-07"]
	require.True(t, ok, "device.hostname must be derived")
	assert.Equal(t, ocsf.ObservableTypeHostname, host.TypeID)
	assert.Equal(t, "device.hostname", host.Name)
}

// TestObservablePivot is the indicator-pivot primitive the roadmap depends on.
func TestObservablePivot(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Three events, two of which touch 8.8.8.8.
	_, err = store.SaveEvent(ctx, observableEvent())
	require.NoError(t, err)

	second := observableEvent()
	second.Metadata.UID = "meta-obs-2"
	second.SrcEndpoint = &ocsf.Endpoint{IP: "10.0.0.5"}
	_, err = store.SaveEvent(ctx, second)
	require.NoError(t, err)

	unrelated := &ocsf.Event{
		Time: time.Now(), ClassUID: 4001, SeverityID: 2, Message: "unrelated",
		SrcEndpoint: &ocsf.Endpoint{IP: "172.16.0.1"},
	}
	_, err = store.SaveEvent(ctx, unrelated)
	require.NoError(t, err)

	events, err := store.FindEventsByObservable(ctx, ocsf.ObservableTypeIPAddress, "8.8.8.8", 0)
	require.NoError(t, err)
	assert.Len(t, events, 2, "both events touching 8.8.8.8 should be returned")

	count, err := store.CountEventsByObservable(ctx, ocsf.ObservableTypeIPAddress, "8.8.8.8")
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Value-only pivot (type unknown) still matches.
	anyType, err := store.CountEventsByObservable(ctx, ocsf.ObservableTypeUnknown, "8.8.8.8")
	require.NoError(t, err)
	assert.Equal(t, 2, anyType)

	// A type mismatch must not match: 8.8.8.8 is not a hostname.
	wrongType, err := store.CountEventsByObservable(ctx, ocsf.ObservableTypeHostname, "8.8.8.8")
	require.NoError(t, err)
	assert.Equal(t, 0, wrongType)

	none, err := store.FindEventsByObservable(ctx, ocsf.ObservableTypeIPAddress, "203.0.113.9", 0)
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestGetObservablesForEventsBatches(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	var ids []string
	for i := 0; i < 5; i++ {
		ev := observableEvent()
		ev.Metadata.UID = "meta-batch-" + string(rune('a'+i))
		id, err := store.SaveEvent(ctx, ev)
		require.NoError(t, err)
		ids = append(ids, id)
	}

	byEvent, err := store.GetObservablesForEvents(ctx, ids)
	require.NoError(t, err)
	assert.Len(t, byEvent, 5)
	for _, id := range ids {
		assert.NotEmpty(t, byEvent[id], "event %s should have observables", id)
	}

	empty, err := store.GetObservablesForEvents(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

// TestObservablesDeduplicated ensures an indicator asserted by the producer and
// also derivable from the event's fields is stored once, as asserted.
func TestObservablesDeduplicated(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	ev := &ocsf.Event{
		Time: time.Now(), ClassUID: 4001, SeverityID: 3, Message: "dupe",
		SrcEndpoint: &ocsf.Endpoint{IP: "10.1.2.3"},
		Observables: []ocsf.Observable{
			{Name: "src_endpoint.ip", TypeID: ocsf.ObservableTypeIPAddress, Value: "10.1.2.3"},
		},
	}
	eventID, err := store.SaveEvent(ctx, ev)
	require.NoError(t, err)

	obs, err := store.GetObservablesByEvent(ctx, eventID)
	require.NoError(t, err)

	matches := 0
	for _, o := range obs {
		if o.Value == "10.1.2.3" {
			matches++
			assert.Equal(t, ObservableSourceAsserted, o.Source,
				"an asserted indicator must not be downgraded to derived by deduplication")
		}
	}
	assert.Equal(t, 1, matches, "the indicator should be stored exactly once")
}

// TestObservableBackfillClassifiesProvenance covers the upgrade path: events
// stored before the observables table existed are backfilled from raw_json, and
// raw_data lets provenance be reconstructed rather than guessed.
func TestObservableBackfillClassifiesProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs-legacy.db")

	// The original payload asserted one observable; the stored raw_json also
	// carries the merged set the old code produced.
	original := `{"class_uid":4001,"category_uid":4,"time":1700000000,` +
		`"src_endpoint":{"ip":"192.168.1.100"},"dst_endpoint":{"ip":"8.8.8.8"},` +
		`"device":{"hostname":"workstation-07"},` +
		`"observables":[{"name":"dst_endpoint.ip","type":"IP Address","type_id":2,"value":"8.8.8.8"}],` +
		`"metadata":{"uid":"meta-legacy-1"}}`

	rawJSON := map[string]interface{}{
		"class_uid":    4001,
		"category_uid": 4,
		"time":         "2023-11-14T22:53:20Z",
		"src_endpoint": map[string]string{"ip": "192.168.1.100"},
		"dst_endpoint": map[string]string{"ip": "8.8.8.8"},
		"device":       map[string]string{"hostname": "workstation-07"},
		"metadata":     map[string]string{"uid": "meta-legacy-1"},
		// Old-style merged observables: informal type strings, no type_id.
		"observables": []map[string]interface{}{
			{"name": "dst_endpoint.ip", "type": "IP Address", "value": "8.8.8.8"},
			{"name": "source_ip", "type": "ip", "value": "192.168.1.100"},
			{"name": "hostname", "type": "hostname", "value": "workstation-07"},
		},
		"raw_data": json.RawMessage(original),
	}
	rawBytes, err := json.Marshal(rawJSON)
	require.NoError(t, err)

	db, err := sql.Open(sqliteDriver, path)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE cases (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT,
		severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', assigned_to TEXT,
		event_count INTEGER DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(legacyEventsDDL)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO events (id, timestamp, event_type, severity, message, host, raw_json, created_at, updated_at)
		VALUES ('evt_legacy_obs', 1700000000, 'network', 'medium', 'legacy', 'workstation-07', ?, 1700000000, 1700000000)`,
		string(rawBytes))
	require.NoError(t, err)
	require.NoError(t, db.Close())

	store, err := NewStore(path)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	obs, err := store.GetObservablesByEvent(ctx, "evt_legacy_obs")
	require.NoError(t, err)
	require.NotEmpty(t, obs, "observables must be backfilled for pre-existing events")

	byValue := map[string]Observable{}
	for _, o := range obs {
		byValue[o.Value] = o
	}

	// Asserted in the original payload.
	dst, ok := byValue["8.8.8.8"]
	require.True(t, ok)
	assert.Equal(t, ObservableSourceAsserted, dst.Source)
	assert.Equal(t, ocsf.ObservableTypeIPAddress, dst.TypeID)

	// Present only in the old merged list — that was Console-IR's own inference.
	src, ok := byValue["192.168.1.100"]
	require.True(t, ok)
	assert.Equal(t, ObservableSourceDerived, src.Source)
	assert.Equal(t, ocsf.ObservableTypeIPAddress, src.TypeID,
		"informal type strings like \"ip\" must resolve to an OCSF type_id")

	host, ok := byValue["workstation-07"]
	require.True(t, ok)
	assert.Equal(t, ObservableSourceDerived, host.Source)
	assert.Equal(t, ocsf.ObservableTypeHostname, host.TypeID)

	// The backfilled rows are immediately pivotable.
	events, err := store.FindEventsByObservable(ctx, ocsf.ObservableTypeIPAddress, "8.8.8.8", 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "evt_legacy_obs", events[0].ID)
}

// TestObservableBackfillIsIdempotent guards against duplicate rows accumulating
// each time an existing database is opened.
func TestObservableBackfillIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs-idem.db")
	seedLegacyDB(t, path)

	var first int
	for i := 0; i < 3; i++ {
		st, err := NewStore(path)
		require.NoError(t, err, "open #%d", i+1)

		var count int
		require.NoError(t, st.db.QueryRow(`SELECT COUNT(1) FROM observables`).Scan(&count))
		if i == 0 {
			first = count
		} else {
			assert.Equal(t, first, count, "observable count must not grow on reopen")
		}
		require.NoError(t, st.Close())
	}
}

// TestDeleteEventCascadesObservables keeps the index from retaining indicators
// for events that no longer exist.
func TestDeleteEventCascadesObservables(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	eventID, err := store.SaveEvent(ctx, observableEvent())
	require.NoError(t, err)

	before, err := store.GetObservablesByEvent(ctx, eventID)
	require.NoError(t, err)
	require.NotEmpty(t, before)

	require.NoError(t, store.DeleteEvents(ctx, []string{eventID}))

	after, err := store.GetObservablesByEvent(ctx, eventID)
	require.NoError(t, err)
	assert.Empty(t, after, "observables should not outlive their event")
}

// TestForeignKeysEnforcedOnBothDrivers guards a parity gap that silently broke
// every ON DELETE rule on the shipped build: the two SQLite drivers take
// different DSN syntax, and passing one driver's spelling to the other is
// ignored without error.
func TestForeignKeysEnforcedOnBothDrivers(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "fk.db"))
	require.NoError(t, err)
	defer st.Close()

	var enabled int
	require.NoError(t, st.db.QueryRow("PRAGMA foreign_keys").Scan(&enabled))
	assert.Equal(t, 1, enabled,
		"foreign keys must be enforced under driver %q, or ON DELETE CASCADE/SET NULL silently do nothing", sqliteDriver)
}

// TestBackfillWithoutOriginalAssertionsIsDerived covers the common upgrade case:
// events ingested before observables existed whose original payload asserted
// nothing. Everything reconstructed for them is Console-IR's own inference and
// must not be presented as if the source vouched for it.
func TestBackfillWithoutOriginalAssertionsIsDerived(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs-noassert.db")

	// Original payload with NO observables array — as most real sources send.
	original := `{"class_uid":4001,"category_uid":4,"time":1700000000,` +
		`"src_endpoint":{"ip":"10.0.0.5"},"device":{"hostname":"host-a"}}`

	rawJSON := map[string]interface{}{
		"class_uid":    4001,
		"category_uid": 4,
		"time":         "2023-11-14T22:53:20Z",
		"src_endpoint": map[string]string{"ip": "10.0.0.5"},
		"device":       map[string]string{"hostname": "host-a"},
		// The old merged list, using informal type spellings.
		"observables": []map[string]interface{}{
			{"name": "source_ip", "type": "ip", "value": "10.0.0.5"},
			{"name": "hostname", "type": "hostname", "value": "host-a"},
		},
		"raw_data": json.RawMessage(original),
	}
	rawBytes, err := json.Marshal(rawJSON)
	require.NoError(t, err)

	db, err := sql.Open(sqliteDriver, path)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE cases (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT,
		severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', assigned_to TEXT,
		event_count INTEGER DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(legacyEventsDDL)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO events (id, timestamp, event_type, severity, message, host, raw_json, created_at, updated_at)
		VALUES ('evt_noassert', 1700000000, 'network', 'medium', 'legacy', 'host-a', ?, 1700000000, 1700000000)`,
		string(rawBytes))
	require.NoError(t, err)
	require.NoError(t, db.Close())

	st, err := NewStore(path)
	require.NoError(t, err)
	defer st.Close()

	obs, err := st.GetObservablesByEvent(context.Background(), "evt_noassert")
	require.NoError(t, err)
	require.NotEmpty(t, obs)

	for _, o := range obs {
		assert.Equal(t, ObservableSourceDerived, o.Source,
			"%q was never asserted by the source and must not be credited to it", o.Value)
		// The stored caption must agree with the id, not keep the legacy spelling.
		assert.Equal(t, ocsf.ObservableTypeName(o.TypeID), o.Type,
			"type caption must match type_id")
	}
}
