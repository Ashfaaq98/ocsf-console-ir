package store_test

import (
	"context"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detectionFinding builds a Detection Finding payload with the given lifecycle
// activity and status.
func detectionFinding(activityID, statusID int, severityID int, title string) []byte {
	return []byte(`{
		"class_uid": 2004, "category_uid": 2, "type_uid": 200401,
		"activity_id": ` + itoa(activityID) + `,
		"status_id": ` + itoa(statusID) + `,
		"severity_id": ` + itoa(severityID) + `,
		"time": 1700000000,
		"risk_score": 78,
		"confidence_id": 3,
		"is_alert": true,
		"message": "encoded powershell beacon",
		"finding_info": {
			"uid": "finding-abc-123",
			"title": "` + title + `",
			"analytic": {"name": "Encoded PowerShell Drop", "uid": "rule-1", "type_id": 1},
			"attacks": [{"technique": {"name": "PowerShell", "uid": "T1059.001"}, "version": "14"}],
			"related_events": [{"uid": "evt-1", "type_uid": 100701}]
		},
		"evidences": [{"name": "proc", "process": {"name": "powershell.exe"}, "verdict_id": 4}],
		"observables": [{"name": "device.hostname", "type_id": 1, "value": "workstation-07"}],
		"metadata": {"uid": "meta-finding-1", "version": "1.8.0"}
	}`)
}

func itoa(i int) string {
	if i < 0 {
		return "0"
	}
	digits := ""
	if i == 0 {
		return "0"
	}
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}

func saveRaw(t *testing.T, st *store.Store, raw []byte) store.SavedRecord {
	t.Helper()
	p := ingest.NewParser()
	rec, err := p.Parse(raw)
	require.NoError(t, err)
	saved, err := st.SaveRecord(context.Background(), rec)
	require.NoError(t, err)
	return saved
}

// TestFindingRoutedAwayFromEvents is the central Phase 2 behaviour: a Findings
// class must not be filed as an event.
func TestFindingRoutedAwayFromEvents(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saved := saveRaw(t, st, detectionFinding(1, 1, 4, "Encoded PowerShell beacon"))

	assert.NotEmpty(t, saved.FindingID, "a Detection Finding must produce a finding")
	assert.Empty(t, saved.EventID, "a Findings-category record is not also an event")

	events, err := st.CountEvents(ctx, store.EventFilter{})
	require.NoError(t, err)
	assert.Equal(t, 0, events, "the events table must not receive Findings-category records")

	findings, err := st.GetFindings(ctx, store.FindingFilter{})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, 2004, f.ClassUID)
	assert.Equal(t, "Detection Finding", f.ClassName())
	assert.Equal(t, "finding-abc-123", f.FindingUID)
	// Findings carry their text in finding_info.title, not message.
	assert.Equal(t, "Encoded PowerShell beacon", f.Title)
	assert.Equal(t, "Encoded PowerShell Drop", f.AnalyticName)
	assert.Equal(t, 78, f.RiskScore)
	assert.True(t, f.IsAlert)
	assert.Equal(t, []string{"T1059.001"}, f.AttackTechniques())
	assert.Len(t, f.Evidences(), 1)
	assert.Len(t, f.RelatedEvents(), 1)
}

// TestAlertableEventProducesBoth covers the security_control case: an activity
// class flagged is_alert stays queryable as telemetry *and* enters triage.
func TestAlertableEventProducesBoth(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	raw := []byte(`{"class_uid":4001,"category_uid":4,"type_uid":400101,"severity_id":4,
		"time":1700000000,"is_alert":true,"message":"blocked outbound c2",
		"src_endpoint":{"ip":"10.0.0.9"},
		"metadata":{"uid":"meta-alert-1"}}`)

	saved := saveRaw(t, st, raw)
	assert.NotEmpty(t, saved.EventID, "an alertable activity event remains an event")
	assert.NotEmpty(t, saved.FindingID, "an alertable activity event also enters triage")

	events, err := st.CountEvents(ctx, store.EventFilter{})
	require.NoError(t, err)
	assert.Equal(t, 1, events)

	findings, err := st.CountFindings(ctx, store.FindingFilter{})
	require.NoError(t, err)
	assert.Equal(t, 1, findings)
}

func TestPlainEventIsNotAFinding(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	raw := []byte(`{"class_uid":4001,"category_uid":4,"type_uid":400101,"severity_id":2,
		"time":1700000000,"message":"ordinary connection","metadata":{"uid":"m1"}}`)
	saved := saveRaw(t, st, raw)

	assert.NotEmpty(t, saved.EventID)
	assert.Empty(t, saved.FindingID, "an ordinary activity event must not become a finding")
}

// TestFindingLifecycleUpsert is why activity_id matters: Create, then Update,
// then Close must collapse onto ONE record. Appending each arrival would turn a
// single alert into a queue full of near-duplicates.
func TestFindingLifecycleUpsert(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()

	// 1. Create
	saveRaw(t, st, detectionFinding(ocsf.FindingActivityCreate, ocsf.FindingStatusNew, 3, "Beacon detected"))
	count, err := st.CountFindings(ctx, store.FindingFilter{})
	require.NoError(t, err)
	require.Equal(t, 1, count)

	first, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, ocsf.FindingStatusNew, first.StatusID)
	originalID := first.ID

	// 2. Update — severity revised, title changed, still one record.
	saveRaw(t, st, detectionFinding(ocsf.FindingActivityUpdate, ocsf.FindingStatusInProgress, 5, "Beacon confirmed"))
	count, err = st.CountFindings(ctx, store.FindingFilter{})
	require.NoError(t, err)
	assert.Equal(t, 1, count, "an update must not create a second finding")

	updated, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, originalID, updated.ID, "the record identity must be stable across updates")
	assert.Equal(t, ocsf.FindingStatusInProgress, updated.StatusID)
	assert.Equal(t, "Beacon confirmed", updated.Title)
	assert.Equal(t, 5, updated.SeverityID)

	// 3. Close without an explicit terminal status still closes it.
	saveRaw(t, st, detectionFinding(ocsf.FindingActivityClose, 0, 5, "Beacon confirmed"))
	closed, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	require.NotNil(t, closed)
	assert.Equal(t, ocsf.FindingStatusResolved, closed.StatusID,
		"activity_id 3 (Close) must terminate the finding even without an explicit status")
	assert.False(t, closed.IsOpen())

	count, err = st.CountFindings(ctx, store.FindingFilter{})
	require.NoError(t, err)
	assert.Equal(t, 1, count, "three lifecycle events, one finding")
}

// TestAnalystVerdictSurvivesProducerUpdate: a verdict is the analyst's
// judgement. A routine refresh from the source must not silently erase it.
func TestAnalystVerdictSurvivesProducerUpdate(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saveRaw(t, st, detectionFinding(1, 1, 3, "Beacon"))

	f, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	require.NotNil(t, f)

	require.NoError(t, st.UpdateFindingVerdict(ctx, f.ID, ocsf.VerdictTruePositive))

	// The producer sends an update carrying no verdict.
	saveRaw(t, st, detectionFinding(2, 2, 4, "Beacon"))

	after, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, ocsf.VerdictTruePositive, after.VerdictID,
		"the analyst's verdict must survive a producer update")
	assert.Equal(t, "True Positive", after.VerdictName())
}

func TestFindingTriageUpdates(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saveRaw(t, st, detectionFinding(1, 1, 3, "Beacon"))
	f, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	require.NotNil(t, f)

	require.NoError(t, st.UpdateFindingStatus(ctx, f.ID, ocsf.FindingStatusSuppressed))
	after, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	assert.Equal(t, ocsf.FindingStatusSuppressed, after.StatusID)
	assert.Equal(t, "Suppressed", after.StatusName())
	assert.False(t, after.IsOpen())

	// A suppressed finding drops out of the open queue.
	open, err := st.CountFindings(ctx, store.FindingFilter{OpenOnly: true})
	require.NoError(t, err)
	assert.Equal(t, 0, open)

	all, err := st.CountFindings(ctx, store.FindingFilter{})
	require.NoError(t, err)
	assert.Equal(t, 1, all)
}

func TestFindingFilters(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saveRaw(t, st, detectionFinding(1, ocsf.FindingStatusNew, 4, "High beacon"))

	// A second, distinct finding.
	raw := []byte(`{"class_uid":2004,"category_uid":2,"type_uid":200401,"activity_id":1,
		"status_id":2,"severity_id":2,"time":1700000100,
		"finding_info":{"uid":"finding-xyz-999","title":"Low noise",
			"analytic":{"name":"Noise Rule","uid":"rule-2","type_id":1}},
		"metadata":{"uid":"meta-2"}}`)
	saveRaw(t, st, raw)

	byStatus, err := st.GetFindings(ctx, store.FindingFilter{Statuses: []int{ocsf.FindingStatusNew}})
	require.NoError(t, err)
	require.Len(t, byStatus, 1)
	assert.Equal(t, "finding-abc-123", byStatus[0].FindingUID)

	byClass, err := st.CountFindings(ctx, store.FindingFilter{Classes: []int{2004}})
	require.NoError(t, err)
	assert.Equal(t, 2, byClass)

	bySearch, err := st.GetFindings(ctx, store.FindingFilter{Search: "noise"})
	require.NoError(t, err)
	require.Len(t, bySearch, 1)
	assert.Equal(t, "Low noise", bySearch[0].Title)

	bySeverity, err := st.CountFindings(ctx, store.FindingFilter{Severities: []string{"high"}})
	require.NoError(t, err)
	assert.Equal(t, 1, bySeverity)
}

// TestFindingObservablesArePivotable: a finding's indicators are the most
// valuable in the system, so the pivot must reach them.
func TestFindingObservablesArePivotable(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saved := saveRaw(t, st, detectionFinding(1, 1, 4, "Beacon"))

	obs, err := st.GetObservablesByFinding(ctx, saved.FindingID)
	require.NoError(t, err)
	require.NotEmpty(t, obs, "a finding's observables must be persisted")

	for _, o := range obs {
		assert.Empty(t, o.EventID, "a finding's observable is owned by the finding")
		assert.Equal(t, saved.FindingID, o.FindingID)
	}

	hits, err := st.FindFindingsByObservable(ctx, ocsf.ObservableTypeHostname, "workstation-07", 0)
	require.NoError(t, err)
	require.Len(t, hits, 1)
	assert.Equal(t, "finding-abc-123", hits[0].FindingUID)

	count, err := st.CountFindingsByObservable(ctx, ocsf.ObservableTypeHostname, "workstation-07")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestFindingWithoutUIDStillDeduplicates: producers that omit the required
// finding_info.uid must not generate a new record on every update.
func TestFindingWithoutUIDStillDeduplicates(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	raw := []byte(`{"class_uid":2004,"category_uid":2,"type_uid":200401,"activity_id":1,
		"severity_id":3,"time":1700000000,
		"finding_info":{"title":"No uid here","analytic":{"name":"R","uid":"r","type_id":1}},
		"metadata":{"uid":"stable-meta-uid"}}`)

	saveRaw(t, st, raw)
	saveRaw(t, st, raw)
	saveRaw(t, st, raw)

	count, err := st.CountFindings(ctx, store.FindingFilter{})
	require.NoError(t, err)
	assert.Equal(t, 1, count, "a missing finding_info.uid must fall back to a stable identity")
}

func TestDeleteFindingCascadesObservables(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saved := saveRaw(t, st, detectionFinding(1, 1, 4, "Beacon"))

	before, err := st.GetObservablesByFinding(ctx, saved.FindingID)
	require.NoError(t, err)
	require.NotEmpty(t, before)

	require.NoError(t, st.DeleteFindings(ctx, []string{saved.FindingID}))

	after, err := st.GetObservablesByFinding(ctx, saved.FindingID)
	require.NoError(t, err)
	assert.Empty(t, after, "observables must not outlive their finding")
}

// TestUnjudgedFindingHasNoVerdict: verdict_id 0 means "no analyst judgement
// yet". It must render as absent, not as the literal string "Unknown".
func TestUnjudgedFindingHasNoVerdict(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saveRaw(t, st, detectionFinding(1, 1, 3, "Beacon"))
	// A producer update on a finding nobody has judged.
	saveRaw(t, st, detectionFinding(2, 2, 4, "Beacon"))

	f, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, ocsf.VerdictUnknown, f.VerdictID)
	assert.Empty(t, f.VerdictName(), "an unjudged finding must have no verdict, not \"Unknown\"")
}
