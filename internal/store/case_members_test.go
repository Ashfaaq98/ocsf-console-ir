package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCase(t *testing.T, st *store.Store, title string) string {
	t.Helper()
	id, err := st.CreateOrUpdateCase(context.Background(), store.Case{
		Title: title, Severity: "high", Status: store.CaseStatusOpen,
	})
	require.NoError(t, err)
	return id
}

func plainEvent(msg string) []byte {
	return []byte(`{"class_uid":4001,"category_uid":4,"type_uid":400101,"severity_id":3,
		"time":1700000000,"message":"` + msg + `","src_endpoint":{"ip":"10.0.0.1"},
		"metadata":{"uid":"m-` + msg + `"}}`)
}

// TestFindingCanBelongToManyCases is the defect Phase 3 exists to fix. A single
// nullable foreign key could only ever express one case; an alert routinely
// belongs to both the incident it triggered and a longer-running campaign case.
func TestFindingCanBelongToManyCases(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saved := saveRaw(t, st, detectionFinding(1, 1, 4, "C2 beacon"))

	incident := newCase(t, st, "workstation-14 intrusion")
	campaign := newCase(t, st, "Q3 C2 infrastructure tracking")

	require.NoError(t, st.AssignFindingToCase(ctx, saved.FindingID, incident))
	require.NoError(t, st.AssignFindingToCase(ctx, saved.FindingID, campaign))

	cases, err := st.GetCasesForMember(ctx, store.MemberTypeFinding, saved.FindingID)
	require.NoError(t, err)
	assert.Len(t, cases, 2, "one finding must be able to belong to two cases")

	for _, caseID := range []string{incident, campaign} {
		findings, err := st.GetCaseFindings(ctx, caseID)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "finding-abc-123", findings[0].FindingUID)
	}
}

func TestEventCanBelongToManyCases(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	saved := saveRaw(t, st, plainEvent("shared"))

	a := newCase(t, st, "Case A")
	b := newCase(t, st, "Case B")
	require.NoError(t, st.AssignEventToCase(ctx, saved.EventID, a))
	require.NoError(t, st.AssignEventToCase(ctx, saved.EventID, b))

	cases, err := st.GetCasesForMember(ctx, store.MemberTypeEvent, saved.EventID)
	require.NoError(t, err)
	assert.Len(t, cases, 2)

	for _, id := range []string{a, b} {
		events, err := st.GetEventsByCase(ctx, id)
		require.NoError(t, err)
		assert.Len(t, events, 1)
	}
}

// TestMembersVersusEvidence covers the role split: a case is *about* its
// findings and *supported by* its events.
func TestMembersVersusEvidence(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	caseID := newCase(t, st, "Intrusion")

	finding := saveRaw(t, st, detectionFinding(1, 1, 5, "LSASS access"))
	require.NoError(t, st.AssignFindingToCase(ctx, finding.FindingID, caseID))

	for _, msg := range []string{"ev1", "ev2", "ev3"} {
		e := saveRaw(t, st, plainEvent(msg))
		require.NoError(t, st.AssignEventToCase(ctx, e.EventID, caseID))
	}

	members, err := st.GetCaseMembers(ctx, caseID)
	require.NoError(t, err)
	require.Len(t, members, 4)

	roles := map[string]int{}
	for _, m := range members {
		roles[m.Role]++
	}
	assert.Equal(t, 1, roles[store.RoleMember], "findings join as members")
	assert.Equal(t, 3, roles[store.RoleEvidence], "events join as evidence")

	counts, err := st.CountCaseMembers(ctx, caseID)
	require.NoError(t, err)
	assert.Equal(t, 1, counts.Findings)
	assert.Equal(t, 3, counts.Events)

	// The denormalized counts on the case row track membership.
	c, err := st.GetCase(ctx, caseID)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, 1, c.FindingCount)
	assert.Equal(t, 3, c.EventCount)
}

func TestRemoveCaseMember(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	caseID := newCase(t, st, "Case")
	other := newCase(t, st, "Other")

	f := saveRaw(t, st, detectionFinding(1, 1, 4, "Beacon"))
	require.NoError(t, st.AssignFindingToCase(ctx, f.FindingID, caseID))
	require.NoError(t, st.AssignFindingToCase(ctx, f.FindingID, other))

	require.NoError(t, st.RemoveCaseMember(ctx, caseID, store.MemberTypeFinding, f.FindingID))

	remaining, err := st.GetCasesForMember(ctx, store.MemberTypeFinding, f.FindingID)
	require.NoError(t, err)
	require.Len(t, remaining, 1, "removing from one case must not remove it from the other")
	assert.Equal(t, other, remaining[0].ID)

	inCase, err := st.GetCaseFindings(ctx, caseID)
	require.NoError(t, err)
	assert.Empty(t, inCase)
}

// TestCaseStatusMapping checks the app labels project onto OCSF incident
// statuses, including the Resolved state the app previously could not express.
func TestCaseStatusMapping(t *testing.T) {
	cases := map[string]int{
		store.CaseStatusOpen:          ocsf.IncidentStatusNew,
		store.CaseStatusInvestigating: ocsf.IncidentStatusInProgress,
		store.CaseStatusContained:     ocsf.IncidentStatusOnHold,
		store.CaseStatusResolved:      ocsf.IncidentStatusResolved,
		store.CaseStatusClosed:        ocsf.IncidentStatusClosed,
	}
	for label, id := range cases {
		assert.Equal(t, id, store.CaseStatusIDFor(label), "label %q", label)
		assert.Equal(t, label, store.CaseStatusLabelFor(id), "status_id %d", id)
	}

	assert.Contains(t, store.CaseStatuses(), store.CaseStatusResolved,
		"Resolved must be selectable; OCSF distinguishes it from Closed")
	assert.Equal(t, ocsf.IncidentStatusNew, store.CaseStatusIDFor("nonsense"))
}

// TestCaseStatusIDKeptInSync: every write path must keep the label and the OCSF
// status_id consistent, since status_id is what an Incident Finding reports.
func TestCaseStatusIDKeptInSync(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	id, err := st.CreateOrUpdateCase(ctx, store.Case{
		Title: "Sync", Severity: "high", Status: store.CaseStatusInvestigating,
	})
	require.NoError(t, err)

	c, err := st.GetCase(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, ocsf.IncidentStatusInProgress, c.StatusID)

	require.NoError(t, st.UpdateCaseStatus(ctx, id, ocsf.IncidentStatusResolved))
	c, err = st.GetCase(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, ocsf.IncidentStatusResolved, c.StatusID)
	assert.Equal(t, store.CaseStatusResolved, c.Status)
}

func TestCaseTriageFields(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	id := newCase(t, st, "Triage")

	require.NoError(t, st.UpdateCaseVerdict(ctx, id, ocsf.VerdictTruePositive))
	require.NoError(t, st.UpdateCaseTriage(ctx, id, 4, 3, true))

	c, err := st.GetCase(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, ocsf.VerdictTruePositive, c.VerdictID)
	assert.Equal(t, "True Positive", c.VerdictName())
	assert.Equal(t, 4, c.PriorityID)
	assert.Equal(t, 3, c.ImpactID)
	assert.True(t, c.IsSuspectedBreach)
}

func TestDeletingCaseClearsMembership(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	caseID := newCase(t, st, "Doomed")
	f := saveRaw(t, st, detectionFinding(1, 1, 4, "Beacon"))
	e := saveRaw(t, st, plainEvent("ev"))
	require.NoError(t, st.AssignFindingToCase(ctx, f.FindingID, caseID))
	require.NoError(t, st.AssignEventToCase(ctx, e.EventID, caseID))

	require.NoError(t, st.DeleteCaseAndUnassign(ctx, caseID))

	cases, err := st.GetCasesForMember(ctx, store.MemberTypeFinding, f.FindingID)
	require.NoError(t, err)
	assert.Empty(t, cases)

	// The finding itself survives — deleting a case must not delete its contents.
	found, err := st.GetFindingByUID(ctx, "finding-abc-123")
	require.NoError(t, err)
	assert.NotNil(t, found)
}

func TestDeletingMemberPrunesMembership(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	caseID := newCase(t, st, "Case")
	f := saveRaw(t, st, detectionFinding(1, 1, 4, "Beacon"))
	require.NoError(t, st.AssignFindingToCase(ctx, f.FindingID, caseID))

	require.NoError(t, st.DeleteFindings(ctx, []string{f.FindingID}))

	members, err := st.GetCaseMembers(ctx, caseID)
	require.NoError(t, err)
	assert.Empty(t, members, "membership must not outlive the finding it points at")

	counts, err := st.CountCaseMembers(ctx, caseID)
	require.NoError(t, err)
	assert.Equal(t, 0, counts.Findings)
}

// TestCaseMemberBackfill is the upgrade path: existing single-case assignments
// must appear in the membership table with the right roles.
func TestCaseMemberBackfill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "members.db")

	// Build a database in the pre-Phase-3 shape, then populate case_id directly.
	st, err := store.NewStore(path)
	require.NoError(t, err)

	ctx := context.Background()
	caseID := newCase(t, st, "Legacy case")
	f := saveRaw(t, st, detectionFinding(1, 1, 4, "Beacon"))
	e := saveRaw(t, st, plainEvent("legacy"))
	require.NoError(t, st.Close())

	// Simulate a pre-migration database: case_id set, membership table empty.
	db, err := sql.Open(store.SQLiteDriverName(), path)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM case_members`)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE events SET case_id = ? WHERE id = ?`, caseID, e.EventID)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE findings SET case_id = ? WHERE id = ?`, caseID, f.FindingID)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	// Reopening runs the backfill.
	st2, err := store.NewStore(path)
	require.NoError(t, err)
	defer st2.Close()

	members, err := st2.GetCaseMembers(ctx, caseID)
	require.NoError(t, err)
	require.Len(t, members, 2, "existing assignments must be carried into the membership table")

	byType := map[string]store.CaseMember{}
	for _, m := range members {
		byType[m.MemberType] = m
	}
	assert.Equal(t, store.RoleMember, byType[store.MemberTypeFinding].Role)
	assert.Equal(t, store.RoleEvidence, byType[store.MemberTypeEvent].Role)

	findings, err := st2.GetCaseFindings(ctx, caseID)
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	events, err := st2.GetEventsByCase(ctx, caseID)
	require.NoError(t, err)
	assert.Len(t, events, 1)
}

func TestCaseTickets(t *testing.T) {
	st, err := store.NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	id := newCase(t, st, "Ticketed")

	require.NoError(t, st.AddCaseTicket(ctx, store.CaseTicket{
		CaseID: id, UID: "SEC-4412", Title: "Investigate beacon",
		Type: "Jira", SrcURL: "https://tracker.example/SEC-4412", Status: "Open",
	}))
	// Re-adding the same ticket updates rather than duplicating.
	require.NoError(t, st.AddCaseTicket(ctx, store.CaseTicket{
		CaseID: id, UID: "SEC-4412", Title: "Investigate beacon", Status: "In Progress",
	}))

	tickets, err := st.GetCaseTickets(ctx, id)
	require.NoError(t, err)
	require.Len(t, tickets, 1)
	assert.Equal(t, "SEC-4412", tickets[0].UID)
	assert.Equal(t, "In Progress", tickets[0].Status)
}
