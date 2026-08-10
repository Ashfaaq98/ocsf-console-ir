package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

func descStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "desc.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func findingWithDesc(uid, title, desc, message string) *ocsf.Finding {
	f := &ocsf.Finding{FindingInfo: ocsf.FindingInfo{UID: uid, Title: title, Desc: desc}}
	f.Message = message
	f.ClassUID = ocsf.ClassDetectionFinding
	f.CategoryUID = ocsf.CategoryFindings
	f.SeverityID = ocsf.SeverityHigh
	f.Time = time.Now()
	return f
}

// A finding's description survives the round trip.
//
// The parser read finding_info.desc and nothing stored it — no column, no
// field — so the inspector fell back to message and, when a producer set
// message to the title, told the analyst nothing had been supplied. It had.
func TestFindingDescriptionIsStored(t *testing.T) {
	st := descStore(t)
	ctx := context.Background()

	want := "A macro-enabled document arrived from a lookalike sender domain."
	f := findingWithDesc("with-desc", "Malicious attachment delivered to j.rivera", want, "")
	if _, err := st.SaveFinding(ctx, f); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetFindingByUID(ctx, "with-desc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Desc != want {
		t.Errorf("stored desc %q, want %q", got.Desc, want)
	}

	// And an update keeps it.
	revised := "Revised: the sender domain was registered yesterday."
	f.FindingInfo.Desc = revised
	if _, err := st.SaveFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetFindingByUID(ctx, "with-desc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Desc != revised {
		t.Errorf("after an update the desc is %q, want %q", got.Desc, revised)
	}
}

// A finding that carries none stores none, rather than a copy of something else.
func TestAFindingWithoutADescriptionStoresNone(t *testing.T) {
	st := descStore(t)
	if _, err := st.SaveFinding(context.Background(),
		findingWithDesc("bare", "Something happened", "", "")); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetFindingByUID(context.Background(), "bare")
	if err != nil {
		t.Fatal(err)
	}
	if got.Desc != "" {
		t.Errorf("a finding with no desc stored %q", got.Desc)
	}
}

// An existing database gains the column and is filled in from what it already
// holds, because raw_json has carried the text all along.
func TestTheDescriptionIsBackfilledFromRawJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// A database as it was before the column existed.
	st, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "The account authenticated from two countries in nine minutes."
	if _, err := st.SaveFinding(context.Background(),
		findingWithDesc("old", "Suspected account compromise", want, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE findings SET description = NULL`); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Opening it runs the migration.
	st, err = NewStore(path)
	if err != nil {
		t.Fatalf("reopening the database failed: %v", err)
	}
	defer st.Close()

	got, err := st.GetFindingByUID(context.Background(), "old")
	if err != nil {
		t.Fatal(err)
	}
	if got.Desc != want {
		t.Errorf("backfilled desc %q, want %q", got.Desc, want)
	}
}

// Unparseable raw_json is skipped, not fatal: a database that will not open is
// worse than a description that stays empty.
func TestTheBackfillSkipsUnreadableRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.db")

	st, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveFinding(context.Background(),
		findingWithDesc("broken", "Something", "should not survive", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE findings SET description = NULL, raw_json = '{not json'`); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = NewStore(path)
	if err != nil {
		t.Fatalf("a finding with unreadable raw_json stopped the database opening: %v", err)
	}
	defer st.Close()

	got, err := st.GetFindingByUID(context.Background(), "broken")
	if err != nil {
		t.Fatal(err)
	}
	if got.Desc != "" {
		t.Errorf("the backfill invented %q from unparseable json", got.Desc)
	}
}

// Running the migration twice changes nothing.
func TestTheDescriptionMigrationIsRepeatable(t *testing.T) {
	st := descStore(t)
	if _, err := st.SaveFinding(context.Background(),
		findingWithDesc("twice", "Title", "A description.", "")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := st.migrateFindings(); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	got, err := st.GetFindingByUID(context.Background(), "twice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Desc != "A description." {
		t.Errorf("re-running the migration left %q", got.Desc)
	}

	var columns int
	if err := st.db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name='description'`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 1 {
		t.Errorf("the findings table has %d description columns", columns)
	}
}

// The placeholder list is counted from the columns.
//
// It was a literal 35, so adding a column produced "36 values for 37 columns"
// at runtime, from every caller at once, and only once a finding was saved.
func TestPlaceholdersMatchTheColumns(t *testing.T) {
	cols := strings.Split(findingColumns, ",")
	marks := strings.Split(sqlPlaceholders(findingColumns), ",")
	if len(marks) != len(cols) {
		t.Fatalf("%d placeholders for %d columns", len(marks), len(cols))
	}
	for _, m := range marks {
		if strings.TrimSpace(m) != "?" {
			t.Errorf("placeholder list contains %q", m)
		}
	}
}
