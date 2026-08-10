package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// A report is still there after the application is closed and opened again.
//
// The obvious test — save it and read it back — passes on a database that never
// writes to disk, because both halves talk to the same open handle. This one
// closes the store and reopens the file, which is what quitting and relaunching
// does.
func TestAReportSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports.db")
	ctx := context.Background()

	st, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.SaveReport(ctx, Report{
		Kind: ReportKindCase, Title: "Suspected account compromise",
		CaseID: "c1", Content: "# Suspected account compromise\n\nSomething happened.\n",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewStore(path)
	if err != nil {
		t.Fatalf("reopening the database failed: %v", err)
	}
	defer reopened.Close()

	list, err := reopened.ListReports(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("after a restart the database holds %d reports, want 1", len(list))
	}
	full, err := reopened.GetReport(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if full.Content == "" {
		t.Error("the report came back empty")
	}
}
