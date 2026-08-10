package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// reportStore makes a database with one case worth writing up.
func reportStore(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.db")
	st, err := store.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	if _, err := st.CreateOrUpdateCase(ctx, store.Case{
		ID: "case_abc123", Title: "Suspected account compromise", Severity: "high",
		Status: "investigating", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddNote(ctx, store.Note{
		CaseID: "case_abc123", Content: "Blocked the address at the firewall", Author: "ashfaaq",
	}); err != nil {
		t.Fatal(err)
	}
	return path
}

// runReportCmd drives the command as a person would, and returns stdout.
func runReportCmd(t *testing.T, db string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer

	reportOut = ""
	viper.Set("database.path", db)
	t.Cleanup(func() { viper.Set("database.path", "") })

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := runReport(cmd, args)
	return out.String(), err
}

// The report goes to stdout, so it pipes and redirects like anything else.
func TestReportWritesToStdout(t *testing.T) {
	db := reportStore(t)

	got, err := runReportCmd(t, db, "account compromise")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# Suspected account compromise",
		"## Findings",
		"Blocked the address at the firewall",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report is missing %q:\n%s", want, got)
		}
	}
}

// With no case it says what there is, rather than failing with usage. Somebody
// who does not know a case id is exactly who typed this.
func TestReportWithNoCaseListsThem(t *testing.T) {
	db := reportStore(t)

	got, err := runReportCmd(t, db)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "case_abc123") || !strings.Contains(got, "Suspected account compromise") {
		t.Errorf("the listing does not name the case:\n%s", got)
	}
}

// --out writes the file and leaves stdout empty, so a redirect holds the report
// and nothing else.
func TestReportToAFile(t *testing.T) {
	db := reportStore(t)
	path := filepath.Join(t.TempDir(), "incident.md")

	reportOut = path
	t.Cleanup(func() { reportOut = "" })
	viper.Set("database.path", db)
	t.Cleanup(func() { viper.Set("database.path", "") })

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	if err := runReport(cmd, []string{"account compromise"}); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "# Suspected account compromise") {
		t.Error("the file does not hold the report")
	}
	if out.Len() != 0 {
		t.Errorf("standard output was not left for the report: %q", out.String())
	}
}

// A case nobody has is an error, not an empty document.
func TestReportRefusesAnUnknownCase(t *testing.T) {
	db := reportStore(t)

	if _, err := runReportCmd(t, db, "ransomware"); err == nil {
		t.Error("a case that does not exist produced a report")
	}
}
