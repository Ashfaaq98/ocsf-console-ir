package ui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
)

// seedReportableCase makes a case with a finding, an event and a note.
func seedReportableCase(t *testing.T, ui *UI, st *store.Store) string {
	t.Helper()
	ctx := context.Background()

	if _, err := st.CreateOrUpdateCase(ctx, store.Case{
		ID: "c1", Title: "Suspected account compromise", Severity: "high",
		Status: "investigating", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	fid := seedTriageFinding(t, st, "f1", "c1")
	_ = fid

	ev := &ocsf.Event{Time: time.Now(), ClassUID: 4001, ActivityID: 1, TypeUID: 400101,
		SeverityID: 3, Message: "Outbound to 45.147.230.11"}
	ev.Metadata.UID = "e1"
	eid, err := st.SaveEvent(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AssignEventToCase(ctx, eid, "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddNote(ctx, store.Note{
		CaseID: "c1", Content: "Blocked the address at the firewall", Author: "ashfaaq",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}
	return "c1"
}

// The Reports screen shows what has been written, not a list of things that do
// not exist.
//
// It used to render a static paragraph advertising case bundles, generated
// briefings and telemetry export — three features that were never built, with
// no key to reach any of them, on a numbered destination.
func TestTheReportsScreenListsWhatWasWritten(t *testing.T) {
	ui, st := newTestUI(t)
	caseID := seedReportableCase(t, ui, st)

	ui.enterScreen(destReports)
	awaitIdle(t, ui)

	empty := strings.Join(renderPrimitive(t, ui.reports.root, 140, 24), "\n")
	if !strings.Contains(empty, "No reports yet") {
		t.Errorf("an empty Reports screen does not say so:\n%s", empty)
	}
	for _, gone := range []string{"STIX", "Telemetry Export", "Case Bundles"} {
		if strings.Contains(empty, gone) {
			t.Errorf("the screen still advertises %q, which does not exist", gone)
		}
	}

	ui.writeReportForCase(caseID)
	awaitIdle(t, ui)

	frame := strings.Join(renderPrimitive(t, ui.reports.root, 140, 24), "\n")
	if !strings.Contains(frame, "Suspected account compromise") {
		t.Errorf("the written report is not listed:\n%s", frame)
	}
	if !strings.Contains(frame, "case") {
		t.Errorf("the list does not say what kind of report it is:\n%s", frame)
	}
}

// The report is kept, so what was sent can be read back after the case moves on.
func TestAReportSurvivesTheCaseChanging(t *testing.T) {
	ui, st := newTestUI(t)
	caseID := seedReportableCase(t, ui, st)
	ctx := context.Background()

	ui.enterScreen(destReports)
	awaitIdle(t, ui)
	ui.writeReportForCase(caseID)
	awaitIdle(t, ui)

	// The case moves on.
	if _, err := st.CreateOrUpdateCase(ctx, store.Case{
		ID: "c1", Title: "Renamed after the fact", Severity: "low", Status: "closed",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	list, err := st.ListReports(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("expected one stored report, got %d (%v)", len(list), err)
	}
	full, err := st.GetReport(ctx, list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full.Content, "Suspected account compromise") {
		t.Error("the stored report changed when the case did")
	}
}

// w writes the file where the analyst launched from, and says the whole path.
func TestWritingAReportSaysWhereItWent(t *testing.T) {
	ui, st := newTestUI(t)
	caseID := seedReportableCase(t, ui, st)

	dir := t.TempDir()
	was, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(was) })

	ui.enterScreen(destReports)
	awaitIdle(t, ui)
	ui.writeReportForCase(caseID)
	awaitIdle(t, ui)
	ui.reports.table.Select(1, 0)

	ui.writeSelectedReport()
	awaitIdle(t, ui)

	files, _ := filepath.Glob(filepath.Join(dir, "console-ir-*.md"))
	if len(files) != 1 {
		t.Fatalf("expected one report file in the working directory, found %v", files)
	}
	if _, err := os.Stat(filepath.Join(dir, "exports")); err == nil {
		t.Error("an exports folder was invented")
	}

	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "# Suspected account compromise") {
		t.Error("the file does not hold the report")
	}
	if bar := stripTags(ui.statusBar.GetText(true)); !strings.Contains(bar, files[0]) {
		t.Errorf("the status bar does not give the full path: %s", bar)
	}
}

// The screen owns its keys.
func TestReportsOwnsItsKeys(t *testing.T) {
	ui, st := newTestUI(t)
	seedReportableCase(t, ui, st)
	ui.enterScreen(destReports)
	awaitIdle(t, ui)

	if bar := stripTags(ui.statusBar.GetText(true)); !strings.Contains(bar, "n new") {
		t.Errorf("the Reports bar does not offer a way to write one: %s", bar)
	}
	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 'n', tcell.ModNone)) != nil {
		t.Fatal("n was not claimed on Reports")
	}
	if ui.activeModal == nil {
		t.Fatal("n opened nothing")
	}
	frame := strings.Join(renderPrimitive(t, ui.activeModal, 150, 34), "\n")
	if !strings.Contains(frame, "Suspected account compromise") {
		t.Errorf("the picker does not list the cases:\n%s", frame)
	}
	ui.closeModal()
}

// Tab belongs to this screen's two panes.
//
// Unclaimed it reached cycleFocus, which moves between the case sidebar, the
// events table and the event detail — none of which is on this screen. Focus
// landed on a widget nobody could see, and the bar announced "Focus: Cases"
// while Reports was showing.
func TestTabOnReportsStaysOnReports(t *testing.T) {
	ui, st := newTestUI(t)
	caseID := seedReportableCase(t, ui, st)
	ui.enterScreen(destReports)
	awaitIdle(t, ui)
	ui.writeReportForCase(caseID)
	awaitIdle(t, ui)

	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone)) != nil {
		t.Fatal("Tab was not claimed on Reports")
	}
	if got := ui.app.GetFocus(); got != ui.reports.preview {
		t.Errorf("Tab moved focus to %T, want the report being read", got)
	}
	if bar := stripTags(ui.statusBar.GetText(true)); strings.Contains(bar, "Focus: Cases") {
		t.Errorf("Tab announced another screen's panel: %s", bar)
	}

	ui.globalInputCapture(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone))
	if got := ui.app.GetFocus(); got != ui.reports.table {
		t.Errorf("Tab again moved focus to %T, want the list back", got)
	}
}
