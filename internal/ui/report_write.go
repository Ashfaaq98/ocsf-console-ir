package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/buildinfo"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/report"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Generating a report, and putting it somewhere an analyst can find it.
//
// Two steps, deliberately separate. Generating stores the text in the database,
// because a report is a snapshot of data that keeps moving and the document
// that was sent cannot be regenerated later. Writing it out is a second act the
// analyst asks for, and it says exactly where the file went.

// reportAuditLimit bounds the activity a report carries. A case worked for a
// week can hold hundreds of entries, and a timeline nobody reads to the end is
// not a timeline.
const reportAuditLimit = 200

// buildCaseReport gathers everything a case report is written from.
//
// It runs off the UI goroutine — six queries — and returns a value rather than
// painting anything.
func (ui *UI) buildCaseReport(ctx context.Context, caseID string) (report.CaseReport, error) {
	if ui.store == nil {
		return report.CaseReport{}, fmt.Errorf("no database")
	}

	c, err := ui.store.GetCase(ctx, caseID)
	if err != nil || c == nil {
		return report.CaseReport{}, fmt.Errorf("could not read case %s: %w", caseID, err)
	}

	r := report.CaseReport{
		Case:      *c,
		Version:   buildinfo.Display(ui.version),
		Generated: time.Now(),
	}

	// A failure in any one of these costs a section, not the report. A case
	// with no notes and a report that will not generate are different problems,
	// and only the first is the analyst's.
	r.Briefing, _ = ui.store.GetBriefing(ctx, caseID)
	r.Findings, _ = ui.store.GetCaseFindings(ctx, caseID)
	r.Events, _ = ui.store.GetEventsByCase(ctx, caseID)
	r.Notes, _ = ui.store.GetNotes(ctx, caseID)
	r.Audit, _ = ui.store.GetAuditEntries(ctx, caseID, reportAuditLimit)
	r.Indicators, _ = ui.store.GetCaseIndicators(ctx, caseID)

	return r, nil
}

// generateCaseReport writes a case report into the database and returns it.
func (ui *UI) generateCaseReport(ctx context.Context, caseID string) (*store.Report, error) {
	built, err := ui.buildCaseReport(ctx, caseID)
	if err != nil {
		return nil, err
	}

	rec := store.Report{
		Kind:      store.ReportKindCase,
		Title:     built.Title(),
		CaseID:    caseID,
		Content:   built.Markdown(),
		CreatedAt: built.Generated,
	}
	id, err := ui.store.SaveReport(ctx, rec)
	if err != nil {
		return nil, err
	}
	rec.ID = id
	return &rec, nil
}

// writeReportFile puts a stored report on disk and returns the absolute path.
//
// One file, in the directory the analyst launched from — not a folder the
// application invents. `exports/` is resolved against the working directory, so
// running the binary from home wrote to ~/exports and running it from /tmp wrote
// somewhere else; nobody could predict where their report went.
//
// If that directory cannot be written to, the data directory beside the
// database is the fallback, and the caller says so.
func writeReportFile(r store.Report) (string, error) {
	name := reportFileName(r)

	dir, err := os.Getwd()
	if err != nil {
		dir = paths.Current().Data
	}
	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, []byte(r.Content), 0o644); err != nil {
		fallback := filepath.Join(paths.Current().Data, name)
		if e := os.MkdirAll(paths.Current().Data, 0o755); e != nil {
			return "", err
		}
		if e := os.WriteFile(fallback, []byte(r.Content), 0o644); e != nil {
			return "", err
		}
		path = fallback
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return abs, nil
}

// reportFileName is what the file is called: readable, sortable, and safe on
// every filesystem.
func reportFileName(r store.Report) string {
	slug := slugify(r.Title)
	if slug == "" {
		slug = r.Kind
	}
	when := r.CreatedAt
	if when.IsZero() {
		when = time.Now()
	}
	return fmt.Sprintf("console-ir-%s-%s.md", slug, when.Format("2006-01-02-1504"))
}

var notSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = notSlug.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-")
	}
	return s
}

// writeCaseReport is `E` inside a case: write the report up, store it, put it
// on disk, and say where it went.
//
// One key rather than a menu. The moment an analyst wants a report is the
// moment they have finished the case, and asking them to choose a format first
// is a question with an obvious answer.
func (cm *CaseManagement) writeCaseReport() {
	if cm.parentUI == nil || cm.parentUI.store == nil {
		cm.updateStatus("No database")
		return
	}
	ui := cm.parentUI
	caseID := cm.caseData.ID

	cm.updateStatus("Writing the report…")
	go func() {
		rec, err := ui.generateCaseReport(ui.ctx, caseID)
		if err != nil {
			ui.queueUpdate(func() { cm.updateStatus(fmt.Sprintf("Report failed: %v", err)) })
			return
		}
		path, err := writeReportFile(*rec)
		if err != nil {
			ui.queueUpdate(func() {
				cm.updateStatus(fmt.Sprintf("Report stored, but the file failed: %v", err))
			})
			return
		}
		_ = ui.store.RecordReportPath(ui.ctx, rec.ID, path)
		_ = ui.store.LogCaseAction(ui.ctx, caseID, "report_written", cm.getCurrentAnalyst(),
			map[string]interface{}{"path": path})

		ui.queueUpdate(func() { cm.updateStatus("Report written to " + path) })
	}()
}
