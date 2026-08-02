package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// Notes are a decision log, not a text editor.
//
// Newest **last**, so the log reads forward the way an investigation happened.
// Each entry carries who, when, what kind of decision it was and what it was
// about — a wall of undated prose is not a record anyone can defend.
//
// This file previously rendered one hardcoded note ("Host FIN-02 isolated from
// network") for every case, which is a fabricated decision attributed to a
// named analyst.

// noteTemplates are the shapes a decision usually takes. Offered on `t` so the
// analyst writes the useful parts rather than staring at a blank line.
var noteTemplates = []struct {
	Name string
	Body string
}{
	{"Assessment", "What I believe happened, and what the evidence supports:\n\n"},
	{"Containment action", "What I changed, when, and on whose authority:\n\n"},
	{"Handoff", "Where this stands, and the open question for whoever picks it up:\n\n"},
	{"False-positive rationale", "Why this is benign, and what would change my mind:\n\n"},
	{"Evidence observation", "What I saw in the evidence, and where:\n\n"},
}

// renderNotes draws the decision log.
func renderNotes(table *tview.Table, notes []store.Note, t Theme) {
	table.Clear()

	// Briefing content lives in notes too. It belongs to the Briefing tab, and
	// showing it here would fill the decision log with fragments of a summary.
	log := make([]store.Note, 0, len(notes))
	for _, n := range notes {
		if store.IsBriefingNote(n) || strings.EqualFold(n.LinkedType, "ioc") {
			continue
		}
		log = append(log, n)
	}

	if len(log) == 0 {
		table.SetCell(0, 0, tview.NewTableCell("No notes yet.").
			SetTextColor(t.TextPrimary).SetSelectable(false).SetExpansion(1))
		table.SetCell(1, 0, tview.NewTableCell("").SetSelectable(false))
		table.SetCell(2, 0, tview.NewTableCell(
			"Press n to record a decision, or t to start from a template.").
			SetTextColor(t.TextMuted).SetSelectable(false).SetExpansion(1))
		return
	}

	// Oldest first: the log reads forward.
	sort.SliceStable(log, func(i, j int) bool { return log[i].CreatedAt.Before(log[j].CreatedAt) })

	row := 0
	for _, n := range log {
		table.SetCell(row, 0, tview.NewTableCell(" "+n.CreatedAt.Format("2006-01-02 15:04")).
			SetTextColor(t.TextMuted))
		table.SetCell(row, 1, tview.NewTableCell(orUnknown(n.Author)).SetTextColor(t.Accent))
		table.SetCell(row, 2, tview.NewTableCell(noteLink(n)).SetTextColor(t.TextMuted))
		table.SetCell(row, 3, tview.NewTableCell(tview.Escape(firstLine(n.Content))).
			SetTextColor(t.TextPrimary).SetExpansion(1))
		row++
	}
}

// noteLink names what a note is about, when it is about something.
func noteLink(n store.Note) string {
	if strings.TrimSpace(n.LinkedID) == "" {
		return ""
	}
	kind := strings.TrimSpace(n.LinkedType)
	if kind == "" {
		kind = "linked"
	}
	return kind
}

// firstLine is the note's preview. The log lists decisions; opening one shows
// the whole thing.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	return truncate(s, 96)
}

// updateNotesText paints the Notes tab.
func (cm *CaseManagement) updateNotesText() {
	if cm.notesTable == nil {
		return
	}
	renderNotes(cm.notesTable, cm.notes, cm.theme)
}

// ---------------------------------------------------------------------------
// Activity
// ---------------------------------------------------------------------------

// foldThreshold is how many consecutive entries of one action fold into a
// single row. Twelve ingestion lines bury the one status change that matters.
const foldThreshold = 3

// activityRow is one line of the audit trail, possibly standing for several.
type activityRow struct {
	At     time.Time
	Actor  string
	Action string
	// Change is the before → after for a lifecycle transition, empty otherwise.
	Change string
	// Folded is how many entries this row stands for; 1 when it stands alone.
	Folded int
}

// foldActivity collapses runs of the same action by the same actor.
//
// Newest first: an audit trail is read to answer "what just happened", which is
// the opposite of how the timeline is read.
func foldActivity(entries []store.AuditEntry) []activityRow {
	sorted := make([]store.AuditEntry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.After(sorted[j].Timestamp) })

	rows := []activityRow{}
	for i := 0; i < len(sorted); {
		e := sorted[i]
		j := i + 1
		for j < len(sorted) && sorted[j].Action == e.Action && sorted[j].Actor == e.Actor {
			j++
		}
		run := j - i

		// Below the threshold every entry keeps its own row. Consuming the run
		// regardless would drop the entries it stood for without saying so,
		// which is the one thing an audit trail may never do.
		if run < foldThreshold {
			for _, entry := range sorted[i:j] {
				rows = append(rows, activityRow{
					At: entry.Timestamp, Actor: orUnknown(entry.Actor),
					Action: humaniseAction(entry.Action), Change: auditChange(entry), Folded: 1,
				})
			}
			i = j
			continue
		}

		rows = append(rows, activityRow{
			At: e.Timestamp, Actor: orUnknown(e.Actor),
			Action: humaniseAction(e.Action),
			// A folded run has no single before → after to report.
			Change: "", Folded: run,
		})
		i = j
	}
	return rows
}

// auditChange renders a lifecycle transition, which is the detail an audit
// trail exists to carry.
func auditChange(e store.AuditEntry) string {
	from, hasFrom := auditDetail(e, "from", "old_status", "previous")
	to, hasTo := auditDetail(e, "to", "new_status", "status")
	switch {
	case hasFrom && hasTo:
		return from + " → " + to
	case hasTo:
		return "→ " + to
	}
	if id, ok := auditDetail(e, "finding_id", "event_id", "ioc"); ok {
		return id
	}
	return ""
}

// auditDetail reads the first present key from an audit entry's details.
func auditDetail(e store.AuditEntry, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := e.Details[k]; ok {
			if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
				return s, true
			}
		}
	}
	return "", false
}

// renderActivity draws the audit trail.
func renderActivity(table *tview.Table, rows []activityRow, t Theme, total int) {
	table.Clear()

	headers := []string{"WHEN", "WHO", "WHAT", "BEFORE → AFTER"}
	for col, h := range headers {
		table.SetCell(0, col, tview.NewTableCell(" "+h).
			SetTextColor(t.TableHeader).SetBackgroundColor(t.TableHeaderBg).SetSelectable(false))
	}

	if len(rows) == 0 {
		table.SetCell(1, 0, tview.NewTableCell(" No activity recorded.").
			SetTextColor(t.TextMuted).SetSelectable(false).SetExpansion(1))
		return
	}

	for i, r := range rows {
		what := r.Action
		if r.Folded > 1 {
			what = fmt.Sprintf("%d × %s", r.Folded, r.Action)
		}
		table.SetCell(i+1, 0, tview.NewTableCell(" "+r.At.Format("15:04:05")).SetTextColor(t.TextMuted))
		table.SetCell(i+1, 1, tview.NewTableCell(tview.Escape(r.Actor)).SetTextColor(t.Accent))
		table.SetCell(i+1, 2, tview.NewTableCell(tview.Escape(what)).SetTextColor(t.TextPrimary).SetExpansion(1))
		table.SetCell(i+1, 3, tview.NewTableCell(tview.Escape(r.Change)).SetTextColor(t.TextMuted))
	}

	if total > len(rows) {
		table.SetCell(len(rows)+2, 2, tview.NewTableCell(
			fmt.Sprintf("%d entries folded into %d rows.", total, len(rows))).
			SetTextColor(t.TextMuted).SetSelectable(false))
	}
}

// renderActivityLog paints the Activity tab.
func (cm *CaseManagement) renderActivityLog() {
	if cm.activityTable == nil {
		return
	}
	renderActivity(cm.activityTable, foldActivity(cm.auditLog), cm.theme, len(cm.auditLog))
}

// showNoteTemplates offers the shapes a decision usually takes.
//
// A blank editor is the reason case notes go unwritten; a first line naming
// what this note is for is most of the work.
func (cm *CaseManagement) showNoteTemplates() {
	list := tview.NewList().ShowSecondaryText(false)
	list.SetBorder(true).SetTitle(" NOTE TEMPLATE ").SetTitleAlign(tview.AlignLeft)
	list.SetBackgroundColor(cm.theme.Bg)
	list.SetMainTextColor(cm.theme.TextPrimary)
	list.SetSelectedBackgroundColor(cm.theme.Accent)

	for i, tpl := range noteTemplates {
		body := tpl.Body
		list.AddItem(tpl.Name, "", rune('1'+i), func() {
			cm.popModalRoot()
			cm.switchToNotesEdit()
			if cm.notesEditor != nil {
				cm.notesEditor.SetText(body, true)
			}
		})
	}
	list.AddItem("Blank note", "", 'b', func() {
		cm.popModalRoot()
		cm.switchToNotesEdit()
	})
	// Esc backs out without choosing.
	list.SetDoneFunc(func() { cm.popModalRoot() })

	// Centred both ways: pushModalRoot mounts whatever it is given as the whole
	// root, so the surrounding space has to be built here.
	height := len(noteTemplates) + 5
	row := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(list, 56, 0, true).
		AddItem(nil, 0, 1, false)
	cm.pushModalRoot(tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(row, height, 0, true).
		AddItem(nil, 0, 1, false))
}
