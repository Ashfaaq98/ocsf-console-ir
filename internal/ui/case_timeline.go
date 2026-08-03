package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// The timeline is the case's narrative, so it reads as a story rather than a
// log: events, findings and audit entries on one line of time, clustered so
// six things on one host inside six minutes are one entry rather than six.
//
// Clustering reuses the same window-and-entity rule the Events screen applies,
// via clusterEvents in event_cluster.go — the timeline is not a second idea
// about what "around the same time" means.

// timelineCap bounds the entries drawn. Beyond this the case is not a narrative
// any more, and the cap is stated on screen rather than silently applied.
const timelineCap = 500

// timelineKind distinguishes what a timeline row came from, because the three
// sources answer different questions and must not look alike.
type timelineKind int

const (
	timelineEvent timelineKind = iota
	timelineFinding
	timelineActivity
)

// timelineEntry is one moment in the case.
type timelineEntry struct {
	At     time.Time
	Kind   timelineKind
	Label  string
	Detail string
	// Count is how many events a clustered entry holds; 1 for a single moment.
	Count  int
	Pinned bool
	// Events are the members of a cluster, drawn when it is expanded.
	Events []store.Event
}

// buildTimeline merges the three sources into one ordered narrative.
//
// Findings and activity are single moments; events cluster. A finding is the
// claim and the audit entry is what an analyst did, and neither is made clearer
// by being folded into "6 events".
// It returns the entries and how many the cap dropped. The count is of
// *entries*, not of source records: clustering six events into one line is the
// timeline working, not the timeline hiding something, and reporting it as
// "showing 12 of 25" would call every well-clustered case truncated.
func buildTimeline(events []store.Event, findings []store.Finding, audit []store.AuditEntry,
	pinned map[string]bool, group groupKey) ([]timelineEntry, int) {

	entries := []timelineEntry{}

	for _, c := range clusterEvents(events, group) {
		anyPinned := false
		for _, e := range c.Events {
			if pinned[e.ID] {
				anyPinned = true
			}
		}
		label := c.Label
		if c.Count() == 1 {
			label = truncate(c.Events[0].Message, 70)
		}
		entries = append(entries, timelineEntry{
			At:     c.Start,
			Kind:   timelineEvent,
			Label:  label,
			Detail: eventCountLabel(c.Count()),
			Count:  c.Count(),
			Pinned: anyPinned,
			Events: c.Events,
		})
	}

	for _, f := range findings {
		entries = append(entries, timelineEntry{
			At: f.FirstSeen, Kind: timelineFinding,
			Label: truncate(f.Title, 70), Detail: "finding", Count: 1,
		})
	}

	// Audit folds the same way it does on the Activity tab. Twelve identical
	// "evidence attached" lines bury the narrative the timeline exists to tell,
	// and the timeline is not the one place that rule stops applying.
	for _, a := range foldActivity(audit) {
		label := fmt.Sprintf("%s by %s", a.Action, a.Actor)
		if a.Folded > 1 {
			label = fmt.Sprintf("%d × %s by %s", a.Folded, a.Action, a.Actor)
		}
		entries = append(entries, timelineEntry{
			At: a.At, Kind: timelineActivity, Label: label,
			Detail: "activity", Count: 1,
		})
	}

	// Oldest first: a narrative reads forward.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].At.Before(entries[j].At) })

	dropped := 0
	if len(entries) > timelineCap {
		dropped = len(entries) - timelineCap
		entries = entries[:timelineCap]
	}
	return entries, dropped
}

func eventCountLabel(n int) string {
	if n == 1 {
		return "1 event"
	}
	return fmt.Sprintf("%d events", n)
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "system"
	}
	return s
}

// renderTimeline draws the narrative into a table.
//
// A table rather than a text pane, for two reasons. Event messages carry
// brackets — a command line, a JSON fragment — and escaping those inside a
// multi-line TextView makes tview's tag state drift across the rows. And a
// cluster needs a cursor on it before Enter can expand it.
//
// The rail uses terminal-native marks with an ASCII fallback, and never costs a
// column of timestamp: a decorative graph that obscures the time is a worse
// timeline than a list.
func renderTimeline(table *tview.Table, entries []timelineEntry, expanded string, t Theme, dropped int) map[int]string {
	table.Clear()
	rowCluster := map[int]string{}

	if len(entries) == 0 {
		table.SetCell(0, 0, tview.NewTableCell("Nothing on the timeline yet.").
			SetTextColor(t.TextPrimary).SetSelectable(false).SetExpansion(1))
		table.SetCell(1, 0, tview.NewTableCell("").SetSelectable(false))
		table.SetCell(2, 0, tview.NewTableCell(
			"Attach events with 'a' from the Events screen, or escalate a finding with 'e' from Triage.").
			SetTextColor(t.TextMuted).SetSelectable(false).SetExpansion(1))
		return rowCluster
	}

	vert, last := "│", "└"
	if !supportsUnicode() {
		vert, last = "|", "\\"
	}

	row := 0
	for i, e := range entries {
		glyph, colour := timelineMark(e.Kind, t)
		rail := vert
		if i == len(entries)-1 {
			rail = last
		}

		mark := " "
		if e.Pinned {
			mark = "★"
		}
		open := ""
		if e.Count > 1 {
			open = " ▸"
			if e.Label == expanded {
				open = " ▾"
			}
			rowCluster[row] = e.Label
		}

		table.SetCell(row, 0, tview.NewTableCell(" "+e.At.Format("15:04")).SetTextColor(t.TextMuted))
		table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("[%s]%s[-]", colour, glyph)))
		table.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("[%s]%s[-]", t.TagWarning, mark)))
		table.SetCell(row, 3, tview.NewTableCell(tview.Escape(e.Label)+open).
			SetTextColor(t.TextPrimary).SetExpansion(1))
		table.SetCell(row, 4, tview.NewTableCell(e.Detail).SetTextColor(t.TextMuted))
		row++

		if e.Count > 1 && e.Label == expanded {
			for _, ev := range e.Events {
				table.SetCell(row, 0, tview.NewTableCell("").SetSelectable(false))
				table.SetCell(row, 1, tview.NewTableCell(rail).SetTextColor(t.TextMuted).SetSelectable(false))
				table.SetCell(row, 3, tview.NewTableCell(
					ev.Timestamp.Format("15:04:05")+"  "+tview.Escape(truncate(ev.Message, 64))).
					SetTextColor(t.TextMuted).SetSelectable(false).SetExpansion(1))
				row++
			}
		}
	}

	if dropped > 0 {
		table.SetCell(row+1, 3, tview.NewTableCell(
			fmt.Sprintf("Capped at %d entries; %d further not shown.", timelineCap, dropped)).
			SetTextColor(t.TextMuted).SetSelectable(false))
	}
	return rowCluster
}

// timelineMark gives each source a distinct glyph, not only a distinct colour.
func timelineMark(k timelineKind, t Theme) (glyph, colour string) {
	switch k {
	case timelineFinding:
		return "◆", t.TagSeverityHigh
	case timelineActivity:
		return "·", t.TagMuted
	default:
		return "●", t.TagAccent
	}
}

// humaniseAction turns an audit action into plain words.
//
// The audit trail has to be terse and trustworthy, which rules out decorating
// it: an emoji beside "case closed" is a claim about how to feel about it.
func humaniseAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "create_case", "case_created":
		return "case created"
	case "assign_event", "event_assigned":
		return "evidence attached"
	case "note_added":
		return "note added"
	case "ioc_added":
		return "indicator added"
	case "status_changed", "update_status":
		return "status changed"
	case "copilot_query":
		return "copilot asked"
	case "":
		return "activity"
	default:
		return strings.ReplaceAll(action, "_", " ")
	}
}

// updateTimelineView paints the Timeline tab.
func (cm *CaseManagement) updateTimelineView() {
	if cm.timelineView == nil {
		return
	}
	findings, err := cm.store.GetCaseFindings(cm.ctx, cm.caseData.ID)
	if err != nil && cm.logger != nil {
		cm.logger.Warn("timeline: could not read case findings: %v", err)
	}

	entries, dropped := buildTimeline(cm.events, findings, cm.auditLog, cm.pinnedEvents, groupByHost)
	cm.timelineRows = renderTimeline(cm.timelineView, entries, cm.expandedTimeline, cm.theme, dropped)
}

// toggleTimelineCluster expands or collapses the cluster under the cursor.
//
// One open at a time, as on the Events screen: expanding everything reproduces
// the log the timeline exists to replace.
func (cm *CaseManagement) toggleTimelineCluster() {
	row, _ := cm.timelineView.GetSelection()
	label, ok := cm.timelineRows[row]
	if !ok {
		return
	}
	if cm.expandedTimeline == label {
		cm.expandedTimeline = ""
	} else {
		cm.expandedTimeline = label
	}
	cm.updateTimelineView()
}
