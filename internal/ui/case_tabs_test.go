package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// tableText flattens a table for assertions.
func tableCells(table *tview.Table) string {
	var b strings.Builder
	for r := 0; r < table.GetRowCount(); r++ {
		for c := 0; c < table.GetColumnCount(); c++ {
			if cell := table.GetCell(r, c); cell != nil {
				b.WriteString(cell.Text)
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Indicators
// ---------------------------------------------------------------------------

// Provenance is what makes an indicator defensible: a producer's claim and our
// own inference are answered differently. A row without it is a bug.
func TestIndicatorProvenanceAlwaysRenders(t *testing.T) {
	theme := themeDark()
	table := tview.NewTable()
	renderCaseIndicators(table, []store.CaseIndicator{
		{TypeID: 2, Type: "ip", Value: "198.51.100.73", Source: "asserted", Sightings: 12},
		{TypeID: 2, Type: "ip", Value: "203.0.113.9", Source: "derived", Sightings: 1},
		{TypeID: 1, Type: "hostname", Value: "fin-02", Source: "", Sightings: 4},
	}, theme, nil)

	for row := 1; row <= 3; row++ {
		cell := table.GetCell(row, 2)
		if cell == nil || strings.TrimSpace(cell.Text) == "" {
			t.Fatalf("row %d renders no provenance at all", row)
		}
	}

	// A glyph as well as a colour, so the distinction survives 16 colours —
	// and the two must not render identically.
	assertedGlyph, assertedColour, _ := provenanceMark("asserted", theme)
	derivedGlyph, derivedColour, _ := provenanceMark("derived", theme)
	if assertedGlyph == derivedGlyph {
		t.Errorf("asserted and derived share the glyph %q", assertedGlyph)
	}
	if assertedColour == derivedColour {
		t.Errorf("asserted and derived share the colour %q", assertedColour)
	}

	// An unknown source is asserted, not blank.
	if _, _, label := provenanceMark("", theme); label != "asserted" {
		t.Errorf("an empty source labelled %q, want asserted", label)
	}
}

// Sightings are counted from the case, not invented. This tab used to print
// "3 events" for every indicator whatever the case held.
func TestIndicatorSightingsComeFromTheData(t *testing.T) {
	table := tview.NewTable()
	renderCaseIndicators(table, []store.CaseIndicator{
		{Type: "ip", Value: "198.51.100.73", Source: "asserted", Sightings: 12},
		{Type: "ip", Value: "203.0.113.9", Source: "derived", Sightings: 1},
	}, themeDark(), nil)

	got := tableCells(table)
	for _, want := range []string{"12", "198.51.100.73", "203.0.113.9"} {
		if !strings.Contains(got, want) {
			t.Errorf("indicators are missing %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "3 events") {
		t.Errorf("the hardcoded sighting count is back\n%s", got)
	}
}

// The same indicator in two cases is one indicator with the sightings summed,
// and asserted anywhere wins: one producer's claim is not weakened by another
// case having only inferred it.
func TestIndicatorsMergeAcrossCases(t *testing.T) {
	early := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	late := early.Add(3 * time.Hour)

	got := mergeIndicators([]store.CaseIndicator{
		{TypeID: 2, Value: "198.51.100.73", Source: "derived", Sightings: 2, FirstSeen: late, LastSeen: late},
		{TypeID: 2, Value: "198.51.100.73", Source: "asserted", Sightings: 5, FirstSeen: early, LastSeen: early},
		{TypeID: 1, Value: "fin-02", Source: "asserted", Sightings: 1},
	})

	if len(got) != 2 {
		t.Fatalf("merged to %d indicators, want 2", len(got))
	}
	if got[0].Sightings != 7 {
		t.Errorf("sightings = %d, want 7", got[0].Sightings)
	}
	if got[0].Source != "asserted" {
		t.Errorf("source = %q, want asserted to win", got[0].Source)
	}
	if !got[0].FirstSeen.Equal(early) || !got[0].LastSeen.Equal(late) {
		t.Errorf("window = %v–%v, want %v–%v", got[0].FirstSeen, got[0].LastSeen, early, late)
	}
}

// An analyst's own entry is neither asserted nor derived, and must not be
// dropped from the tab or disguised as one of them.
func TestManualIndicatorsAreKeptAndMarked(t *testing.T) {
	at := time.Date(2026, 8, 1, 11, 0, 0, 0, time.UTC)
	got, ids := manualIndicators([]store.Note{
		{ID: "n1", Content: "ioc_type:ip", LinkedType: "ioc", LinkedID: "10.0.0.5", CreatedAt: at},
		{ID: "n2", Content: "an ordinary note", LinkedType: "", LinkedID: ""},
		{ID: "n3", Content: "ioc_type:", LinkedType: "ioc", LinkedID: "evil.example", CreatedAt: at},
	})

	if len(got) != 2 {
		t.Fatalf("kept %d manual indicators, want 2", len(got))
	}
	if got[0].Type != "ip" || got[0].Value != "10.0.0.5" {
		t.Errorf("first manual indicator = %s/%s, want ip/10.0.0.5", got[0].Type, got[0].Value)
	}
	// A missing type falls back to a word, never to an empty column.
	if got[1].Type == "" {
		t.Error("an indicator with no type rendered a blank type")
	}
	for _, ind := range got {
		if _, _, label := provenanceMark(ind.Source, themeDark()); label != "manual" {
			t.Errorf("manual entry labelled %q", label)
		}
	}
	if ids["10.0.0.5"] != "n1" {
		t.Errorf("row-to-note mapping lost n1, so Space and d would act on nothing")
	}
}

// ---------------------------------------------------------------------------
// Activity
// ---------------------------------------------------------------------------

// Twelve ingestion lines bury the one status change that matters.
func TestActivityFoldsRepetitiveRuns(t *testing.T) {
	base := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	entries := []store.AuditEntry{
		{Timestamp: base, Action: "status_changed", Actor: "paolo",
			Details: map[string]interface{}{"from": "open", "to": "investigating"}},
	}
	for i := 0; i < 12; i++ {
		entries = append(entries, store.AuditEntry{
			Timestamp: base.Add(time.Duration(-i-1) * time.Minute),
			Action:    "assign_event", Actor: "paolo",
		})
	}

	rows := foldActivity(entries)
	if len(rows) != 2 {
		t.Fatalf("folded to %d rows, want 2\n%+v", len(rows), rows)
	}
	// Newest first: an audit trail answers "what just happened".
	if rows[0].Folded != 1 || !strings.Contains(rows[0].Change, "→") {
		t.Errorf("the lifecycle change was folded away: %+v", rows[0])
	}
	if rows[1].Folded != 12 {
		t.Errorf("the run folded to %d, want 12", rows[1].Folded)
	}
	// The count reaches the screen rather than silently hiding eleven entries.
	table := tview.NewTable()
	renderActivity(table, rows, themeDark(), 13)
	if got := tableCells(table); !strings.Contains(got, "12 ×") {
		t.Errorf("the fold count is not on screen\n%s", got)
	}
}

// A run below the threshold stays as individual rows — folding two entries
// hides as much as it saves.
func TestActivityKeepsShortRuns(t *testing.T) {
	base := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	rows := foldActivity([]store.AuditEntry{
		{Timestamp: base, Action: "note_added", Actor: "paolo"},
		{Timestamp: base.Add(-time.Minute), Action: "note_added", Actor: "paolo"},
	})
	if len(rows) != 2 {
		t.Errorf("a run of 2 folded into %d rows; the threshold is %d", len(rows), foldThreshold)
	}
}

// A lifecycle change without both ends still says what it became.
func TestAuditChangeDegradesGracefully(t *testing.T) {
	for _, tc := range []struct {
		name    string
		details map[string]interface{}
		want    string
	}{
		{"both ends", map[string]interface{}{"from": "open", "to": "closed"}, "open → closed"},
		{"only the new", map[string]interface{}{"new_status": "closed"}, "→ closed"},
		{"neither", map[string]interface{}{"finding_id": "F-1"}, "F-1"},
		{"nothing", map[string]interface{}{}, ""},
	} {
		got := auditChange(store.AuditEntry{Details: tc.details})
		if got != tc.want {
			t.Errorf("%s: change = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

// The decision log reads forward, and the briefing's own notes belong to the
// Briefing tab rather than filling the log with fragments of a summary.
func TestNotesReadForwardAndExcludeBriefing(t *testing.T) {
	base := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	table := tview.NewTable()
	renderNotes(table, []store.Note{
		{Content: "second decision", Author: "paolo", CreatedAt: base.Add(time.Hour)},
		{Content: "first decision", Author: "paolo", CreatedAt: base},
		{Content: `{"text":"a hypothesis"}`, LinkedType: string(store.NoteTypeHypothesis), CreatedAt: base},
	}, themeDark())

	got := tableCells(table)
	first, second := strings.Index(got, "first decision"), strings.Index(got, "second decision")
	if first < 0 || second < 0 {
		t.Fatalf("a decision is missing from the log\n%s", got)
	}
	if first > second {
		t.Errorf("the log reads backwards\n%s", got)
	}
	if strings.Contains(got, "a hypothesis") {
		t.Errorf("briefing content leaked into the decision log\n%s", got)
	}
}

// A multi-line note previews its first line; the log lists decisions and
// opening one shows the whole thing.
func TestNotePreviewIsOneLine(t *testing.T) {
	if got := firstLine("Isolated FIN-02.\nAuthorised by j.rivera."); strings.Contains(got, "\n") {
		t.Errorf("the preview spans lines: %q", got)
	}
	if got := firstLine("Isolated FIN-02.\nmore"); !strings.HasSuffix(got, "…") {
		t.Errorf("a truncated preview is not marked: %q", got)
	}
}

// An empty log names the next action rather than saying nothing.
func TestEmptyNotesNameTheNextAction(t *testing.T) {
	table := tview.NewTable()
	renderNotes(table, nil, themeDark())
	got := tableCells(table)
	for _, want := range []string{"No notes yet", "n to record", "t to start from a template"} {
		if !strings.Contains(got, want) {
			t.Errorf("the empty log is missing %q\n%s", want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

func timelineFixture() ([]store.Event, []store.Finding, []store.AuditEntry) {
	base := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	events := []store.Event{}
	// Six events on one host inside six minutes: one entry, not six.
	for i := 0; i < 6; i++ {
		events = append(events, store.Event{
			ID: string(rune('a' + i)), Timestamp: base.Add(time.Duration(i) * time.Minute),
			Host: "FIN-02", Message: "powershell -enc [redacted]",
		})
	}
	findings := []store.Finding{{Title: "C2 beaconing", FirstSeen: base.Add(30 * time.Minute)}}
	audit := []store.AuditEntry{{Timestamp: base.Add(time.Hour), Action: "status_changed", Actor: "paolo"}}
	return events, findings, audit
}

// The narrative reads forward, and the three sources stay distinguishable —
// a finding is a claim and an audit entry is what an analyst did, and neither
// is made clearer by being folded into "6 events".
func TestTimelineMergesAndOrders(t *testing.T) {
	events, findings, audit := timelineFixture()
	entries, _ := buildTimeline(events, findings, nil, audit, map[string]bool{}, groupByHost)

	if len(entries) != 3 {
		t.Fatalf("timeline has %d entries, want 3 (one cluster, one finding, one activity)\n%+v",
			len(entries), entries)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].At.Before(entries[i-1].At) {
			t.Errorf("entry %d is out of order", i)
		}
	}
	if entries[0].Kind != timelineEvent || entries[0].Count != 6 {
		t.Errorf("the six events did not cluster: %+v", entries[0])
	}
	if entries[1].Kind != timelineFinding || entries[2].Kind != timelineActivity {
		t.Errorf("the sources were merged into one kind: %+v", entries)
	}
}

// Clustering is stable: the same fixture twice reads the same way, or the
// timeline cannot be cited.
func TestTimelineIsStable(t *testing.T) {
	events, findings, audit := timelineFixture()
	a, _ := buildTimeline(events, findings, nil, audit, map[string]bool{}, groupByHost)
	b, _ := buildTimeline(events, findings, nil, audit, map[string]bool{}, groupByHost)

	if len(a) != len(b) {
		t.Fatalf("two runs gave %d and %d entries", len(a), len(b))
	}
	for i := range a {
		if a[i].Label != b[i].Label || !a[i].At.Equal(b[i].At) || a[i].Count != b[i].Count {
			t.Errorf("entry %d differs between runs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

// Each source gets its own glyph, not only its own colour.
func TestTimelineMarksAreDistinct(t *testing.T) {
	theme := themeDark()
	seen := map[string]timelineKind{}
	for _, k := range []timelineKind{timelineEvent, timelineFinding, timelineActivity} {
		glyph, _ := timelineMark(k, theme)
		if glyph == "" {
			t.Errorf("kind %d has no glyph", k)
		}
		if prev, dup := seen[glyph]; dup {
			t.Errorf("kinds %d and %d share the glyph %q", prev, k, glyph)
		}
		seen[glyph] = k
	}
}

// Event messages carry brackets — a command line, a JSON fragment — and the
// timeline must show them rather than let tview eat them as colour tags.
func TestTimelineEscapesEventText(t *testing.T) {
	events, findings, audit := timelineFixture()
	entries, _ := buildTimeline(events, findings, nil, audit, map[string]bool{"a": true}, groupByHost)
	table := tview.NewTable()
	rows := renderTimeline(table, entries, entries[0].Label, themeDark(), 0)

	got := tableCells(table)
	if !strings.Contains(got, "[redacted") {
		t.Errorf("the bracketed message was swallowed\n%s", got)
	}
	// The expanded cluster shows its members, and a pinned member is starred.
	if !strings.Contains(got, "★") {
		t.Errorf("a pinned event is not marked\n%s", got)
	}
	if len(rows) == 0 {
		t.Error("no row maps back to a cluster, so Enter would expand nothing")
	}
}

// The cap is stated on screen rather than silently applied.
func TestTimelineCapIsDeclared(t *testing.T) {
	base := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	entries := make([]timelineEntry, 0, timelineCap)
	for i := 0; i < timelineCap; i++ {
		entries = append(entries, timelineEntry{
			At: base.Add(time.Duration(i) * time.Second), Kind: timelineFinding,
			Label: "finding", Count: 1,
		})
	}
	table := tview.NewTable()
	renderTimeline(table, entries, "", themeDark(), 40)
	if got := tableCells(table); !strings.Contains(got, "40 further not shown") {
		t.Errorf("the cap was applied silently\n%s", got[len(got)-400:])
	}
}

// An empty timeline names the two ways to fill it.
func TestEmptyTimelineNamesTheNextAction(t *testing.T) {
	table := tview.NewTable()
	renderTimeline(table, nil, "", themeDark(), 0)
	got := tableCells(table)
	for _, want := range []string{"Nothing on the timeline yet", "'a' from the Events screen", "'e' from Triage"} {
		if !strings.Contains(got, want) {
			t.Errorf("the empty timeline is missing %q\n%s", want, got)
		}
	}
}

// The timeline folds repetitive audit the same way the Activity tab does —
// twelve identical lines bury the narrative it exists to tell.
func TestTimelineFoldsRepetitiveAudit(t *testing.T) {
	base := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	audit := []store.AuditEntry{}
	for i := 0; i < 12; i++ {
		audit = append(audit, store.AuditEntry{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Action:    "assign_event", Actor: "paolo",
		})
	}

	entries, _ := buildTimeline(nil, nil, nil, audit, map[string]bool{}, groupByHost)
	if len(entries) != 1 {
		t.Fatalf("twelve audit entries produced %d timeline rows, want 1", len(entries))
	}
	if !strings.Contains(entries[0].Label, "12 ×") {
		t.Errorf("the fold count is not in the label: %q", entries[0].Label)
	}
}

// The tab strip must degrade rather than truncate: at 80 columns the full
// framed form drops the last tabs off the end, so the analyst cannot see that
// Activity exists at all.
func TestTabStripKnowsWhenItDoesNotFit(t *testing.T) {
	names := []string{"Briefing", "Findings", "Events", "Timeline", "Indicators", "Notes", "Activity"}
	full := caseTabStripWidth(names, 0)
	if full <= 80 {
		t.Fatalf("the full strip measures %d columns; the narrow form would never engage", full)
	}
	if full > 150 {
		t.Errorf("the full strip measures %d columns and would not fit at 150 either", full)
	}
}

// The per-tab key handlers compare against these indices. They were once bare
// numbers written for a six-tab order, and when Briefing was added they all
// shifted by one — `n` fired on Indicators and did nothing on Notes. Pin the
// names to the list so the next insertion fails here rather than on screen.
func TestTabIndicesMatchTheirNames(t *testing.T) {
	for _, tc := range []struct {
		index int
		name  string
	}{
		{tabBriefing, "Briefing"},
		{tabFindings, "Findings"},
		{tabEvents, "Events"},
		{tabTimeline, "Timeline"},
		{tabIOCs, "Indicators"},
		{tabNotes, "Notes"},
		{tabActivity, "Activity"},
	} {
		if tc.index >= len(caseTabNames) || caseTabNames[tc.index] != tc.name {
			t.Errorf("index %d is %q, but the constant names %q",
				tc.index, caseTabNames[tc.index], tc.name)
		}
	}
	if len(caseTabNames) != tabActivity+1 {
		t.Errorf("%d tabs but the constants cover %d", len(caseTabNames), tabActivity+1)
	}
	// Every tab has a page and a focus pane, or switching to it draws nothing.
	if len(caseTabPages) != len(caseTabNames) {
		t.Errorf("%d tabs but %d page mappings", len(caseTabNames), len(caseTabPages))
	}
}

// The analyst's own notes belong on the timeline.
//
// A note is the only entry there somebody chose to make: "blocked the address
// at the firewall" explains the events above it and the absence of any below.
// Without it the timeline said what arrived and never what was done about it —
// and the same notes were already in the report, so the case screen was the one
// place they did not appear.
func TestNotesAppearOnTheTimeline(t *testing.T) {
	base := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)

	events := []store.Event{
		{ID: "e1", Message: "Outbound to 45.147.230.11", Host: "ws-14", Timestamp: base.Add(2 * time.Minute)},
	}
	findings := []store.Finding{
		{Title: "Confirmed C2 beaconing", FirstSeen: base},
	}
	notes := []store.Note{
		{Content: "Blocked 45.147.230.11 at the firewall", Author: "ashfaaq",
			CreatedAt: base.Add(50 * time.Minute)},
		{Content: "the statement, not a decision", LinkedType: store.NoteTypeStatement,
			CreatedAt: base.Add(10 * time.Minute)},
		{Content: "45.147.230.11", LinkedType: "ioc", CreatedAt: base.Add(20 * time.Minute)},
	}
	audit := []store.AuditEntry{
		{Action: "create_case", Actor: "ashfaaq", Timestamp: base.Add(time.Hour)},
	}

	entries, _ := buildTimeline(events, findings, notes, audit, map[string]bool{}, groupByHost)

	var kinds []timelineKind
	var labels []string
	for _, e := range entries {
		kinds = append(kinds, e.Kind)
		labels = append(labels, e.Label)
	}

	found := false
	for i, k := range kinds {
		if k == timelineNote {
			found = true
			if !strings.Contains(labels[i], "Blocked 45.147.230.11") {
				t.Errorf("the note on the timeline reads %q", labels[i])
			}
		}
	}
	if !found {
		t.Errorf("no note reached the timeline: %v", labels)
	}

	// The briefing belongs to the summary and an IOC to the indicators; neither
	// is part of the narrative.
	for _, l := range labels {
		if strings.Contains(l, "not a decision") || l == "45.147.230.11" {
			t.Errorf("a briefing or IOC note leaked into the timeline: %q", l)
		}
	}

	// And it lands in order, between the event and the case being opened.
	for i := 1; i < len(entries); i++ {
		if entries[i].At.Before(entries[i-1].At) {
			t.Errorf("the timeline runs backwards at entry %d", i)
		}
	}
}

// A note is marked as one, so it cannot be mistaken for something that happened
// on its own.
func TestANoteLooksLikeANote(t *testing.T) {
	glyph, _ := timelineMark(timelineNote, themeDark())
	if glyph == "" {
		t.Fatal("a note has no mark on the timeline")
	}
	for _, other := range []timelineKind{timelineEvent, timelineFinding, timelineActivity} {
		if g, _ := timelineMark(other, themeDark()); g == glyph {
			t.Errorf("a note is drawn the same as kind %v", other)
		}
	}
}
