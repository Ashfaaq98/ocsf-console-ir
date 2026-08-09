package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// columnTitles is the queue's header row as rendered.
func columnTitles(ui *UI) []string {
	var out []string
	for col := 0; col < ui.eventList.GetColumnCount(); col++ {
		if cell := ui.eventList.GetCell(0, col); cell != nil {
			out = append(out, cell.Text)
		}
	}
	return out
}

// cellUnder returns the row-1 value of a named column.
func cellUnder(ui *UI, title string) string {
	for col, c := range ui.triageColumns() {
		if c.title == title {
			if cell := ui.eventList.GetCell(1, col); cell != nil {
				return cell.Text
			}
		}
	}
	return ""
}

// triageAtWidth opens Triage, lays the queue out at a given width and repaints.
//
// The column set is read from the pane's inner rect, which tview only fills in
// once the widget has been drawn.
func triageAtWidth(t *testing.T, ui *UI, width int) {
	t.Helper()
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	renderPrimitive(t, ui.eventList, width, 20)
	ui.updateFindingsList(len(ui.findings))
}

// A finding already escalated says which case has it.
//
// The queue could not answer that without opening each finding in turn, and it
// is the first thing worth knowing: an escalated finding is someone's work, and
// triaging it again is duplicated effort.
func TestTheQueueSaysWhichCaseHasAFinding(t *testing.T) {
	ui, st := newTestUI(t)
	if _, err := st.CreateOrUpdateCase(context.Background(), store.Case{
		ID: "c1", Title: "Phish cluster", Status: "OPEN",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	seedTriageFinding(t, st, "escalated", "c1")

	triageAtWidth(t, ui, 150)

	if got := columnTitles(ui); !contains(got, "Case") {
		t.Fatalf("no Case column at 150 columns: %v", got)
	}
	if got := cellUnder(ui, "Case"); !strings.Contains(got, "Phish cluster") {
		t.Errorf("the Case column reads %q, want the case's title", got)
	}
}

// And an untriaged finding says it is in none, rather than showing a UUID or a
// blank that reads as missing data.
func TestTheQueueMarksAFindingInNoCase(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "loose", "")

	triageAtWidth(t, ui, 150)

	if got := cellUnder(ui, "Case"); got != "—" {
		t.Errorf("a finding in no case reads %q in the Case column, want a dash", got)
	}
}

// Case outranks Asset, Tactic and Source: it survives a narrower terminal than
// any of them. Display order and drop order are separate for exactly this.
func TestTheColumnLadderKeepsWhatMatters(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")

	for _, tc := range []struct {
		width int
		want  []string
	}{
		{150, []string{"!", "Risk", "Age", "Status", "Case", "Title", "Asset", "Tactic", "Source"}},
		{116, []string{"!", "Risk", "Age", "Status", "Case", "Title", "Asset", "Tactic"}},
		{100, []string{"!", "Risk", "Age", "Status", "Case", "Title", "Asset"}},
		{90, []string{"!", "Risk", "Age", "Status", "Title", "Asset"}},
		{70, []string{"!", "Risk", "Age", "Status", "Title"}},
	} {
		triageAtWidth(t, ui, tc.width+2) // +2 for the border
		got := columnTitles(ui)
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("at %d columns the queue shows %v, want %v", tc.width, got, tc.want)
		}
		// The title is what the queue is for, and it always expands.
		if !contains(got, "Title") {
			t.Errorf("at %d columns the queue has no Title column", tc.width)
		}
	}
}

// A narrow terminal says what it dropped.
//
// The queue drops columns rather than scrolling sideways — there is nothing off
// to the right to scroll to — and it dropped them silently, so a narrow
// terminal was indistinguishable from a build without those columns.
func TestTheQueueSaysWhatItDropped(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")

	triageAtWidth(t, ui, 72)
	narrow := ui.eventList.GetTitle()
	if !strings.Contains(narrow, "4 columns dropped to fit") {
		t.Errorf("a 70-column queue does not say what it dropped: %q", narrow)
	}

	triageAtWidth(t, ui, 152)
	wide := ui.eventList.GetTitle()
	if strings.Contains(wide, "dropped") {
		t.Errorf("a wide queue claims to have dropped columns: %q", wide)
	}
}

// The count of dropped columns is about width, and must not be confused with
// the count of findings a filter removed. Both can be true at once.
func TestDroppedColumnsAreNotFilteredRows(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	seedTriageFinding(t, st, "b", "")

	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	renderPrimitive(t, ui.eventList, 72, 20)
	ui.findingsUnfiltered = 5
	ui.updateFindingsList(2)

	got := ui.eventList.GetTitle()
	if !strings.Contains(got, "3 hidden by filters") {
		t.Errorf("the title lost the filter count: %q", got)
	}
	if !strings.Contains(got, "columns dropped to fit") {
		t.Errorf("the title lost the column count: %q", got)
	}
}
