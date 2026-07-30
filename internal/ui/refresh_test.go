package ui

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

func refreshTestUI(t *testing.T, st *store.Store, ctx context.Context) *UI {
	t.Helper()
	return NewUI(ctx, st, llm.NewLocalStub(), logging.New(io.Discard, logging.LevelDebug, "test"), "test")
}

// seedFinding stores a Detection Finding so the queue has something to render.
func seedFinding(t *testing.T, st *store.Store, ctx context.Context, uid, title string) {
	t.Helper()
	_, err := st.SaveFinding(ctx, &ocsf.Finding{
		Event: ocsf.Event{
			Time:        time.Now(),
			ClassUID:    2004,
			CategoryUID: 2,
			ActivityID:  1,
			TypeUID:     200401,
			SeverityID:  4,
			Message:     title,
		},
		FindingInfo: ocsf.FindingInfo{UID: uid, Title: title},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The regression test for the theme bug: the findings queue and the events list
// share one table widget, so a render-only refresh must dispatch on which view
// is open. applyTheme called updateEventsList unconditionally, wiping findings
// off the screen on every theme change.
func TestRepaintCurrentListDispatchesOnOpenView(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	seedFinding(t, st, ctx, "f-1", "Encoded PowerShell on workstation-14")
	ui := refreshTestUI(t, st, ctx)
	ui.events = []store.Event{{ID: "evt_1", Message: "an ordinary event"}}
	ui.findings = []store.Finding{{ID: "fnd_1", Title: "Encoded PowerShell on workstation-14", Severity: "critical"}}
	ui.findingsTotal = 1

	// Findings mode: a repaint must keep findings on screen.
	ui.showFindings = true
	ui.repaintCurrentList()
	if got := tableText(ui); !strings.Contains(got, "Encoded PowerShell") {
		t.Errorf("repaint dropped the findings queue:\n%s", got)
	}
	if strings.Contains(tableText(ui), "an ordinary event") {
		t.Errorf("repaint showed events while the findings queue was open:\n%s", tableText(ui))
	}

	// Events mode: the same call must render events.
	ui.showFindings = false
	ui.repaintCurrentList()
	if got := tableText(ui); !strings.Contains(got, "an ordinary event") {
		t.Errorf("repaint dropped the events list:\n%s", got)
	}
}

// applyTheme is the caller that had the bug; assert it goes through the helper
// rather than only testing the helper in isolation.
func TestApplyThemeKeepsTheFindingsQueue(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	ui := refreshTestUI(t, st, ctx)
	ui.events = []store.Event{{ID: "evt_1", Message: "an ordinary event"}}
	ui.findings = []store.Finding{{ID: "fnd_1", Title: "Impossible travel for m.chen", Severity: "medium"}}
	ui.findingsTotal = 1
	ui.showFindings = true

	ui.setTheme("light")

	got := tableText(ui)
	if !strings.Contains(got, "Impossible travel") {
		t.Errorf("switching theme replaced the findings queue with events:\n%s", got)
	}
	if strings.Contains(got, "an ordinary event") {
		t.Errorf("events leaked into the findings queue after a theme change:\n%s", got)
	}
}

// tableText flattens the shared table widget so assertions read what is on
// screen rather than which function was called.
func tableText(ui *UI) string {
	var sb strings.Builder
	rows, cols := ui.eventList.GetRowCount(), ui.eventList.GetColumnCount()
	for r := 0; r < rows; r++ {
		for c := 0; c < cols; c++ {
			if cell := ui.eventList.GetCell(r, c); cell != nil {
				sb.WriteString(cell.Text)
				sb.WriteString(" ")
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
