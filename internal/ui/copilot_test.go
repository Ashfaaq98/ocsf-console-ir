package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// ---------------------------------------------------------------------------
// Suggestions
// ---------------------------------------------------------------------------

func fullCase() suggestionInput {
	base := time.Date(2026, 8, 1, 9, 12, 0, 0, time.UTC)
	return suggestionInput{
		Case: store.Case{Title: "C2 beaconing", FindingCount: 6},
		Brief: store.Briefing{
			Statement: "A phishing attachment led to encoded PowerShell and outbound C2.",
		},
		Events: []store.Event{
			{ID: "e1", Timestamp: base, Host: "workstation-14", UserName: "j.rivera"},
			{ID: "e2", Timestamp: base.Add(53 * time.Minute), Host: "dc-01"},
		},
		Findings:   []store.Finding{{Title: "C2 beaconing"}},
		Indicators: []store.CaseIndicator{{Type: "ip", Value: "198.51.100.73", Source: "asserted", Sightings: 5}},
		Notes:      []store.Note{{Content: "Isolated the host.", Author: "paolo"}},
	}
}

// A suggestion exists because of something true about this case. The four it
// replaced were the same four on every case, bound to keys that did nothing.
func TestSuggestionsCarryTheirReason(t *testing.T) {
	got := caseSuggestions(fullCase())
	if len(got) == 0 {
		t.Fatal("a case with hosts, indicators and findings offered nothing to ask")
	}
	for _, s := range got {
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("suggestion %q states no reason, so it is a guess", s.Text)
		}
		if strings.TrimSpace(s.Text) == "" {
			t.Error("a suggestion has no question")
		}
	}
}

// The statement prompt is the case's most pressing gap when it is missing, and
// must disappear once the gap is closed.
func TestStatementSuggestionTracksTheBriefing(t *testing.T) {
	withStatement := caseSuggestions(fullCase())
	for _, s := range withStatement {
		if strings.Contains(s.Text, "incident statement") {
			t.Errorf("a case that has a statement was still asked to draft one: %q", s.Text)
		}
	}

	in := fullCase()
	in.Brief.Statement = ""
	without := caseSuggestions(in)
	if len(without) == 0 || !strings.Contains(without[0].Text, "incident statement") {
		t.Errorf("a case with no statement does not lead with drafting one: %+v", without)
	}
	if !strings.Contains(without[0].Reason, "no statement") {
		t.Errorf("the reason does not name the gap: %q", without[0].Reason)
	}
}

// An empty case has nothing true to ask about except its emptiness — and must
// not invent facts to fill the list.
func TestSuggestionsForAnEmptyCase(t *testing.T) {
	got := caseSuggestions(suggestionInput{Case: store.Case{Title: "new"}})
	for _, s := range got {
		if strings.Contains(s.Text, "links") || strings.Contains(s.Text, "indicator") {
			t.Errorf("an empty case was offered %q, which references data it has none of", s.Text)
		}
	}
	if len(got) > maxSuggestions {
		t.Errorf("offered %d suggestions, over the cap of %d", len(got), maxSuggestions)
	}
}

// The list is capped, or it becomes a menu to read rather than a prompt to act
// on — and pushes the input field off a short drawer.
func TestSuggestionsAreCapped(t *testing.T) {
	in := fullCase()
	in.Brief.Statement = ""
	in.Notes = nil
	if got := caseSuggestions(in); len(got) > maxSuggestions {
		t.Errorf("a case matching every rule offered %d suggestions, cap is %d", len(got), maxSuggestions)
	}
}

// The most-sighted indicator is the one worth explaining, and an asserted claim
// outranks an inference on a tie.
func TestTopIndicatorPrefersWeightThenAssertion(t *testing.T) {
	got, ok := topIndicator([]store.CaseIndicator{
		{Value: "a", Source: "derived", Sightings: 2},
		{Value: "b", Source: "asserted", Sightings: 9},
		{Value: "c", Source: "asserted", Sightings: 2},
	})
	if !ok || got.Value != "b" {
		t.Errorf("top indicator = %+v, want the one with 9 sightings", got)
	}

	tie, _ := topIndicator([]store.CaseIndicator{
		{Value: "derived", Source: "derived", Sightings: 4},
		{Value: "asserted", Source: "asserted", Sightings: 4},
	})
	if tie.Value != "asserted" {
		t.Errorf("on a tie the %q one won; asserted should outrank derived", tie.Value)
	}

	if _, ok := topIndicator(nil); ok {
		t.Error("an empty indicator list reported a top indicator")
	}
}

// The renderer and the row mapping have to agree, or Enter on a suggestion
// asks a different question than the one under the cursor — or, as it did when
// the two disagreed, silently asks nothing at all.
func TestEverySuggestionIsReachableFromItsRow(t *testing.T) {
	suggestions := caseSuggestions(func() suggestionInput {
		in := fullCase()
		in.Brief.Statement = ""
		return in
	}())
	if len(suggestions) < 3 {
		t.Fatalf("fixture produced only %d suggestions", len(suggestions))
	}

	table := tview.NewTable()
	renderSuggestions(table, suggestions, themeDark())

	for i, want := range suggestions {
		row := suggestionRow(i)
		// The row the renderer drew on must map back to this suggestion.
		got, ok := suggestionForRow(row, suggestions)
		if !ok || got.Text != want.Text {
			t.Errorf("row %d maps to (%q, %v), but the renderer drew %q there",
				row, got.Text, ok, want.Text)
		}
		// And the cell there must actually carry that question. Compared with
		// the markup stripped: a question naming an address has that address
		// coloured, so the raw cell is no longer the plain sentence.
		cell := table.GetCell(row, 0)
		if cell == nil || !strings.Contains(stripTags(cell.Text), want.Text) {
			t.Errorf("row %d does not hold %q", row, want.Text)
		}
	}
}

// The cursor lands on a question, not on its reason or the blank line between.
func TestSuggestionRowMapping(t *testing.T) {
	suggestions := []copilotSuggestion{
		{Text: "first", Reason: "because"},
		{Text: "second", Reason: "because"},
	}
	table := tview.NewTable()
	renderSuggestions(table, suggestions, themeDark())

	for _, want := range []struct {
		row  int
		text string
		ok   bool
	}{
		{0, "", false}, // the heading
		{2, "first", true},
		{3, "", false}, // the reason under it
		{5, "second", true},
		{99, "", false},
	} {
		got, ok := suggestionForRow(want.row, suggestions)
		if ok != want.ok || got.Text != want.text {
			t.Errorf("row %d = (%q, %v), want (%q, %v)", want.row, got.Text, ok, want.text, want.ok)
		}
	}
}

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

func sampleChat() []llm.ChatMessage {
	return []llm.ChatMessage{
		{Role: "user", Content: "Explain 198.51.100.73"},
		{Role: "assistant", Content: "Seen 5 times, all outbound from workstation-14 on 443."},
	}
}

// Every generated line carries the rail. A transcript scrolls, so a label at
// the top of an answer is not on screen when the middle of it is.
func TestEveryGeneratedLineIsRailed(t *testing.T) {
	rows := buildTranscript(sampleChat(), 40, copilotStatus{})

	sawAssistant := false
	for _, r := range rows {
		if r.Message < 0 {
			continue
		}
		if sampleChat()[r.Message].Role == "assistant" {
			sawAssistant = true
			if !r.Rail {
				t.Errorf("a generated line has no rail: %q", r.Text)
			}
		}
	}
	if !sawAssistant {
		t.Fatal("the answer produced no rows at all")
	}
}

// The analyst's own words are never railed — the rail means "not yours".
func TestAnalystLinesAreNotRailed(t *testing.T) {
	for _, r := range buildTranscript(sampleChat(), 40, copilotStatus{}) {
		if r.Message == 0 && r.Rail {
			t.Errorf("the analyst's own question was marked as generated: %q", r.Text)
		}
	}
}

// A long answer wraps rather than running off the drawer, and every wrapped
// line keeps its rail.
func TestLongAnswerWrapsAndStaysRailed(t *testing.T) {
	long := strings.Repeat("beacon interval sixty seconds ", 20)
	rows := buildTranscript([]llm.ChatMessage{{Role: "assistant", Content: long}}, 40, copilotStatus{})

	railed := 0
	for _, r := range rows {
		if r.Rail {
			railed++
		}
		if len([]rune(r.Text)) > 40 {
			t.Errorf("a line is %d columns wide, over the 40 it has: %q", len([]rune(r.Text)), r.Text)
		}
	}
	if railed < 5 {
		t.Errorf("only %d lines carry the rail; the answer wrapped to more than that", railed)
	}
}

// A model's answer contains brackets, which tview reads as colour tags. In a
// table each cell escapes independently, so they survive.
func TestBracketsInAnswersSurvive(t *testing.T) {
	table := tview.NewTable()
	renderTranscript(table, buildTranscript([]llm.ChatMessage{
		{Role: "assistant", Content: "Run [Get-Process] to check."},
	}, 60, copilotStatus{}), themeDark())

	if got := tableCells(table); !strings.Contains(got, "Get-Process") {
		t.Errorf("the bracketed text was swallowed\n%s", got)
	}
}

// The route into the record is offered on the answer itself.
func TestAcceptIsOfferedOnTheAnswer(t *testing.T) {
	table := tview.NewTable()
	renderTranscript(table, buildTranscript(sampleChat(), 60, copilotStatus{}), themeDark())
	got := tableCells(table)
	for _, want := range []string{"a accept into notes", "r regenerate"} {
		if !strings.Contains(got, want) {
			t.Errorf("the transcript is missing %q\n%s", want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Provider and layout
// ---------------------------------------------------------------------------

// The panel used to claim "Provider: local" whatever was configured — a claim
// about where the case's text is being sent.
func TestProviderLineStatesWhatIsConfigured(t *testing.T) {
	if got := copilotProviderLine("ollama/qwen3:0.6b", true); !strings.Contains(got, "ollama/qwen3:0.6b") {
		t.Errorf("provider line = %q, want it to name the provider", got)
	}
	if got := copilotProviderLine("", true); !strings.Contains(got, "no provider") {
		t.Errorf("with nothing configured the line reads %q", got)
	}
	if got := copilotProviderLine("groq/llama-3.1", true); !strings.Contains(got, "scoped to this case") {
		t.Errorf("the line does not state the scope: %q", got)
	}
}

// The copilot may not squeeze the case below the smallest supported terminal.
func TestCopilotTakesTheScreenWhenItCannotShare(t *testing.T) {
	for _, tc := range []struct {
		width int
		full  bool
	}{
		{150, false}, // 106 left for the case
		{124, false}, // exactly 80 left
		{123, true},  // 79 left — below the floor
		{100, true},  // 56 left
		{80, true},   // 36 left, which is neither one thing nor the other
	} {
		if got := copilotFullScreen(tc.width); got != tc.full {
			t.Errorf("at %d columns full-screen = %v, want %v (case would get %d)",
				tc.width, got, tc.full, tc.width-copilotDrawerWidth)
		}
	}
}

// A request that never came back must say so in the transcript. The status bar
// is transient — the next message overwrites it — leaving a question on screen
// with nothing after it, which reads as an answer nobody gave.
func TestFailureIsReportedInTheTranscript(t *testing.T) {
	rows := buildTranscript(sampleChat()[:1], 60,
		copilotStatus{Failure: "ollama: context deadline exceeded"})

	var text string
	failed := false
	for _, r := range rows {
		text += r.Text + "\n"
		if r.Failed {
			failed = true
			if r.Rail {
				t.Error("a failure was railed; the rail means generated content")
			}
		}
	}
	if !failed {
		t.Fatalf("no row is marked as failed\n%s", text)
	}
	for _, want := range []string{"No answer", "context deadline exceeded", "r retry"} {
		if !strings.Contains(text, want) {
			t.Errorf("the failure report is missing %q\n%s", want, text)
		}
	}
}

// An in-flight request is visible in the transcript too, for the same reason.
func TestPendingIsVisibleInTheTranscript(t *testing.T) {
	rows := buildTranscript(sampleChat()[:1], 60, copilotStatus{Pending: true})
	found := false
	for _, r := range rows {
		if strings.Contains(r.Text, "thinking") {
			found = true
		}
	}
	if !found {
		t.Error("an in-flight request leaves the transcript showing only the question")
	}
}

// A settled request reports neither, so the transcript is not permanently
// decorated with a state it is no longer in.
func TestSettledRequestReportsNothing(t *testing.T) {
	for _, r := range buildTranscript(sampleChat(), 60, copilotStatus{}) {
		if r.Failed || strings.Contains(r.Text, "thinking") {
			t.Errorf("a settled transcript still reports a state: %q", r.Text)
		}
	}
}

// An accepted answer becomes part of the record: it appears in the decision log
// under the analyst who accepted it, and says where the words came from.
//
// Briefing-typed notes are filtered out of that log, so an accepted answer must
// not be typed as one — it would vanish the moment it was accepted.
func TestAcceptedAnswerReachesTheDecisionLog(t *testing.T) {
	accepted := store.Note{
		CaseID: "c1", Content: "Seen 5 times, all outbound from workstation-14.",
		Author: "paolo", LinkedType: "copilot",
		CreatedAt: time.Date(2026, 8, 1, 11, 0, 0, 0, time.UTC),
	}
	if store.IsBriefingNote(accepted) {
		t.Fatal("an accepted answer is typed as briefing content, so the log would hide it")
	}

	table := tview.NewTable()
	renderNotes(table, []store.Note{accepted}, themeDark())
	got := tableCells(table)

	for _, want := range []string{"Seen 5 times", "paolo", "copilot"} {
		if !strings.Contains(got, want) {
			t.Errorf("the decision log is missing %q\n%s", want, got)
		}
	}
}

// Nothing reaches the record on its own. The transcript's only route in is the
// accept key, so an unaccepted answer leaves the log as it was.
func TestUnacceptedAnswersStayOutOfTheRecord(t *testing.T) {
	table := tview.NewTable()
	renderNotes(table, nil, themeDark())
	if got := tableCells(table); !strings.Contains(got, "No notes yet") {
		t.Errorf("a case with an unaccepted answer does not show an empty log\n%s", got)
	}
}
