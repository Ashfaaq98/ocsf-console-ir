package ui

import (
	"fmt"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

// The copilot transcript is a table, one row per rendered line.
//
// Not a TextView, for a reason that has cost a cycle before: a model's answer
// contains brackets — a command line, a path, a JSON fragment — and escaping
// those inside one multi-line TextView makes tview's tag state drift, putting a
// stray "]" at the head of every following line. Table cells do not share tag
// state, so each line is escaped independently.
//
// Generated lines carry a rail down the left. Not a single label at the top: a
// transcript scrolls, and half an answer read on its own must still be
// identifiable as the model's rather than the analyst's.

// copilotRail marks every generated line.
const copilotRail = "┃"

// copilotRailASCII is the fallback where the box-drawing glyph will not render.
const copilotRailASCII = "|"

// transcriptRow is one rendered line, and which message it belongs to.
type transcriptRow struct {
	// Message indexes chatHistory, or -1 for a line that stands alone.
	Message int
	Rail    bool
	Text    string
	Muted   bool
	// Failed marks the report of a request that did not come back.
	Failed bool
}

// copilotStatus is what became of the most recent question.
//
// It belongs in the transcript rather than the status bar. A status line is
// transient — the next message overwrites it — so a request that timed out
// leaves a question on screen with nothing after it, indistinguishable from one
// nobody answered.
type copilotStatus struct {
	Pending bool
	Failure string
}

// buildTranscript lays the chat out as rows at a given width.
func buildTranscript(history []llm.ChatMessage, width int, st copilotStatus) []transcriptRow {
	if width < 20 {
		width = 20
	}
	rows := []transcriptRow{}

	for i, msg := range history {
		switch msg.Role {
		case "user":
			// The analyst's own question, marked as theirs and never railed.
			for j, line := range wrapText(msg.Content, width-2) {
				prefix := "› "
				if j > 0 {
					prefix = "  "
				}
				rows = append(rows, transcriptRow{Message: i, Text: prefix + line})
			}
		case "assistant":
			for _, line := range wrapText(msg.Content, width-2) {
				rows = append(rows, transcriptRow{Message: i, Rail: true, Text: line})
			}
			// The actions belong to the answer, so they sit inside the rail.
			rows = append(rows,
				transcriptRow{Message: i, Rail: true, Text: ""},
				transcriptRow{Message: i, Rail: true, Muted: true,
					Text: "a accept into notes    r regenerate"})
		default:
			continue
		}
		rows = append(rows, transcriptRow{Message: -1, Text: ""})
	}

	switch {
	case st.Pending:
		rows = append(rows, transcriptRow{Message: -1, Muted: true, Text: "  thinking…"})
	case st.Failure != "":
		// Not railed: a failure is not generated content, and marking it as
		// though it were would make the rail mean two things.
		for i, line := range wrapText("No answer — "+st.Failure, width-2) {
			text := "  " + line
			if i == 0 {
				text = "✕ " + line
			}
			rows = append(rows, transcriptRow{Message: -1, Failed: true, Text: text})
		}
		rows = append(rows,
			transcriptRow{Message: -1, Text: ""},
			transcriptRow{Message: -1, Failed: true, Muted: true, Text: "  r retry"})
	}
	return rows
}

// renderTranscript draws the rows.
func renderTranscript(table *tview.Table, rows []transcriptRow, t Theme) {
	table.Clear()

	rail := copilotRail
	if !supportsUnicode() {
		rail = copilotRailASCII
	}

	for i, r := range rows {
		mark := " "
		if r.Rail {
			mark = rail
		}
		table.SetCell(i, 0, tview.NewTableCell(" "+mark).
			SetTextColor(t.Accent).SetSelectable(false))

		colour := t.TextPrimary
		switch {
		case r.Failed && r.Muted:
			colour = t.TextMuted
		case r.Failed:
			colour = t.Error
		case r.Muted:
			colour = t.TextMuted
		}
		// A model's answer names hosts, addresses and files; colouring them is
		// also a small check on it — an address it invented reads as an
		// address, and you can pivot on it to find there is nothing there.
		table.SetCell(i, 1, tview.NewTableCell(paintTextOn(r.Text, tagColor(colour), t)).
			SetTextColor(colour).SetExpansion(1))
	}
	table.ScrollToEnd()
}

// renderSuggestions draws the opening list.
func renderSuggestions(table *tview.Table, suggestions []copilotSuggestion, t Theme) {
	table.Clear()

	if len(suggestions) == 0 {
		table.SetCell(0, 0, tview.NewTableCell(" Ask anything about this case.").
			SetTextColor(t.TextMuted).SetSelectable(false).SetExpansion(1))
		return
	}

	table.SetCell(0, 0, tview.NewTableCell(" SUGGESTED").
		SetTextColor(t.TableHeader).SetSelectable(false).SetExpansion(1))

	// Three rows each — question, reason, gap — which is the stride
	// suggestionForRow inverts. Only the question is selectable, so the cursor
	// moves between questions rather than through their reasons.
	for i, s := range suggestions {
		row := suggestionRow(i)
		table.SetCell(row, 0, tview.NewTableCell(" "+paintTextOn(s.Text, tagColor(t.TextPrimary), t)).
			SetTextColor(t.TextPrimary).SetExpansion(1))
		table.SetCell(row+1, 0, tview.NewTableCell("   "+tview.Escape(s.Reason)).
			SetTextColor(t.TextMuted).SetSelectable(false).SetExpansion(1))
		table.SetCell(row+2, 0, tview.NewTableCell("").SetSelectable(false))
	}

	// The list is only useful if its keys are on screen with it.
	table.SetCell(suggestionRow(len(suggestions)), 0, tview.NewTableCell(
		" ↑↓ choose · Enter ask · or just type").
		SetTextColor(t.TextMuted).SetSelectable(false).SetExpansion(1))
}

// suggestionRow is where the nth question is drawn.
func suggestionRow(i int) int { return 2 + i*3 }

// suggestionForRow maps a cursor position back to the suggestion it names.
//
// The list interleaves each question with its reason and a blank line, so the
// arithmetic lives here rather than being repeated at every call site.
func suggestionForRow(row int, suggestions []copilotSuggestion) (copilotSuggestion, bool) {
	// Row 0 is the heading; suggestionRow places the nth question at 2+3n.
	idx := (row - 2) / 3
	if row < 2 || (row-2)%3 != 0 || idx >= len(suggestions) {
		return copilotSuggestion{}, false
	}
	return suggestions[idx], true
}

// copilotProviderLine names the provider actually in use.
//
// The panel used to state "Provider: local" whatever was configured, which is a
// claim about where the case's text is being sent.
func copilotProviderLine(active string, scoped bool) string {
	name := strings.TrimSpace(active)
	if name == "" {
		name = "no provider configured"
	}
	if !scoped {
		return name
	}
	return fmt.Sprintf("%s · scoped to this case", name)
}

// activeLLMProvider names the configured provider and model.
//
// Never the API key: this line is on screen whenever the drawer is open.
func activeLLMProvider() string {
	settings, err := llm.LoadSettings(paths.Current().ConfigFile(paths.LLMSettingsName))
	if err != nil {
		return ""
	}
	provider := strings.TrimSpace(settings.Active.Provider)
	model := strings.TrimSpace(settings.Active.Model)
	switch {
	case provider == "":
		return ""
	case model == "":
		return provider
	}
	return provider + "/" + model
}

// showCopilotSuggestions draws the opening list, derived from the case.
func (cm *CaseManagement) showCopilotSuggestions() {
	if cm.copilotSuggestions == nil {
		return
	}
	brief, err := cm.store.GetBriefing(cm.ctx, cm.caseData.ID)
	if err != nil && cm.logger != nil {
		cm.logger.Warn("copilot: could not read the briefing for suggestions: %v", err)
	}
	findings, err := cm.store.GetCaseFindings(cm.ctx, cm.caseData.ID)
	if err != nil && cm.logger != nil {
		cm.logger.Warn("copilot: could not read case findings for suggestions: %v", err)
	}

	cm.suggestions = caseSuggestions(suggestionInput{
		Case: cm.caseData, Brief: brief, Events: cm.events,
		Findings: findings, Indicators: cm.caseIndicators, Notes: cm.notes,
	})
	renderSuggestions(cm.copilotSuggestions, cm.suggestions, cm.theme)
	cm.copilotPages.SwitchToPage("suggestions")
}

// askSuggestion sends the suggestion under the cursor.
func (cm *CaseManagement) askSuggestion(row int) {
	s, ok := suggestionForRow(row, cm.suggestions)
	if !ok {
		return
	}
	cm.processCopilotMessage(s.Text)
}

// assistantAt finds the answer the cursor is inside, so `a` and `r` act on the
// one being read rather than always the last.
func (cm *CaseManagement) assistantAt(row int) (int, bool) {
	rows := buildTranscript(cm.chatHistory, cm.copilotTextWidth(), cm.copilotStatus)
	if row < 0 || row >= len(rows) {
		return 0, false
	}
	idx := rows[row].Message
	if idx < 0 || idx >= len(cm.chatHistory) || cm.chatHistory[idx].Role != "assistant" {
		return 0, false
	}
	return idx, true
}

// acceptCopilotAnswer writes an answer into the case notes.
//
// This is the only route from the transcript into the record, and it takes a
// keypress on a chosen answer. The note is linked as copilot-sourced, so the
// record says where the words came from without the reader having to remember.
func (cm *CaseManagement) acceptCopilotAnswer() {
	row, _ := cm.copilotTranscript.GetSelection()
	idx, ok := cm.assistantAt(row)
	if !ok {
		cm.updateStatus("Put the cursor on an answer to accept it")
		return
	}

	note := store.Note{
		CaseID:     cm.caseData.ID,
		Content:    cm.chatHistory[idx].Content,
		Author:     cm.getCurrentAnalyst(),
		LinkedType: "copilot",
	}
	go func() {
		_, err := cm.store.AddNote(cm.ctx, note)
		cm.app.QueueUpdateDraw(func() {
			if err != nil {
				cm.updateStatus(fmt.Sprintf("Could not save the note: %v", err))
				return
			}
			cm.updateStatus("Accepted into notes")
			cm.refreshNotes()
		})
	}()
}

// regenerateCopilotAnswer asks the question again.
func (cm *CaseManagement) regenerateCopilotAnswer() {
	// A question that failed has no answer to sit on, so `r` retries the last
	// one asked rather than requiring a cursor position that does not exist.
	if cm.copilotStatus.Failure != "" {
		for i := len(cm.chatHistory) - 1; i >= 0; i-- {
			if cm.chatHistory[i].Role == "user" {
				question := cm.chatHistory[i].Content
				cm.chatHistory = cm.chatHistory[:i]
				cm.processCopilotMessage(question)
				return
			}
		}
		return
	}

	row, _ := cm.copilotTranscript.GetSelection()
	idx, ok := cm.assistantAt(row)
	if !ok {
		cm.updateStatus("Put the cursor on an answer to regenerate it")
		return
	}
	// The question that produced it is the preceding user message.
	for i := idx - 1; i >= 0; i-- {
		if cm.chatHistory[i].Role == "user" {
			question := cm.chatHistory[i].Content
			// Drop the answer being replaced, so the transcript does not grow a
			// second copy of a question already asked.
			cm.chatHistory = cm.chatHistory[:idx]
			cm.updateCopilotTranscript()
			cm.processCopilotMessage(question)
			return
		}
	}
	cm.updateStatus("No question found for that answer")
}

// refreshNotes re-reads the notes and repaints what depends on them.
//
// The Notes tab, the header's next-action prompt and the copilot's suggestions
// all read the same list, so one write has to reach all three.
func (cm *CaseManagement) refreshNotes() {
	notes, err := cm.store.GetNotes(cm.ctx, cm.caseData.ID)
	if err != nil {
		if cm.logger != nil {
			cm.logger.Warn("could not re-read the case notes: %v", err)
		}
		return
	}
	cm.notes = notes
	cm.updateNotesText()
	cm.updateMetadataBar()
}

// focusCopilotEntry puts the cursor where the analyst's next keystroke belongs:
// on the suggestions while they are the whole panel, on the input once there is
// a conversation to continue.
func (cm *CaseManagement) focusCopilotEntry() {
	if len(cm.chatHistory) == 0 && len(cm.suggestions) > 0 && cm.copilotSuggestions != nil {
		cm.copilotSuggestions.Select(suggestionRow(0), 0)
		cm.app.SetFocus(cm.copilotSuggestions)
		return
	}
	if cm.copilotInput != nil {
		cm.app.SetFocus(cm.copilotInput)
	}
}

// copilotTextWidth is the room an answer has to wrap in.
//
// The transcript's own rect is unusable on the frame it is switched into view —
// tview computes rects during Draw — and a stale zero clamps the wrap to its
// 20-column floor, breaking a sentence over four lines in a 42-column panel.
// The drawer's width is known without asking, so it is the fallback.
func (cm *CaseManagement) copilotTextWidth() int {
	// The rail column plus the panel's two borders.
	const chrome = 4

	if cm.copilotFull && cm.layout != nil {
		if _, _, w, _ := cm.layout.GetInnerRect(); w > copilotDrawerWidth {
			return w - chrome
		}
	}
	if cm.copilotTranscript != nil {
		if _, _, w, _ := cm.copilotTranscript.GetInnerRect(); w > 20 {
			return w - 2
		}
	}
	return copilotDrawerWidth - chrome
}
