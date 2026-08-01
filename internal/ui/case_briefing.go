package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The Briefing is what an analyst would say to a colleague.
//
// It replaced two things. The case tab called "Overview" listed the case's
// title, description, status and time span — facts the analyst already had,
// since they opened this case. And the Cases screen rendered a briefing whose
// hypotheses were *hardcoded strings*: every case, whatever it held, was
// "Confirmed: Suspicious execution via PowerShell on FIN-02". Fabricated
// analysis presented as the case's own is worse than an empty tab.
//
// One renderer serves both, so the two can no longer disagree about a case.

// No escaped brackets anywhere in this file.
//
// The briefing is one scrollable TextView, and tview's escaped-tag state drifts
// across the lines of a single TextView — a "[H] add one" on row six put a
// stray "]" at the start of row seven. The house style already avoids the
// problem: renderKey colours the key instead of bracketing it, which is what
// the action bars on every other screen do.

// briefingTwoColumnWidth is where the layout splits into two columns.
const briefingTwoColumnWidth = 104

// briefingData is everything the briefing draws from.
type briefingData struct {
	Case   store.Case
	Brief  store.Briefing
	Events []store.Event
	Pinned map[string]bool
}

// loadBriefing gathers a case's briefing. Errors are returned rather than
// rendered, so each caller can degrade its own way.
func (ui *UI) loadBriefing(c store.Case) (briefingData, error) {
	d := briefingData{Case: c, Pinned: map[string]bool{}}

	brief, err := ui.store.GetBriefing(ui.ctx, c.ID)
	if err != nil {
		return d, err
	}
	d.Brief = brief

	if events, err := ui.store.GetCaseEventMembers(ui.ctx, c.ID); err == nil {
		d.Events = events
	}
	if pinned, err := ui.store.GetPinnedMemberIDs(ui.ctx, c.ID, store.MemberTypeEvent); err == nil {
		d.Pinned = pinned
	}
	return d, nil
}

// renderBriefing writes the briefing as marked-up text.
func renderBriefing(d briefingData, t Theme, width int) string {
	var b strings.Builder

	briefingStatement(&b, d, t, width)
	b.WriteString("\n")

	scope := scopeLines(d, t)
	hypotheses := hypothesisLines(d.Brief, t)
	actions := nextActionLines(d.Brief, t)
	summary := summaryLines(d.Brief, t, width/2)

	if width >= briefingTwoColumnWidth {
		briefingHeadings(&b, t, "SCOPE", "WORKING HYPOTHESES", width/2)
		briefingColumns(&b, scope, hypotheses, width/2)
		b.WriteString("\n")
		briefingHeadings(&b, t, "NEXT ACTIONS", "AI SUMMARY  ·  generated, not case truth", width/2)
		briefingColumns(&b, actions, summary, width/2)
	} else {
		briefingBlock(&b, t, "SCOPE", scope)
		briefingBlock(&b, t, "WORKING HYPOTHESES", hypotheses)
		briefingBlock(&b, t, "NEXT ACTIONS", actions)
		briefingBlock(&b, t, "AI SUMMARY  ·  generated, not case truth", summary)
	}

	if pinned := pinnedEvidenceLines(d, t); len(pinned) > 0 {
		b.WriteString("\n")
		briefingBlock(&b, t, "PINNED EVIDENCE", pinned)
	}
	return b.String()
}

// briefingStatement writes the incident statement, or asks for one.
func briefingStatement(b *strings.Builder, d briefingData, t Theme, width int) {
	fmt.Fprintf(b, "\n [%s]INCIDENT STATEMENT[-]\n", t.TagMuted)

	if s := strings.TrimSpace(d.Brief.Statement); s != "" {
		for _, line := range wrapText(s, maxInt(width-4, 30)) {
			fmt.Fprintf(b, " [%s]%s[-]\n", t.TagTextPrimary, tview.Escape(line))
		}
		return
	}
	// This is what every existing case shows on first open, so it has to be
	// worth reading rather than a blank.
	fmt.Fprintf(b, " [%s]No statement yet — one sentence on what happened, so the next person[-]\n", t.TagMuted)
	fmt.Fprintf(b, " [%s]does not have to reconstruct it from the evidence.[-]   %s\n",
		t.TagMuted, renderKey("S", "write one", t))
}

// scopeLines summarises what the case covers.
func scopeLines(d briefingData, t Theme) []string {
	hosts, users, first, last := scopeOf(d.Events)

	row := func(label, value string) string {
		return fmt.Sprintf("  [%s]%-9s[-] [%s]%s[-]", t.TagMuted, label, t.TagTextPrimary, tview.Escape(value))
	}
	window := "—"
	if !first.IsZero() {
		window = first.Format("15:04") + " – " + last.Format("15:04")
	}
	return []string{
		row("hosts", orNone(strings.Join(hosts, ", "))),
		row("users", orNone(strings.Join(users, ", "))),
		row("window", window),
		row("counts", fmt.Sprintf("%d findings · %d evidence", d.Case.FindingCount, len(d.Events))),
	}
}

// scopeOf derives the hosts, users and time window a set of events covers.
func scopeOf(events []store.Event) (hosts, users []string, first, last time.Time) {
	hostSet, userSet := map[string]bool{}, map[string]bool{}
	for _, e := range events {
		if h := strings.TrimSpace(e.Host); h != "" {
			hostSet[h] = true
		}
		if u := strings.TrimSpace(e.UserName); u != "" {
			userSet[u] = true
		}
		if first.IsZero() || e.Timestamp.Before(first) {
			first = e.Timestamp
		}
		if e.Timestamp.After(last) {
			last = e.Timestamp
		}
	}
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	for u := range userSet {
		users = append(users, u)
	}
	// Sorted, so the same case reads the same way twice.
	sort.Strings(hosts)
	sort.Strings(users)
	return hosts, users, first, last
}

// hypothesisLines renders beliefs with their confidence.
func hypothesisLines(brief store.Briefing, t Theme) []string {
	if len(brief.Hypotheses) == 0 {
		return []string{fmt.Sprintf("  [%s]Nothing recorded.[-]   %s", t.TagMuted, renderKey("H", "add one", t))}
	}
	out := make([]string, 0, len(brief.Hypotheses))
	for _, h := range brief.Hypotheses {
		glyph, colour, label := confidenceMark(h.Confidence, t)
		out = append(out, fmt.Sprintf("  [%s]%s %-9s[-] [%s]%s[-]",
			colour, glyph, label, t.TagTextPrimary, tview.Escape(h.Text)))
	}
	return out
}

// confidenceMark maps a confidence to a glyph, a colour and a label.
//
// A glyph as well as a colour: how sure an analyst is about a belief is exactly
// the thing that has to survive a 16-colour terminal.
func confidenceMark(confidence string, t Theme) (glyph, colour, label string) {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case store.ConfidenceConfirmed:
		return "●", t.TagSuccess, "Confirmed"
	case store.ConfidenceLikely:
		return "▲", t.TagWarning, "Likely"
	default:
		return "◆", t.TagMuted, "Open"
	}
}

// nextActionLines renders the checklist.
func nextActionLines(brief store.Briefing, t Theme) []string {
	if len(brief.NextActions) == 0 {
		return []string{fmt.Sprintf("  [%s]Nothing outstanding.[-]   %s", t.TagMuted, renderKey("A", "add one", t))}
	}
	out := make([]string, 0, len(brief.NextActions))
	for _, a := range brief.NextActions {
		// A glyph rather than "[x]": brackets would have to be escaped, and an
		// escaped bracket here drifts onto the next line.
		box, colour := "○", t.TagTextPrimary
		if a.Done {
			box, colour = "✓", t.TagSuccess
		}
		out = append(out, fmt.Sprintf("  [%s]%s[-] [%s]%s[-]", colour, box, t.TagTextPrimary, tview.Escape(a.Text)))
	}
	return out
}

// summaryLines renders the generated summary, always labelled as generated.
func summaryLines(brief store.Briefing, t Theme, width int) []string {
	if !brief.HasSummary || strings.TrimSpace(brief.Summary) == "" {
		return []string{fmt.Sprintf("  [%s]None generated.[-]   %s", t.TagMuted, renderKey("g", "generate", t))}
	}
	out := []string{}
	for _, line := range wrapText(brief.Summary, maxInt(width-4, 24)) {
		out = append(out, fmt.Sprintf("  [%s]%s[-]", t.TagTextPrimary, tview.Escape(line)))
	}
	// The only route from generated text into the case record, and it takes a
	// deliberate action.
	out = append(out, "", "  "+actionBar(t,
		keyHint{"a", "accept into notes"}, keyHint{"r", "regenerate"}))
	return out
}

// pinnedEvidenceLines lists the evidence the analyst marked as decisive.
func pinnedEvidenceLines(d briefingData, t Theme) []string {
	if len(d.Pinned) == 0 {
		return nil
	}
	out := []string{}
	for _, e := range d.Events {
		if !d.Pinned[e.ID] {
			continue
		}
		out = append(out, fmt.Sprintf("  [%s]★[-] [%s]%s[-]  [%s]%s[-]",
			t.TagWarning, t.TagMuted, e.Timestamp.Format("15:04:05"),
			t.TagTextPrimary, tview.Escape(truncate(e.Message, 76))))
	}
	return out
}

// briefingBlock writes a titled block at full width.
func briefingBlock(b *strings.Builder, t Theme, title string, lines []string) {
	fmt.Fprintf(b, "\n [%s]%s[-]\n", t.TagMuted, title)
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
}

// briefingHeadings writes two block titles side by side.
func briefingHeadings(b *strings.Builder, t Theme, left, right string, col int) {
	l := fmt.Sprintf(" [%s]%s[-]", t.TagMuted, left)
	fmt.Fprintf(b, "%s%s [%s]%s[-]\n", l, strings.Repeat(" ", pad(visibleWidth(l), col)), t.TagMuted, right)
}

// briefingColumns writes two blocks side by side.
//
// Padding counts *visible* columns rather than bytes: every line here carries
// colour markup, and one tag is a dozen bytes wide and zero columns wide.
func briefingColumns(b *strings.Builder, left, right []string, col int) {
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	for i := 0; i < n; i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		b.WriteString(l + strings.Repeat(" ", pad(visibleWidth(l), col)) + r + "\n")
	}
}

// pad returns the spaces needed to reach a column, never fewer than one.
func pad(have, want int) int {
	if have >= want {
		return 1
	}
	return want - have
}

// visibleWidth counts the columns a marked-up string occupies, ignoring colour
// tags and counting an escaped bracket as the one character it renders as.
func visibleWidth(s string) int {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetText(s)
	return len([]rune(strings.TrimRight(tv.GetText(true), "\n")))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// buildCaseBriefingTab renders a case's briefing for the Cases screen.
func (ui *UI) buildCaseBriefingTab(c store.Case) *tview.Flex {
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	flex.SetBackgroundColor(ui.theme.Bg)

	view := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	stylePanel(view.Box, "BRIEFING  ·  "+truncate(c.Title, 48), PanelRolePrimary, ui.theme)
	view.SetBackgroundColor(ui.theme.Bg)

	d, err := ui.loadBriefing(c)
	if err != nil {
		view.SetText(fmt.Sprintf("\n [%s]Could not load the briefing.[-]\n [%s]%s[-]\n\n [%s]%s[-]",
			ui.theme.TagError, ui.theme.TagMuted, tview.Escape(err.Error()),
			ui.theme.TagAccent, renderKey("r", "Retry", ui.theme)))
		flex.AddItem(view, 0, 1, true)
		return flex
	}

	// The width is not known until the first draw, so the text is rebuilt then.
	view.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		view.SetText(renderBriefing(d, ui.theme, width-2))
		return x, y, width, height
	})

	flex.AddItem(view, 0, 1, true)
	return flex
}
