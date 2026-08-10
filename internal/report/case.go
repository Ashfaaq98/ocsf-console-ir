// Package report turns what a case holds into a document someone can read.
//
// Plain Markdown, deliberately: it pastes into a ticket, renders on GitHub,
// converts to PDF or Word if a client asks, and stays readable in a terminal if
// nobody converts it at all. HTML would look better in one place and worse in
// the other four.
//
// Nothing here touches a database, a clock or a screen. A report is a pure
// function of what it is given, so it can be checked by comparing text — which
// is the only way to know a report says what it should before sending it to
// somebody's client.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// CaseReport is everything one case report is written from.
//
// Passed in rather than fetched, including the time: a report generated twice
// from the same inputs must be the same document, or there is no way to test it
// and no way to say what was sent.
type CaseReport struct {
	Case       store.Case
	Briefing   store.Briefing
	Findings   []store.Finding
	Events     []store.Event
	Notes      []store.Note
	Audit      []store.AuditEntry
	Indicators []store.CaseIndicator

	Version   string
	Generated time.Time
}

// Title is what the report is called, for a list of them.
func (r CaseReport) Title() string {
	if t := strings.TrimSpace(r.Case.Title); t != "" {
		return t
	}
	return "Untitled case"
}

// Markdown renders the report.
func (r CaseReport) Markdown() string {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", r.Title())
	r.writeHeader(&b)
	r.writeSummary(&b)
	r.writeFindings(&b)
	r.writeTimeline(&b)
	r.writeIndicators(&b)
	r.writeDecisions(&b)
	r.writeFooter(&b)

	return b.String()
}

func (r CaseReport) writeHeader(b *strings.Builder) {
	fmt.Fprintf(b, "**Severity** %s  **Status** %s  **Opened** %s\n",
		upperOr(r.Case.Severity, "unrated"),
		lowerOr(r.Case.Status, "unknown"),
		stamp(r.Case.CreatedAt))

	if a := strings.TrimSpace(r.Case.AssignedTo); a != "" {
		fmt.Fprintf(b, "**Assigned to** %s\n", a)
	}
	fmt.Fprintf(b, "**Holds** %s · %s · %s\n\n",
		plural(len(r.Findings), "finding"),
		plural(len(r.Events), "event"),
		plural(len(r.Indicators), "indicator"))
}

// writeSummary is the analyst's own account first.
//
// A generated summary is labelled as generated and placed after it. Handing a
// client a paragraph a model wrote, presented as the investigator's view, is
// the one thing a report must never do.
func (r CaseReport) writeSummary(b *strings.Builder) {
	b.WriteString("## Summary\n\n")

	if s := strings.TrimSpace(r.Briefing.Statement); s != "" {
		fmt.Fprintf(b, "%s\n\n", s)
	} else {
		b.WriteString("_No incident statement was recorded._\n\n")
	}

	if len(r.Briefing.Hypotheses) > 0 {
		b.WriteString("**Working hypotheses**\n\n")
		for _, h := range r.Briefing.Hypotheses {
			fmt.Fprintf(b, "- %s _(%s)_\n", h.Text, lowerOr(h.Confidence, "open"))
		}
		b.WriteString("\n")
	}

	if len(r.Briefing.NextActions) > 0 {
		b.WriteString("**Outstanding actions**\n\n")
		for _, a := range r.Briefing.NextActions {
			mark := " "
			if a.Done {
				mark = "x"
			}
			fmt.Fprintf(b, "- [%s] %s\n", mark, a.Text)
		}
		b.WriteString("\n")
	}

	if r.Briefing.HasSummary && strings.TrimSpace(r.Briefing.Summary) != "" {
		fmt.Fprintf(b, "> **Generated summary** — produced by a language model on %s, not the\n"+
			"> investigator's account. Read it as a starting point.\n>\n> %s\n\n",
			stamp(r.Briefing.SummaryAt),
			strings.ReplaceAll(strings.TrimSpace(r.Briefing.Summary), "\n", "\n> "))
	}
}

func (r CaseReport) writeFindings(b *strings.Builder) {
	b.WriteString("## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("_No findings are attached to this case._\n\n")
		return
	}

	findings := append([]store.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].RiskScore != findings[j].RiskScore {
			return findings[i].RiskScore > findings[j].RiskScore
		}
		return findings[i].FirstSeen.Before(findings[j].FirstSeen)
	})

	b.WriteString("| Severity | Risk | Status | Verdict | Finding |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, f := range findings {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n",
			upperOr(f.Severity, "—"),
			riskOrDash(f.RiskScore),
			orDash(f.StatusName()),
			orDash(f.Verdict),
			escapePipes(f.Title))
	}
	b.WriteString("\n")

	// The producer's own account of each detection, where there is one. A table
	// row says which detections fired; this says what they saw.
	for _, f := range findings {
		why := strings.TrimSpace(f.Desc)
		if why == "" {
			why = strings.TrimSpace(f.Message)
		}
		if why == "" || strings.EqualFold(why, strings.TrimSpace(f.Title)) {
			continue
		}
		fmt.Fprintf(b, "**%s** — %s\n\n", f.Title, why)
	}
}

func (r CaseReport) writeTimeline(b *strings.Builder) {
	b.WriteString("## Timeline\n\n")

	entries := r.timeline()
	if len(entries) == 0 {
		b.WriteString("_Nothing is recorded against this case yet._\n\n")
		return
	}
	for _, e := range entries {
		fmt.Fprintf(b, "- `%s`  **%s**  %s\n", stamp(e.at), e.kind, e.text)
	}
	b.WriteString("\n")
}

// timelineEntry is one line of the narrative.
type timelineEntry struct {
	at   time.Time
	kind string
	text string
}

// timeline merges everything that happened into one order.
//
// Findings, evidence, the analyst's notes and the case's own history read as
// one account. Kept apart they are four lists nobody correlates.
func (r CaseReport) timeline() []timelineEntry {
	var out []timelineEntry

	for _, f := range r.Findings {
		out = append(out, timelineEntry{f.FirstSeen, "finding", f.Title})
	}
	for _, e := range r.Events {
		out = append(out, timelineEntry{e.Timestamp, "event", firstLine(e.Message)})
	}
	for _, n := range r.Notes {
		if store.IsBriefingNote(n) {
			continue
		}
		out = append(out, timelineEntry{n.CreatedAt, "note", firstLine(n.Content)})
	}
	for _, a := range r.Audit {
		out = append(out, timelineEntry{a.Timestamp,
			"activity", fmt.Sprintf("%s by %s", humanise(a.Action), orDash(a.Actor))})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })
	return out
}

func (r CaseReport) writeIndicators(b *strings.Builder) {
	b.WriteString("## Indicators\n\n")
	if len(r.Indicators) == 0 {
		b.WriteString("_No indicators were extracted from this case's evidence._\n\n")
		return
	}

	inds := append([]store.CaseIndicator(nil), r.Indicators...)
	sort.SliceStable(inds, func(i, j int) bool { return inds[i].Sightings > inds[j].Sightings })

	b.WriteString("| Type | Value | Provenance | Sightings | First seen | Last seen |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, i := range inds {
		typeName := strings.TrimSpace(i.Type)
		if typeName == "" {
			typeName = ocsf.ObservableTypeName(i.TypeID)
		}
		fmt.Fprintf(b, "| %s | `%s` | %s | %d | %s | %s |\n",
			typeName, escapePipes(i.Value), provenance(i.Source),
			i.Sightings, stamp(i.FirstSeen), stamp(i.LastSeen))
	}
	b.WriteString("\n")
}

// writeDecisions is the analyst's own record: what was done, and when.
func (r CaseReport) writeDecisions(b *strings.Builder) {
	b.WriteString("## Decision log\n\n")

	notes := make([]store.Note, 0, len(r.Notes))
	for _, n := range r.Notes {
		if store.IsBriefingNote(n) || strings.EqualFold(n.LinkedType, "ioc") {
			continue
		}
		notes = append(notes, n)
	}
	if len(notes) == 0 {
		b.WriteString("_No notes were recorded._\n\n")
		return
	}

	sort.SliceStable(notes, func(i, j int) bool { return notes[i].CreatedAt.Before(notes[j].CreatedAt) })
	for _, n := range notes {
		fmt.Fprintf(b, "**%s** — %s\n\n%s\n\n",
			stamp(n.CreatedAt), orDash(n.Author), strings.TrimSpace(n.Content))
	}
}

func (r CaseReport) writeFooter(b *strings.Builder) {
	fmt.Fprintf(b, "---\n\nGenerated by Console-IR %s on %s.\n",
		orDash(r.Version), stamp(r.Generated))
}
