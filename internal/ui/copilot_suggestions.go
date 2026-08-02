package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Suggestions are the copilot's opening move, and they are derived from the
// case rather than written in advance.
//
// A fixed list — "Summarise selected evidence", "Draft handoff note" — is a
// guess about what this case needs, and it is the same guess on every case.
// Each suggestion here exists because of something true about *this* case, and
// carries that reason with it: "Draft the incident statement" appears because
// the briefing has none, and stops appearing once one is written.
//
// This replaces four prompts that were static text bound to keys that were
// never wired to anything.

// copilotSuggestion is one offered question.
type copilotSuggestion struct {
	// Text is the question sent to the copilot when chosen.
	Text string
	// Reason is the case fact that produced it, shown beneath.
	Reason string
}

// suggestionInput is everything the suggestions are derived from.
type suggestionInput struct {
	Case       store.Case
	Brief      store.Briefing
	Events     []store.Event
	Findings   []store.Finding
	Indicators []store.CaseIndicator
	Notes      []store.Note
}

// maxSuggestions bounds the list. Beyond a handful it is a menu to read rather
// than a prompt to act on, and it would push the input field off a short drawer.
const maxSuggestions = 4

// caseSuggestions builds the offered questions, most useful first.
func caseSuggestions(in suggestionInput) []copilotSuggestion {
	out := []copilotSuggestion{}

	// A case with no statement cannot be handed to anyone, so this outranks
	// everything else it might be useful to ask.
	if strings.TrimSpace(in.Brief.Statement) == "" {
		out = append(out, copilotSuggestion{
			Text:   "Draft an incident statement for this case in two sentences.",
			Reason: "no statement recorded yet",
		})
	}

	// The indicator carrying the most weight is the one worth explaining.
	if top, ok := topIndicator(in.Indicators); ok {
		_, _, provenance := provenanceMark(top.Source, themeDark())
		out = append(out, copilotSuggestion{
			Text:   fmt.Sprintf("Explain the indicator %s and what it implies here.", top.Value),
			Reason: fmt.Sprintf("%s · %s", sightingLabel(top.Sightings), provenance),
		})
	}

	// More than one host is the question of whether this is one incident.
	hosts, users, first, last := scopeOf(in.Events)
	if len(hosts) > 1 {
		out = append(out, copilotSuggestion{
			Text: fmt.Sprintf("What links %s and %s in this case?", hosts[0], hosts[1]),
			Reason: fmt.Sprintf("%s · %s · %s", countLabel(len(hosts), "host"),
				countLabel(len(users), "user"), windowLabel(first, last)),
		})
	}

	// A case whose evidence stops before its findings do has a hole in it.
	if len(in.Events)+len(in.Findings) > 2 {
		out = append(out, copilotSuggestion{
			Text: "Where are the gaps in this timeline?",
			Reason: fmt.Sprintf("%s · %s", countLabel(len(in.Events)+len(in.Findings), "entry"),
				windowLabel(first, last)),
		})
	}

	// A case nobody has written in is the one that goes stale.
	if len(decisionNotes(in.Notes)) == 0 {
		out = append(out, copilotSuggestion{
			Text:   "What should the next action on this case be?",
			Reason: "no decision recorded",
		})
	}

	if len(out) > maxSuggestions {
		out = out[:maxSuggestions]
	}
	return out
}

// topIndicator is the most-sighted indicator, preferring asserted ones on a tie
// — a producer's claim is a firmer thing to ask about than our inference.
func topIndicator(in []store.CaseIndicator) (store.CaseIndicator, bool) {
	if len(in) == 0 {
		return store.CaseIndicator{}, false
	}
	ranked := make([]store.CaseIndicator, len(in))
	copy(ranked, in)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Sightings != ranked[j].Sightings {
			return ranked[i].Sightings > ranked[j].Sightings
		}
		return strings.EqualFold(ranked[i].Source, "asserted") &&
			!strings.EqualFold(ranked[j].Source, "asserted")
	})
	return ranked[0], true
}

// decisionNotes are the notes that record a decision — not briefing fragments,
// not indicator entries.
func decisionNotes(notes []store.Note) []store.Note {
	out := []store.Note{}
	for _, n := range notes {
		if store.IsBriefingNote(n) || strings.EqualFold(n.LinkedType, "ioc") {
			continue
		}
		out = append(out, n)
	}
	return out
}

func countLabel(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if noun == "entry" {
		return fmt.Sprintf("%d entries", n)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func sightingLabel(n int) string {
	if n == 1 {
		return "1 sighting"
	}
	return fmt.Sprintf("%d sightings", n)
}
