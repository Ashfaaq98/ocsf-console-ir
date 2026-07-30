package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// enrichmentField is one fact learned about an indicator.
type enrichmentField struct {
	Name  string
	Value string
}

// enrichmentCard is everything one source learned about one indicator — the unit
// an analyst actually reads.
type enrichmentCard struct {
	Source    string    // "geoip"
	Type      string    // "geoip"
	Indicator string    // "8.8.8.8"; empty when the keys name no known indicator
	When      time.Time // when the lookup landed
	Fields    []enrichmentField
}

// groupEnrichments turns flat enrichment maps into one card per indicator.
//
// The core enrichers key their data <source>_<indicator, dots as underscores>_<field>
// — geoip_8_8_8_8_country, whois_example_com_registrar — which renders as one long
// alphabetical list where the reader has to work out which field belongs to which
// indicator. Splitting a key apart is ambiguous on its own, because both the
// indicator and the field name contain underscores ("8_8_8_8" and "country_code"),
// so candidate indicators come from the caller: the event's own observables.
//
// Keys matching no candidate are collected into a trailing card rather than
// dropped, so an external plugin using a different key scheme still shows
// everything it produced — just ungrouped.
func groupEnrichments(enrichments []store.Enrichment, indicators []string) []enrichmentCard {
	cands := indicatorCandidates(indicators)

	var cards []enrichmentCard
	for _, enr := range enrichments {
		fields := make(map[string][]enrichmentField)
		for _, key := range sortedKeys(enr.Data) {
			indicator, name := splitEnrichmentKey(key, enr.Source, cands)
			fields[indicator] = append(fields[indicator], enrichmentField{Name: name, Value: enr.Data[key]})
		}

		for _, indicator := range groupOrder(fields) {
			cards = append(cards, enrichmentCard{
				Source:    enr.Source,
				Type:      enr.Type,
				Indicator: indicator,
				When:      enr.CreatedAt,
				Fields:    fields[indicator],
			})
		}
	}
	return cards
}

// groupOrder lists named indicators alphabetically, with the unmatched group last
// so the readable cards come first.
func groupOrder(fields map[string][]enrichmentField) []string {
	named := make([]string, 0, len(fields))
	unmatched := false
	for k := range fields {
		if k == "" {
			unmatched = true
			continue
		}
		named = append(named, k)
	}
	sort.Strings(named)
	if unmatched {
		named = append(named, "")
	}
	return named
}

// indicatorCandidate pairs an indicator with the form it takes inside an
// enrichment key.
type indicatorCandidate struct {
	key   string // "8_8_8_8"
	value string // "8.8.8.8"
}

func indicatorCandidates(indicators []string) []indicatorCandidate {
	seen := make(map[string]bool, len(indicators))
	out := make([]indicatorCandidate, 0, len(indicators))
	for _, v := range indicators {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ReplaceAll(v, ".", "_")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, indicatorCandidate{key: key, value: v})
	}
	// Longest first, so a key naming 10.1.2.34 is not claimed by 10.1.2.3.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].key) != len(out[j].key) {
			return len(out[i].key) > len(out[j].key)
		}
		return out[i].key < out[j].key
	})
	return out
}

// splitEnrichmentKey separates an enrichment key into the indicator it describes
// and the field name. An unrecognised key keeps its full original name, since
// that is all we reliably know about it.
func splitEnrichmentKey(key, source string, cands []indicatorCandidate) (indicator, field string) {
	rest := key
	if prefix := strings.ToLower(source) + "_"; strings.HasPrefix(strings.ToLower(rest), prefix) {
		rest = rest[len(prefix):]
	}
	for _, c := range cands {
		// The trailing underscore matters: without it "1_2_3_4" would also match
		// the key for 1.2.3.45.
		if strings.HasPrefix(rest, c.key+"_") {
			return c.value, rest[len(c.key)+1:]
		}
	}
	return "", key
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// enrichmentRenderOptions bounds how much of each card is drawn. Both detail
// views render through the same function so the same lookup does not look like
// two different things depending on where you opened it.
type enrichmentRenderOptions struct {
	Indent      string // leading whitespace for the card header
	MaxFields   int    // per card; 0 means unlimited
	MaxValueLen int    // 0 means untruncated
}

// renderEnrichmentCards writes cards as one block per indicator, field names
// aligned within a card.
func renderEnrichmentCards(sb *strings.Builder, t Theme, cards []enrichmentCard, opt enrichmentRenderOptions) {
	fieldIndent := opt.Indent + "  "

	for i, card := range cards {
		if i > 0 {
			sb.WriteString("\n")
		}

		title := card.Indicator
		if title == "" {
			// Nothing tied these fields to an indicator; say so rather than
			// printing an empty heading.
			title = "other"
		}
		sb.WriteString(fmt.Sprintf("%s[%s]%s[-]  [%s]%s[-]",
			opt.Indent, t.TagAccent, title, t.TagMuted, card.Source))
		if !card.When.IsZero() {
			sb.WriteString(fmt.Sprintf("  [%s]%s[-]", t.TagMuted, card.When.Format("2006-01-02 15:04:05")))
		}
		sb.WriteString("\n")

		shown := card.Fields
		if opt.MaxFields > 0 && len(shown) > opt.MaxFields {
			shown = shown[:opt.MaxFields]
		}

		width := 0
		for _, f := range shown {
			if len(f.Name) > width {
				width = len(f.Name)
			}
		}

		for _, f := range shown {
			value := f.Value
			if value == "" {
				value = "-"
			}
			if opt.MaxValueLen > 0 && len(value) > opt.MaxValueLen {
				value = value[:opt.MaxValueLen-3] + "..."
			}
			sb.WriteString(fmt.Sprintf("%s[%s]%-*s[-]  [%s]%s[-]\n",
				fieldIndent, t.TagWarning, width, f.Name, t.TagTextPrimary, value))
		}
		if len(card.Fields) > len(shown) {
			sb.WriteString(fmt.Sprintf("%s[%s]... and %d more[-]\n",
				fieldIndent, t.TagMuted, len(card.Fields)-len(shown)))
		}
	}
}

// eventIndicatorValues returns the values enrichment keys may have been built
// from: the event's stored observables first, then the fields the core enrichers
// scrape directly, which covers events that arrived carrying no observables.
func eventIndicatorValues(observables []store.Observable, event *store.Event) []string {
	out := make([]string, 0, len(observables)+4)
	for _, o := range observables {
		out = append(out, o.Value)
	}
	if event != nil {
		out = append(out, event.SrcIP, event.DstIP, event.Host, event.FileHash)
	}
	return out
}
