package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// The core enrichers key their data <source>_<indicator>_<field>. Grouping must
// recover the indicator so the reader is not left reassembling
// geoip_8_8_8_8_city / geoip_8_8_8_8_country by eye.
func TestGroupEnrichmentsGroupsByIndicator(t *testing.T) {
	enrichments := []store.Enrichment{{
		Source: "geoip",
		Type:   "geoip",
		Data: map[string]string{
			"geoip_8_8_8_8_country":      "United States",
			"geoip_8_8_8_8_country_code": "US",
			"geoip_8_8_8_8_city":         "Mountain View",
			"geoip_1_1_1_1_country":      "Australia",
			"geoip_1_1_1_1_city":         "Sydney",
		},
	}}

	cards := groupEnrichments(enrichments, []string{"8.8.8.8", "1.1.1.1"})
	if len(cards) != 2 {
		t.Fatalf("got %d cards, want one per indicator: %+v", len(cards), cards)
	}

	// Named indicators come out alphabetically.
	if cards[0].Indicator != "1.1.1.1" || cards[1].Indicator != "8.8.8.8" {
		t.Fatalf("indicators = %q, %q; want 1.1.1.1 then 8.8.8.8", cards[0].Indicator, cards[1].Indicator)
	}

	// Field names must have both the source and the indicator stripped, including
	// field names that themselves contain underscores.
	got := fieldMap(cards[1].Fields)
	want := map[string]string{
		"country":      "United States",
		"country_code": "US",
		"city":         "Mountain View",
	}
	if len(got) != len(want) {
		t.Fatalf("8.8.8.8 fields = %+v, want %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("field %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestGroupEnrichmentsHandlesDomains(t *testing.T) {
	enrichments := []store.Enrichment{{
		Source: "whois",
		Type:   "whois",
		Data: map[string]string{
			"whois_example_com_registrar":       "MarkMonitor Inc.",
			"whois_example_com_created_date":    "1995-08-14",
			"whois_example_com_expiration_date": "2026-08-13",
		},
	}}

	cards := groupEnrichments(enrichments, []string{"example.com"})
	if len(cards) != 1 {
		t.Fatalf("got %d cards, want 1: %+v", len(cards), cards)
	}
	if cards[0].Indicator != "example.com" {
		t.Errorf("indicator = %q, want example.com", cards[0].Indicator)
	}
	got := fieldMap(cards[0].Fields)
	for _, want := range []string{"registrar", "created_date", "expiration_date"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing field %q; got %+v", want, got)
		}
	}
}

// Two indicators can share a prefix once dots become underscores. Requiring the
// trailing separator is what stops 10.1.2.3 claiming 10.1.2.34's fields.
func TestGroupEnrichmentsDoesNotConfusePrefixOverlappingIndicators(t *testing.T) {
	enrichments := []store.Enrichment{{
		Source: "geoip",
		Data: map[string]string{
			"geoip_10_1_2_3_city":  "Berlin",
			"geoip_10_1_2_34_city": "Paris",
		},
	}}

	cards := groupEnrichments(enrichments, []string{"10.1.2.3", "10.1.2.34"})
	if len(cards) != 2 {
		t.Fatalf("got %d cards, want 2: %+v", len(cards), cards)
	}

	byIndicator := map[string]map[string]string{}
	for _, c := range cards {
		byIndicator[c.Indicator] = fieldMap(c.Fields)
	}
	if got := byIndicator["10.1.2.3"]["city"]; got != "Berlin" {
		t.Errorf("10.1.2.3 city = %q, want Berlin", got)
	}
	if got := byIndicator["10.1.2.34"]["city"]; got != "Paris" {
		t.Errorf("10.1.2.34 city = %q, want Paris", got)
	}
}

// An external plugin using its own key scheme must still show everything it
// produced, just ungrouped — losing data would be worse than an ugly card.
func TestGroupEnrichmentsKeepsUnrecognisedKeys(t *testing.T) {
	enrichments := []store.Enrichment{{
		Source: "somevendor",
		Data: map[string]string{
			"verdict":      "malicious",
			"score":        "91",
			"geoip_ignore": "n/a",
		},
	}}

	cards := groupEnrichments(enrichments, []string{"8.8.8.8"})
	if len(cards) != 1 {
		t.Fatalf("got %d cards, want 1 catch-all: %+v", len(cards), cards)
	}
	if cards[0].Indicator != "" {
		t.Errorf("indicator = %q, want empty (unmatched)", cards[0].Indicator)
	}
	got := fieldMap(cards[0].Fields)
	if len(got) != 3 {
		t.Fatalf("dropped keys: got %+v, want all 3", got)
	}
	// Unmatched keys keep their original names, since that is all we know.
	if got["verdict"] != "malicious" || got["score"] != "91" {
		t.Errorf("unmatched fields lost their names or values: %+v", got)
	}
}

// A mix of grouped and ungrouped keys puts the readable cards first.
func TestGroupEnrichmentsPutsUnmatchedGroupLast(t *testing.T) {
	enrichments := []store.Enrichment{{
		Source: "geoip",
		Data: map[string]string{
			"geoip_8_8_8_8_city": "Mountain View",
			"lookup_provider":    "ipapi",
		},
	}}

	cards := groupEnrichments(enrichments, []string{"8.8.8.8"})
	if len(cards) != 2 {
		t.Fatalf("got %d cards, want 2: %+v", len(cards), cards)
	}
	if cards[0].Indicator != "8.8.8.8" {
		t.Errorf("first card = %q, want the named indicator", cards[0].Indicator)
	}
	if cards[1].Indicator != "" {
		t.Errorf("last card = %q, want the unmatched group", cards[1].Indicator)
	}
}

func TestGroupEnrichmentsCarriesSourceAndTime(t *testing.T) {
	when := time.Date(2026, 7, 29, 13, 58, 19, 0, time.UTC)
	cards := groupEnrichments([]store.Enrichment{{
		Source:    "geoip",
		Type:      "geoip",
		CreatedAt: when,
		Data:      map[string]string{"geoip_8_8_8_8_city": "Mountain View"},
	}}, []string{"8.8.8.8"})

	if len(cards) != 1 {
		t.Fatalf("got %d cards", len(cards))
	}
	if cards[0].Source != "geoip" || cards[0].Type != "geoip" {
		t.Errorf("source/type = %q/%q", cards[0].Source, cards[0].Type)
	}
	if !cards[0].When.Equal(when) {
		t.Errorf("When = %v, want %v", cards[0].When, when)
	}
}

func TestGroupEnrichmentsEmptyInput(t *testing.T) {
	if cards := groupEnrichments(nil, nil); len(cards) != 0 {
		t.Errorf("got %+v, want no cards", cards)
	}
}

// eventIndicatorValues must fall back to the event's own fields, since the core
// enrichers scrape those directly for events carrying no observables.
func TestEventIndicatorValuesFallsBackToEventFields(t *testing.T) {
	ev := &store.Event{SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Host: "workstation-14", FileHash: "abc123"}
	got := eventIndicatorValues(nil, ev)

	for _, want := range []string{"10.0.0.1", "8.8.8.8", "workstation-14", "abc123"} {
		if !contains(got, want) {
			t.Errorf("missing %q from %v", want, got)
		}
	}
}

func TestEventIndicatorValuesPrefersObservables(t *testing.T) {
	obs := []store.Observable{{Value: "1.1.1.1"}, {Value: "evil.example"}}
	got := eventIndicatorValues(obs, &store.Event{SrcIP: "10.0.0.1"})

	if got[0] != "1.1.1.1" || got[1] != "evil.example" {
		t.Errorf("observables should lead: %v", got)
	}
	if !contains(got, "10.0.0.1") {
		t.Errorf("event fields should still be appended: %v", got)
	}
}

// The rendering is what the analyst reads, so assert its shape: an indicator
// heading with its fields beneath, not a flat key list.
func TestRenderEnrichmentCardsGroupsVisually(t *testing.T) {
	var sb strings.Builder
	cards := groupEnrichments([]store.Enrichment{{
		Source: "geoip",
		Data: map[string]string{
			"geoip_8_8_8_8_city":    "Mountain View",
			"geoip_8_8_8_8_country": "United States",
		},
	}}, []string{"8.8.8.8"})

	renderEnrichmentCards(&sb, themeDark(), cards, enrichmentRenderOptions{Indent: "  "})
	out := stripTags(sb.String())

	lines := nonEmptyLines(out)
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want a heading plus two fields:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[0], "8.8.8.8") || !strings.Contains(lines[0], "geoip") {
		t.Errorf("heading missing indicator or source: %q", lines[0])
	}
	// The indicator must not be repeated on every field line — that is the wart.
	for _, l := range lines[1:] {
		if strings.Contains(l, "8_8_8_8") {
			t.Errorf("field line still carries the raw key prefix: %q", l)
		}
	}
	if !strings.Contains(out, "city") || !strings.Contains(out, "country") {
		t.Errorf("field names missing:\n%s", out)
	}
}

func TestRenderEnrichmentCardsTruncatesAndReports(t *testing.T) {
	data := map[string]string{}
	for i := 0; i < 10; i++ {
		data[string(rune('a'+i))+"_field"] = "value"
	}
	var sb strings.Builder
	renderEnrichmentCards(&sb, themeDark(),
		groupEnrichments([]store.Enrichment{{Source: "x", Data: data}}, nil),
		enrichmentRenderOptions{MaxFields: 4})

	out := stripTags(sb.String())
	if !strings.Contains(out, "and 6 more") {
		t.Errorf("truncation not reported:\n%s", out)
	}
}

func TestRenderEnrichmentCardsLabelsUnmatchedGroup(t *testing.T) {
	var sb strings.Builder
	renderEnrichmentCards(&sb, themeDark(),
		groupEnrichments([]store.Enrichment{{Source: "x", Data: map[string]string{"verdict": "bad"}}}, nil),
		enrichmentRenderOptions{})

	if out := stripTags(sb.String()); !strings.Contains(out, "other") {
		t.Errorf("unmatched card has no heading:\n%s", out)
	}
}

func TestRenderEnrichmentCardsShowsDashForEmptyValue(t *testing.T) {
	var sb strings.Builder
	renderEnrichmentCards(&sb, themeDark(),
		groupEnrichments([]store.Enrichment{{
			Source: "geoip",
			Data:   map[string]string{"geoip_8_8_8_8_city": ""},
		}}, []string{"8.8.8.8"}),
		enrichmentRenderOptions{})

	if out := stripTags(sb.String()); !strings.Contains(out, "-") {
		t.Errorf("empty value not marked:\n%s", out)
	}
}

func fieldMap(fields []enrichmentField) map[string]string {
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		out[f.Name] = f.Value
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}
