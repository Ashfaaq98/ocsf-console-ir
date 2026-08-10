package report

import (
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

var sample = []store.Case{
	{ID: "case_ccd9cfde-29bb-48d5", Title: "Suspected account compromise — m.chen"},
	{ID: "case_a1b2c3d4-0000-1111", Title: "Phishing-led intrusion on workstation-14"},
	{ID: "case_a1b2ffff-2222-3333", Title: "Cryptominer on build-agent-03"},
}

// A person names a case by whatever they can remember of it.
//
// Case ids are UUIDs, which nobody types. An exact id wins, then enough of one
// to be unique, then any part of the title — the courtesy git extends with
// short hashes.
func TestResolvingACase(t *testing.T) {
	for _, tc := range []struct {
		name, want, wantID string
	}{
		{"the whole id", "case_ccd9cfde-29bb-48d5", "case_ccd9cfde-29bb-48d5"},
		{"enough of the id", "case_ccd9", "case_ccd9cfde-29bb-48d5"},
		{"part of the title", "account compromise", "case_ccd9cfde-29bb-48d5"},
		{"the wrong capitalisation", "CRYPTOMINER", "case_a1b2ffff-2222-3333"},
	} {
		got, err := ResolveCase(sample, tc.want)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got.ID != tc.wantID {
			t.Errorf("%s: %q found %s, want %s", tc.name, tc.want, got.ID, tc.wantID)
		}
	}
}

// Anything ambiguous is an error naming the candidates, not a guess. Writing up
// the wrong case is worse than being asked again.
func TestAnAmbiguousCaseIsRefused(t *testing.T) {
	_, err := ResolveCase(sample, "case_a1b2")
	if err == nil {
		t.Fatal("a prefix matching two cases was resolved to one of them")
	}
	for _, want := range []string{"matches 2 cases", "Phishing-led", "Cryptominer"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// And something that matches nothing says so plainly.
func TestAnUnknownCaseIsRefused(t *testing.T) {
	if _, err := ResolveCase(sample, "ransomware"); err == nil {
		t.Fatal("a case that does not exist was resolved")
	} else if !strings.Contains(err.Error(), "ransomware") {
		t.Errorf("the error does not name what was asked for: %v", err)
	}
}

// A prefix too short to mean anything is not a prefix.
func TestAVeryShortPrefixIsNotAMatch(t *testing.T) {
	if _, err := ResolveCase(sample, "ca"); err == nil {
		t.Error("two characters resolved to a case")
	}
}
