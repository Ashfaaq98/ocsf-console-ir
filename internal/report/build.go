package report

import (
	"context"
	"fmt"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Gathering what a report is written from.
//
// Here rather than in the interface, because the command line writes the same
// report and must not assemble it differently. A report produced by `E` in a
// case and one produced by `console-ir report` are the same document or the
// feature is two features.

// auditLimit bounds the activity a report carries. A case worked for a week can
// hold hundreds of entries, and a timeline nobody reads to the end is not a
// timeline.
const auditLimit = 200

// BuildCase reads everything a case report needs.
//
// The clock is a parameter so the caller decides what "generated at" means, and
// so a test can produce the same document twice.
func BuildCase(ctx context.Context, st *store.Store, caseID, version string, now time.Time) (CaseReport, error) {
	if st == nil {
		return CaseReport{}, fmt.Errorf("no database")
	}

	c, err := st.GetCase(ctx, caseID)
	if err != nil || c == nil {
		return CaseReport{}, fmt.Errorf("could not read case %s: %w", caseID, err)
	}

	r := CaseReport{Case: *c, Version: version, Generated: now}

	// A failure in any one of these costs a section, not the report. A case with
	// no notes and a report that will not generate are different problems, and
	// only the first is the analyst's.
	r.Briefing, _ = st.GetBriefing(ctx, caseID)
	r.Findings, _ = st.GetCaseFindings(ctx, caseID)
	r.Events, _ = st.GetEventsByCase(ctx, caseID)
	r.Notes, _ = st.GetNotes(ctx, caseID)
	r.Audit, _ = st.GetAuditEntries(ctx, caseID, auditLimit)
	r.Indicators, _ = st.GetCaseIndicators(ctx, caseID)

	return r, nil
}

// ResolveCase finds the case a person meant.
//
// Case identifiers are UUIDs, which nobody types. An exact id wins, then a
// unique id prefix, then a unique case-insensitive match on the title — the
// same courtesy git extends with short hashes. Anything ambiguous is an error
// naming the candidates rather than a guess: writing up the wrong case is worse
// than being asked again.
func ResolveCase(cases []store.Case, want string) (store.Case, error) {
	if want == "" {
		return store.Case{}, fmt.Errorf("no case given")
	}

	var prefix, titled []store.Case
	for _, c := range cases {
		if c.ID == want {
			return c, nil
		}
		if len(want) >= 4 && len(c.ID) >= len(want) && equalFold(c.ID[:len(want)], want) {
			prefix = append(prefix, c)
		}
		if containsFold(c.Title, want) {
			titled = append(titled, c)
		}
	}

	for _, set := range [][]store.Case{prefix, titled} {
		switch len(set) {
		case 1:
			return set[0], nil
		case 0:
			continue
		default:
			return store.Case{}, ambiguous(want, set)
		}
	}
	return store.Case{}, fmt.Errorf("no case matches %q", want)
}

func ambiguous(want string, cases []store.Case) error {
	msg := fmt.Sprintf("%q matches %d cases:", want, len(cases))
	for _, c := range cases {
		msg += fmt.Sprintf("\n  %s  %s", c.ID, c.Title)
	}
	return fmt.Errorf("%s", msg)
}
