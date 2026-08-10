package report

import (
	"fmt"
	"strings"
	"time"
)

// Small helpers, kept together so the document above reads as prose.

// stamp is the one date format the whole report uses.
//
// Absolute and unambiguous, not "2d ago": a report is read weeks after it is
// written, and by people who were not there.
func stamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return strings.TrimSpace(s)
}

func upperOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.ToUpper(strings.TrimSpace(s))
}

func lowerOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.ToLower(strings.TrimSpace(s))
}

func riskOrDash(score int) string {
	if score <= 0 {
		return "—"
	}
	return fmt.Sprintf("%d", score)
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// firstLine keeps a multi-line note to one line in the timeline. The whole note
// is in the decision log below it.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i]) + " …"
	}
	return s
}

// provenance says who called something an indicator.
func provenance(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "derived":
		return "derived"
	case "manual":
		return "analyst"
	default:
		return "asserted"
	}
}

// humanise turns an audit action into something a reader recognises.
func humanise(action string) string {
	s := strings.ReplaceAll(strings.TrimSpace(action), "_", " ")
	if s == "" {
		return "activity"
	}
	return s
}

// escapePipes keeps a value containing a pipe from breaking the table it is in.
//
// Command lines and URLs carry them, and one unescaped pipe silently shifts
// every column after it — a report that misattributes a value is worse than one
// that omits it.
func escapePipes(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "|", `\|`)
}
