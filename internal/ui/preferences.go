package ui

import (
	"os"
	"strings"
	"time"
)

// What an analyst can change about how the tool behaves, as opposed to what it
// is pointed at.
//
// The dividing line matters and is the same one the settings panel has always
// drawn: anything that changes what is exposed to a network, or where data
// lives, stays on the command line. Those are decisions about deployment, often
// taken by someone other than the person at the keyboard, and a control that
// appears to change them without surviving the next launch is a lie. Everything
// here is a preference: it changes how you work, and it is safe to change in
// the middle of a session.

// Three of these are declared and not yet offered by the panel — UTC,
// EnrichOff and CopilotTimeoutSeconds. Each needs work behind it before a
// switch would mean anything: UTC needs the forty-odd timestamp formatters
// routed through one funnel, enrichment needs the plugin manager to accept a
// stop, and the request timeout is baked into four provider constructors in
// internal/llm. A switch that does nothing is the defect this panel exists to
// remove, so they are on the roadmap rather than on the screen.

// preferences persist beside the theme. Zero values are the defaults, so a file
// written by an older build reads as "everything default" rather than as
// nonsense.
type preferences struct {
	// Analyst is the name written into the audit trail, case ownership, notes
	// and reports. Empty means "take it from the environment".
	//
	// Settable because the environment is often wrong: a shared jump box, a
	// login that is not your SOC handle, a container running as root. The name
	// lands in a record someone else reads later, so it should be the name that
	// person will recognise.
	Analyst string `json:"analyst,omitempty"`

	// UTC displays every timestamp in UTC rather than the local zone.
	//
	// Reports and handovers are written in UTC by convention, because an
	// incident crosses time zones and a local timestamp is ambiguous the moment
	// it leaves the machine that produced it. Display only: nothing stored
	// changes.
	UTC bool `json:"utc,omitempty"`

	// RelativeAges shows "4m ago" beside or instead of a clock time.
	// On by default, so the zero value has to mean on.
	NoRelativeAges bool `json:"no_relative_ages,omitempty"`

	// ConfirmDestructive asks before anything that cannot be undone. On by
	// default, so the zero value means on and switching it off is explicit.
	NoConfirmDestructive bool `json:"no_confirm_destructive,omitempty"`

	// ASCII draws with plain characters even where the terminal reports UTF-8.
	// For terminals that claim more than they can render.
	ASCII bool `json:"ascii,omitempty"`

	// CopilotOff disables the assistant entirely: no suggestions, no requests,
	// no drawer. Off by default because the copilot is opt-in in effect anyway
	// — it needs a provider — but a switch is clearer than an absence.
	CopilotOff bool `json:"copilot_off,omitempty"`

	// CopilotTimeoutSeconds bounds a request. Zero means the built-in default.
	// Settable because the shipped default targets a local model and CPU-only
	// inference can exceed it, which the configuration docs already warn about.
	CopilotTimeoutSeconds int `json:"copilot_timeout_seconds,omitempty"`

	// CopilotTokenWarning is the estimate above which a request asks first.
	// Zero means the built-in default.
	CopilotTokenWarning int `json:"copilot_token_warning,omitempty"`

	// EnrichOff stops GeoIP and WHOIS lookups. They are network calls made on
	// the analyst's behalf, and on an isolated network they are noise.
	EnrichOff bool `json:"enrich_off,omitempty"`

	// AutoRefreshSeconds re-reads the current screen on a timer. Zero is off,
	// which is the default: re-sorting a list while it is being read is
	// disruptive, and an analyst who wants fresh data presses r.
	AutoRefreshSeconds int `json:"auto_refresh_seconds,omitempty"`
}

// Defaults for the values a zero cannot express.
const (
	defaultCopilotTimeout      = 60
	defaultCopilotTokenWarning = 1000
)

// analystName is the name this session writes into records.
func (p preferences) analystName() string {
	if n := strings.TrimSpace(p.Analyst); n != "" {
		return n
	}
	return environmentAnalyst()
}

// environmentAnalyst is the fallback: whoever the operating system says is
// logged in, and a plain word when it will not say.
func environmentAnalyst() string {
	for _, key := range []string{"USER", "USERNAME"} {
		if u := strings.TrimSpace(os.Getenv(key)); u != "" {
			return u
		}
	}
	return "analyst"
}

// displayTime moves a timestamp into the zone the analyst reads in.
//
// One function rather than a flag threaded through every renderer: a screen
// that formats a time without going through here is a screen that ignores the
// preference, and that is a bug the type system cannot catch — so keep the
// number of formatting paths small and route them all here.
func (p preferences) displayTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	if p.UTC {
		return t.UTC()
	}
	return t.Local()
}

// zoneLabel names the zone in force, for the settings row.
func (p preferences) zoneLabel() string {
	if p.UTC {
		return "UTC"
	}
	name, offset := time.Now().Local().Zone()
	sign := "+"
	if offset < 0 {
		sign, offset = "-", -offset
	}
	h, m := offset/3600, (offset%3600)/60
	return name + " (UTC" + sign + twoDigits(h) + ":" + twoDigits(m) + ")"
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// copilotTimeout is how long a request may take.
func (p preferences) copilotTimeout() time.Duration {
	if p.CopilotTimeoutSeconds > 0 {
		return time.Duration(p.CopilotTimeoutSeconds) * time.Second
	}
	return defaultCopilotTimeout * time.Second
}

// copilotTokenWarning is the estimate above which a request asks first.
func (p preferences) copilotTokenWarning() int {
	if p.CopilotTokenWarning > 0 {
		return p.CopilotTokenWarning
	}
	return defaultCopilotTokenWarning
}

// relativeAges and confirmDestructive read the negated fields, so that the
// zero value of the struct is the shipped behaviour.
func (p preferences) relativeAges() bool       { return !p.NoRelativeAges }
func (p preferences) confirmDestructive() bool { return !p.NoConfirmDestructive }
