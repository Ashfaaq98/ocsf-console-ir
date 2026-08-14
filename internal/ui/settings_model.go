package ui

import (
	"fmt"
	"strings"
)

// What a settings screen is actually for.
//
// With four layers of configuration — built-in defaults, a config file, command
// line flags, and choices made here — the most useful question a settings
// screen can answer is not "what can I change" but **"why is this value what it
// is"**. So every row carries its source, and a row a flag has already decided
// says so rather than accepting a change it cannot keep.

// settingSource is where a value came from.
type settingSource int

const (
	srcDefault  settingSource = iota // nobody has said otherwise
	srcYou                           // chosen here, and persisted
	srcConfig                        // the configuration file
	srcFlag                          // a command line flag, for this session
	srcDetected                      // measured from the terminal or the build
	srcNone                          // not set at all
)

func (s settingSource) label() string {
	switch s {
	case srcYou:
		return "you"
	case srcConfig:
		return "config"
	case srcFlag:
		return "flag"
	case srcDetected:
		return "detected"
	case srcNone:
		return "not set"
	default:
		return "default"
	}
}

// tag colours a source so a row that cannot be changed reads as different
// before you try to change it.
func (s settingSource) tag(t Theme) string {
	switch s {
	case srcYou:
		return t.TagAccent
	case srcFlag:
		return t.TagWarning
	default:
		return t.TagMuted
	}
}

// setting is one row.
//
// Everything is a function of the live UI rather than a snapshot, so the panel
// redraws from the truth after every change instead of from a copy that has to
// be kept in step.
type setting struct {
	name string
	// value renders the current value.
	value func(*UI) string
	// source says where that value came from.
	source func(*UI) settingSource
	// detail is the explanation under the list: what this does, and — where it
	// is easy to assume otherwise — what it does not do.
	detail []string
	// detailFor replaces detail when the explanation depends on the state. The
	// receiver's is the reason this exists: whether anyone who can reach the
	// address may post is the most important thing on that row, and it is only
	// true some of the time.
	detailFor func(*UI) []string
	// edit changes the value. Nil means the row is read-only, and `locked`
	// explains why in the detail pane.
	edit   func(*UI, func())
	locked string
	// search is extra text a search should match, for rows whose name does not
	// contain the obvious word.
	search string
}

// readOnly reports whether Enter does anything on this row.
func (s setting) readOnly() bool { return s.edit == nil }

// explain is the detail to show, live where the row needs it to be.
func (s setting) explain(ui *UI) []string {
	if s.detailFor != nil {
		return s.detailFor(ui)
	}
	return s.detail
}

// matches reports whether a search term hits this row.
func (s setting) matches(term string) bool {
	if term == "" {
		return true
	}
	term = strings.ToLower(term)
	if strings.Contains(strings.ToLower(s.name), term) ||
		strings.Contains(strings.ToLower(s.search), term) {
		return true
	}
	for _, line := range s.detail {
		if strings.Contains(strings.ToLower(line), term) {
			return true
		}
	}
	return false
}

// settingsCategory groups rows under one heading.
type settingsCategory struct {
	name     string
	blurb    string
	settings []setting
}

// onOff renders a boolean the way the row reads.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// yesNo renders a boolean where "on" would be the wrong word.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// chosen marks a value the analyst set, for the source column.
func chosen(set bool) settingSource {
	if set {
		return srcYou
	}
	return srcDefault
}

// seconds renders a duration setting with its unit.
func seconds(n int) string { return fmt.Sprintf("%ds", n) }
