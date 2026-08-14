package ui

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
)

// defaultThemeName is what a fresh install starts on, and the fallback whenever
// a saved name is missing or unknown.
//
// gruvbox: warm, low-contrast and easy to read for a long shift, which is what
// this tool is used for. `dark` remains one keypress away on `t`, and whatever
// is chosen persists — the default only decides the first screen anyone sees.
const defaultThemeName = "gruvbox"

// themeBuilders is the registry of shipped themes, and themeNames() sorts it
// into the cycle `t` walks.
//
// dark and light cover the ordinary cases, gruvbox is the palette people ask for
// by name, and midnight is a darker dark.
//
// high-contrast and colourblind are registered but **not verified screen by
// screen**. Severity is colour-coded throughout, so a palette that confuses two
// severity colours is a correctness problem rather than a preference — they are
// documented as experimental rather than claimed as accessibility support, and
// finishing that check is tracked in the roadmap.
//
// Anything added here appears in the cycle immediately: keep the help text in
// showHelp() and docs/configuration.md in step. TestShippedThemes pins the list,
// and TestSeverityColoursAreDistinctInEveryTheme holds every palette to the one
// rule that is a correctness problem rather than taste.
var themeBuilders = map[string]func() Theme{
	"dark":          themeDark,
	"light":         themeLight,
	"gruvbox":       themeGruvbox,
	"midnight":      themeMidnight,
	"high-contrast": themeHighContrast,
	"colorblind":    themeColorblind,
}

// themeNames returns the theme names in a stable cycle order.
func themeNames() []string {
	names := make([]string, 0, len(themeBuilders))
	for n := range themeBuilders {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// uiSettings is what persists between sessions. Kept separate from the LLM
// settings file so a bad provider config cannot cost you your theme.
type uiSettings struct {
	Theme        string   `json:"theme"`
	RecentCases  []string `json:"recent_cases,omitempty"`
	RecentPivots []string `json:"recent_pivots,omitempty"`

	// LastVisit is when the dashboard was last opened, so it can mark what has
	// arrived since. A dashboard you check ten times a shift is only useful if
	// it can say which of these you have already seen.
	LastVisit time.Time `json:"last_visit,omitempty"`

	// Preferences is everything the settings panel owns. Nested rather than
	// flattened so the fields above — which predate it and are written by other
	// code paths — are not disturbed, and so a file from an older build reads
	// as "every preference is default".
	Preferences preferences `json:"preferences,omitempty"`
}

const uiSettingsName = "ui_settings.json"

// loadThemeName returns the persisted theme, or the default if there is none,
// it cannot be read, or it names a theme that no longer ships.
//
// Every failure here is silent and falls back: a corrupt preferences file is
// not a reason to refuse to start.
// loadUISettings returns the persisted settings or empty defaults.
func loadUISettings() uiSettings {
	data, err := os.ReadFile(paths.Current().ConfigFile(uiSettingsName))
	if err != nil {
		return uiSettings{Theme: defaultThemeName}
	}
	var s uiSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return uiSettings{Theme: defaultThemeName}
	}
	if _, ok := themeBuilders[s.Theme]; !ok {
		s.Theme = defaultThemeName
	}
	return s
}

func loadThemeName() string {
	return loadUISettings().Theme
}

// ensureUISettings writes the settings file if there is not one yet, so a fresh
// installation lands on an explicit, editable preference rather than an
// implicit default. An existing file is never touched: the point is to create
// the file, not to reset a choice the analyst has already made.
func ensureUISettings() error {
	path := paths.Current().ConfigFile(uiSettingsName)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	data, err := json.MarshalIndent(uiSettings{Theme: defaultThemeName}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// saveUISettings persists the current theme. Failures are logged and ignored —
// losing a preference must never interrupt an investigation.
func (ui *UI) saveUISettings() {
	path := paths.Current().ConfigFile(uiSettingsName)
	settings := uiSettings{
		Theme:        ui.themeName,
		RecentCases:  ui.recentCases,
		RecentPivots: ui.recentPivots,
		LastVisit:    ui.lastVisit,
		Preferences:  ui.prefs,
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		ui.logger.Warn("could not encode UI settings: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		ui.logger.Warn("could not save UI settings to %s: %v", path, err)
	}
}
