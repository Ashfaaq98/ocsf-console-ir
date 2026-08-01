package ui

import (
	"encoding/json"
	"os"
	"sort"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
)

// defaultThemeName is what a fresh install starts on. A plain dark theme is
// what a terminal user expects; the previous default was a neon palette, which
// is a strong opinion to impose before anyone has chosen anything.
const defaultThemeName = "dark"

// themeBuilders is the registry of shipped themes.
//
// Three: dark and light cover the ordinary cases, and gruvbox is the one
// palette people ask for by name.
//
// The high-contrast and colourblind-safe palettes were dropped for now. They
// are worth bringing back — severity is colour-coded here, so red/green
// confusion is a correctness problem rather than a preference — but neither had
// been checked against every screen, and shipping an accessibility theme that
// has not been verified is worse than not claiming one. Tracked in the roadmap.
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
