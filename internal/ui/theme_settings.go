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
// Five, each earning its place: dark and light cover the ordinary cases,
// gruvbox is the one palette people ask for by name, and high-contrast and
// cb-safe are accessibility. Since severity is colour-coded, red/green
// confusion is a correctness problem in an IR tool, not a preference.
var themeBuilders = map[string]func() Theme{
	"dark":          themeDark,
	"light":         themeLight,
	"gruvbox":       themeGruvbox,
	"high-contrast": themeHighContrast,
	"cb-safe":       themeColorblindSafe,
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
	Theme string `json:"theme"`
}

const uiSettingsName = "ui_settings.json"

// loadThemeName returns the persisted theme, or the default if there is none,
// it cannot be read, or it names a theme that no longer ships.
//
// Every failure here is silent and falls back: a corrupt preferences file is
// not a reason to refuse to start.
func loadThemeName() string {
	data, err := os.ReadFile(paths.Current().ConfigFile(uiSettingsName))
	if err != nil {
		return defaultThemeName
	}
	var s uiSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return defaultThemeName
	}
	if _, ok := themeBuilders[s.Theme]; !ok {
		return defaultThemeName
	}
	return s.Theme
}

// saveUISettings persists the current theme. Failures are logged and ignored —
// losing a preference must never interrupt an investigation.
func (ui *UI) saveUISettings() {
	path := paths.Current().ConfigFile(uiSettingsName)
	data, err := json.MarshalIndent(uiSettings{Theme: ui.themeName}, "", "  ")
	if err != nil {
		ui.logger.Warn("could not encode UI settings: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		ui.logger.Warn("could not save UI settings to %s: %v", path, err)
	}
}
