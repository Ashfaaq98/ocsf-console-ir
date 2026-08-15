package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
)

// withTempConfig points the process-wide config directory at a scratch dir.
func withTempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	saved := paths.Current()
	paths.Set(paths.Dirs{Data: dir, Config: dir, State: dir})
	t.Cleanup(func() { paths.Set(saved) })
	return dir
}

func TestShippedThemes(t *testing.T) {
	want := []string{"colorblind", "dark", "gruvbox", "high-contrast", "light", "midnight"}
	got := themeNames()

	if len(got) != len(want) {
		t.Fatalf("themes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("themes = %v, want %v", got, want)
		}
	}

	// The culled palettes must be gone, not merely unreferenced.
	for _, dropped := range []string{"neon", "gemini", "claude"} {
		if _, ok := themeBuilders[dropped]; ok {
			t.Errorf("%q is still registered", dropped)
		}
	}

	// Every registered theme must actually build.
	for name, build := range themeBuilders {
		if build == nil {
			t.Errorf("%s has no builder", name)
			continue
		}
		if theme := build(); theme.TagAccent == "" {
			t.Errorf("%s produced an empty theme", name)
		}
	}
}

// Severity is colour-coded, so two levels sharing a colour is a correctness
// problem in an IR tool, not an aesthetic one.
func TestSeverityColoursAreDistinctInEveryTheme(t *testing.T) {
	for name, build := range themeBuilders {
		th := build()
		seen := map[string]string{}
		for level, tag := range map[string]string{
			"critical": th.TagSeverityCritical,
			"high":     th.TagSeverityHigh,
			"medium":   th.TagSeverityMedium,
			"low":      th.TagSeverityLow,
			"info":     th.TagSeverityInfo,
		} {
			if prev, clash := seen[tag]; clash {
				t.Errorf("%s: %s and %s share the colour %s", name, prev, level, tag)
			}
			seen[tag] = level
		}
	}
}

// gruvbox has to be gruvbox — the theme it replaced only looked like it.
func TestGruvboxUsesPublishedValues(t *testing.T) {
	th := themeGruvbox()
	for _, c := range []struct {
		name, got, want string
	}{
		{"background", th.TagTextPrimary, "#ebdbb2"},
		{"accent (orange)", th.TagAccent, "#fe8019"},
		{"error (red)", th.TagError, "#fb4934"},
		{"success (green)", th.TagSuccess, "#b8bb26"},
		{"warning (yellow)", th.TagWarning, "#fabd2f"},
		{"muted (gray)", th.TagMuted, "#928374"},
	} {
		if c.got != c.want {
			t.Errorf("gruvbox %s = %s, want %s", c.name, c.got, c.want)
		}
	}
}

func TestThemeChoicePersistsAcrossSessions(t *testing.T) {
	dir := withTempConfig(t)

	ui := &UI{logger: logging.New(os.Stderr, logging.LevelError, "test")}
	ui.setTheme("gruvbox")

	if _, err := os.Stat(filepath.Join(dir, uiSettingsName)); err != nil {
		t.Fatalf("settings were not written: %v", err)
	}
	if got := loadThemeName(); got != "gruvbox" {
		t.Errorf("restored theme = %q, want gruvbox", got)
	}
}

// A preferences file is never a reason to refuse to start.
func TestThemeLoadFallsBackOnBadInput(t *testing.T) {
	dir := withTempConfig(t)
	path := filepath.Join(dir, uiSettingsName)

	for _, tc := range []struct{ name, content string }{
		{"corrupt JSON", "{not json"},
		{"unknown theme", `{"theme":"neon"}`},
		{"empty theme", `{"theme":""}`},
		{"empty file", ""},
	} {
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := loadThemeName(); got != defaultThemeName {
			t.Errorf("%s: loadThemeName() = %q, want the %q fallback", tc.name, got, defaultThemeName)
		}
	}

	// Missing entirely.
	os.Remove(path)
	if got := loadThemeName(); got != defaultThemeName {
		t.Errorf("no settings file: loadThemeName() = %q, want %q", got, defaultThemeName)
	}
}

func TestSettingsFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows has no Unix mode bits: a file created 0600 reports 666.
		// See docs/configuration.md for what that means for the API key.
		t.Skip("Windows uses ACLs rather than Unix mode bits")
	}
	dir := withTempConfig(t)
	ui := &UI{logger: logging.New(os.Stderr, logging.LevelError, "test")}
	ui.setTheme("light")

	info, err := os.Stat(filepath.Join(dir, uiSettingsName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("settings file mode = %o, want 600", perm)
	}
}

func TestSetThemeRejectsUnknownNames(t *testing.T) {
	withTempConfig(t)
	ui := &UI{logger: logging.New(os.Stderr, logging.LevelError, "test")}

	ui.setTheme("no-such-theme")
	if ui.themeName != defaultThemeName {
		t.Errorf("themeName = %q after an unknown name, want %q", ui.themeName, defaultThemeName)
	}
}

// The cycle must visit every theme exactly once and come back round.
func TestCycleThemeVisitsEveryThemeOnce(t *testing.T) {
	withTempConfig(t)
	ui := &UI{logger: logging.New(os.Stderr, logging.LevelError, "test")}
	ui.setTheme(defaultThemeName)

	seen := map[string]bool{ui.themeName: true}
	start := ui.themeName
	for i := 0; i < len(themeBuilders)-1; i++ {
		ui.cycleTheme()
		if seen[ui.themeName] {
			t.Fatalf("cycle revisited %q after %d steps", ui.themeName, i+1)
		}
		seen[ui.themeName] = true
	}

	ui.cycleTheme()
	if ui.themeName != start {
		t.Errorf("cycle ended on %q, want it to wrap back to %q", ui.themeName, start)
	}
	if len(seen) != len(themeBuilders) {
		t.Errorf("cycle visited %d of %d themes", len(seen), len(themeBuilders))
	}
}

func TestSettingsFileShape(t *testing.T) {
	dir := withTempConfig(t)
	ui := &UI{logger: logging.New(os.Stderr, logging.LevelError, "test")}
	ui.setTheme("gruvbox")

	data, err := os.ReadFile(filepath.Join(dir, uiSettingsName))
	if err != nil {
		t.Fatal(err)
	}
	var s uiSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("settings are not valid JSON: %v\n%s", err, data)
	}
	if s.Theme != "gruvbox" {
		t.Errorf("theme = %q", s.Theme)
	}
}
