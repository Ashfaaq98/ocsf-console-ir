// Package paths resolves the per-user directories Console-IR keeps its
// database, configuration and logs in.
//
// Before v0.2.0 every path resolved against the current working directory, so
// an installed binary opened a different, empty database per directory. That is
// indistinguishable from having lost every case, and it scattered plaintext LLM
// API keys into whatever folder the binary happened to be launched from. Paths
// now resolve to stable per-user locations; Options.Portable restores the old
// layout for USB sticks and jump boxes.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// appDir is the per-user subdirectory created under every base location.
const appDir = "console-ir"

// DBName is the database file created inside the data directory.
const DBName = "console-ir.db"

// LLMSettingsName is the provider configuration created inside the config
// directory. It can hold an API key, which is why config dirs are 0700.
const LLMSettingsName = "llm_settings.json"

// Dirs are the resolved runtime directories.
type Dirs struct {
	Data   string // the SQLite database
	Config string // llm_settings.json and friends
	State  string // logs
}

// Options select where Dirs point. A non-empty override always wins; Portable
// restores the pre-v0.2.0 working-directory layout for the overrides left empty.
type Options struct {
	Data     string
	Config   string
	State    string
	Portable bool
}

// DB is the default database path inside the data directory.
func (d Dirs) DB() string { return filepath.Join(d.Data, DBName) }

// ConfigFile names a file inside the config directory.
func (d Dirs) ConfigFile(name string) string { return filepath.Join(d.Config, name) }

// LogFile names a file inside the state directory.
func (d Dirs) LogFile(name string) string { return filepath.Join(d.State, name) }

// Resolve computes the runtime directories without creating them.
func Resolve(o Options) Dirs {
	d := Dirs{Data: o.Data, Config: o.Config, State: o.State}
	if o.Portable {
		if d.Data == "" {
			d.Data = legacyDataDir
		}
		if d.Config == "" {
			d.Config = legacyConfigDir
		}
		if d.State == "" {
			d.State = legacyLogDir
		}
		return d
	}
	if d.Data == "" {
		d.Data = defaultData()
	}
	if d.Config == "" {
		d.Config = defaultConfig()
	}
	if d.State == "" {
		d.State = defaultState()
	}
	return d
}

// MkdirAll creates the resolved directories. They are 0700 because the config
// directory can hold API keys and the data directory holds investigation data.
func (d Dirs) MkdirAll() error {
	for _, p := range []string{d.Data, d.Config, d.State} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", p, err)
		}
	}
	return nil
}

var (
	mu      sync.RWMutex
	current *Dirs
)

// Set installs the process-wide directories. The CLI calls this once during
// initialisation, before anything opens a database or a log.
func Set(d Dirs) {
	mu.Lock()
	current = &d
	mu.Unlock()
}

// Current returns the process-wide directories, resolving defaults on first use
// so packages that never call Set (tests, library use) still get sane paths.
func Current() Dirs {
	mu.RLock()
	d := current
	mu.RUnlock()
	if d != nil {
		return *d
	}

	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		r := Resolve(Options{})
		current = &r
	}
	return *current
}

// defaultData resolves the database directory. XDG_DATA_HOME is honoured on
// every platform — it is set deliberately, so it should win even on macOS.
func defaultData() string {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, appDir)
	}
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, appDir)
		}
	case "darwin":
		if h := home(); h != "" {
			return filepath.Join(h, "Library", "Application Support", appDir)
		}
	}
	if h := home(); h != "" {
		return filepath.Join(h, ".local", "share", appDir)
	}
	return legacyDataDir
}

func defaultConfig() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, appDir)
	}
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, appDir)
		}
	case "darwin":
		if h := home(); h != "" {
			return filepath.Join(h, "Library", "Application Support", appDir)
		}
	}
	if h := home(); h != "" {
		return filepath.Join(h, ".config", appDir)
	}
	return legacyConfigDir
}

func defaultState() string {
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, appDir)
	}
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, appDir, "logs")
		}
	case "darwin":
		if h := home(); h != "" {
			return filepath.Join(h, "Library", "Logs", appDir)
		}
	}
	if h := home(); h != "" {
		return filepath.Join(h, ".local", "state", appDir)
	}
	return legacyLogDir
}

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}
