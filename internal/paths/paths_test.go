package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestResolveHonoursXDG covers the property the whole package exists for: the
// resolved directories must not depend on the working directory.
func TestResolveHonoursXDG(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "share"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(base, "state"))

	d := Resolve(Options{})
	if got, want := d.Data, filepath.Join(base, "share", appDir); got != want {
		t.Errorf("Data = %q, want %q", got, want)
	}
	if got, want := d.Config, filepath.Join(base, "config", appDir); got != want {
		t.Errorf("Config = %q, want %q", got, want)
	}
	if got, want := d.State, filepath.Join(base, "state", appDir); got != want {
		t.Errorf("State = %q, want %q", got, want)
	}
	if got, want := d.DB(), filepath.Join(base, "share", appDir, DBName); got != want {
		t.Errorf("DB() = %q, want %q", got, want)
	}
}

// TestResolveIsWorkingDirectoryIndependent is the regression test for the bug
// this item fixes: the same user got a different, empty database per directory.
func TestResolveIsWorkingDirectoryIndependent(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "share"))

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	first := Resolve(Options{}).DB()

	elsewhere := t.TempDir()
	if err := os.Chdir(elsewhere); err != nil {
		t.Fatal(err)
	}
	second := Resolve(Options{}).DB()

	if first != second {
		t.Errorf("database path changed with the working directory: %q then %q", first, second)
	}
}

func TestResolveOverridesWinOverEverything(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/should/not/be/used")

	d := Resolve(Options{Data: "/explicit/data", Config: "/explicit/config", State: "/explicit/logs"})
	if d.Data != "/explicit/data" || d.Config != "/explicit/config" || d.State != "/explicit/logs" {
		t.Errorf("overrides ignored: %+v", d)
	}

	// Overrides must also beat portable mode, so --data-dir works with --portable.
	p := Resolve(Options{Portable: true, Data: "/explicit/data"})
	if p.Data != "/explicit/data" {
		t.Errorf("Portable overrode an explicit --data-dir: %q", p.Data)
	}
	if p.Config != legacyConfigDir {
		t.Errorf("Portable Config = %q, want %q", p.Config, legacyConfigDir)
	}
}

func TestResolvePortableRestoresLegacyLayout(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/should/not/be/used")

	d := Resolve(Options{Portable: true})
	if d.Data != legacyDataDir || d.Config != legacyConfigDir || d.State != legacyLogDir {
		t.Errorf("portable layout = %+v, want the legacy relative directories", d)
	}
}

func TestMkdirAllIsPrivate(t *testing.T) {
	requireUnixPermissions(t)

	base := t.TempDir()
	d := Dirs{
		Data:   filepath.Join(base, "data"),
		Config: filepath.Join(base, "config"),
		State:  filepath.Join(base, "logs"),
	}
	if err := d.MkdirAll(); err != nil {
		t.Fatal(err)
	}
	// The config directory can hold a plaintext LLM API key.
	info, err := os.Stat(d.Config)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("config dir mode = %o, want 700", perm)
	}
}

func TestCurrentDefaultsAndSet(t *testing.T) {
	mu.Lock()
	saved := current
	current = nil
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		current = saved
		mu.Unlock()
	})

	// Current resolves defaults rather than returning a zero value, so packages
	// that never call Set still get usable paths.
	if got := Current(); got.Data == "" || got.Config == "" || got.State == "" {
		t.Fatalf("Current() returned an empty dir before Set: %+v", got)
	}

	want := Dirs{Data: "/a", Config: "/b", State: "/c"}
	Set(want)
	if got := Current(); got != want {
		t.Errorf("Current() = %+v, want %+v", got, want)
	}
}

// requireUnixPermissions skips a test that asserts on Unix mode bits.
//
// Windows has no such thing — it uses access control lists, and Go reports 777
// for a directory created with 0700. Skipping is honest where pretending would
// not be: the 0700 the code asks for genuinely does not protect a config
// directory on Windows, and that limit is documented rather than papered over.
func requireUnixPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses ACLs rather than Unix mode bits; see docs/configuration.md")
	}
}
