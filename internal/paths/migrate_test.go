package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// chdirToTemp puts the test in a scratch working directory, since MigrateLegacy
// reads the legacy layout relative to it.
func chdirToTemp(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newDirs(t *testing.T) Dirs {
	t.Helper()
	base := t.TempDir()
	d := Dirs{
		Data:   filepath.Join(base, "data"),
		Config: filepath.Join(base, "config"),
		State:  filepath.Join(base, "logs"),
	}
	if err := d.MkdirAll(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestMigrateLegacyMovesDatabaseAndSidecars(t *testing.T) {
	chdirToTemp(t)
	d := newDirs(t)

	legacy := filepath.Join(legacyDataDir, DBName)
	write(t, legacy, "db")
	write(t, legacy+"-wal", "wal")
	write(t, legacy+"-shm", "shm")

	moved, err := MigrateLegacy(d)
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if len(moved) != 3 {
		t.Fatalf("moved %d files, want 3: %+v", len(moved), moved)
	}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(d.DB() + suffix); err != nil {
			t.Errorf("%s not at the new location: %v", DBName+suffix, err)
		}
		if _, err := os.Stat(legacy + suffix); !os.IsNotExist(err) {
			t.Errorf("%s still at the legacy location", DBName+suffix)
		}
	}

	// The contents must survive, not just the names.
	got, err := os.ReadFile(d.DB())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "db" {
		t.Errorf("database contents = %q, want %q", got, "db")
	}
}

func TestMigrateLegacyMovesLLMSettings(t *testing.T) {
	chdirToTemp(t)
	d := newDirs(t)

	legacy := filepath.Join(legacyConfigDir, LLMSettingsName)
	write(t, legacy, `{"active":{"api_key":"secret"}}`)

	moved, err := MigrateLegacy(d)
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if len(moved) != 1 {
		t.Fatalf("moved %d files, want 1: %+v", len(moved), moved)
	}
	if _, err := os.Stat(d.ConfigFile(LLMSettingsName)); err != nil {
		t.Errorf("settings not at the new location: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Error("settings still at the legacy location")
	}
}

// A second run must not clobber the database the first run produced — the user
// may have kept working in the legacy directory with an older binary.
func TestMigrateLegacyNeverOverwritesAnExistingDatabase(t *testing.T) {
	chdirToTemp(t)
	d := newDirs(t)

	write(t, filepath.Join(legacyDataDir, DBName), "legacy")
	write(t, d.DB(), "current")

	moved, err := MigrateLegacy(d)
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if len(moved) != 0 {
		t.Errorf("moved %+v, want nothing", moved)
	}
	got, err := os.ReadFile(d.DB())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "current" {
		t.Errorf("existing database was overwritten: contents = %q", got)
	}
}

func TestMigrateLegacyNoopWhenNothingToMove(t *testing.T) {
	chdirToTemp(t)
	d := newDirs(t)

	moved, err := MigrateLegacy(d)
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if len(moved) != 0 {
		t.Errorf("moved %+v on a clean install, want nothing", moved)
	}
}

// A WAL that cannot be moved must not leave the database orphaned from it.
func TestMigrateLegacyStopsWhenASidecarCannotMove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	chdirToTemp(t)
	d := newDirs(t)

	legacy := filepath.Join(legacyDataDir, DBName)
	write(t, legacy, "db")
	write(t, legacy+"-wal", "wal")

	// Make the destination unwritable so the second move in the group fails.
	// The first has already succeeded by then, which is what makes "stop, and
	// report" the right behaviour rather than "carry on".
	if err := os.Chmod(d.Data, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d.Data, 0o700) })

	moved, err := MigrateLegacy(d)
	if err == nil {
		t.Fatal("expected an error when the destination is unwritable")
	}
	if len(moved) != 0 {
		t.Errorf("reported %+v as moved, but nothing could be written", moved)
	}
	// Nothing was destroyed: the legacy files are still readable.
	if _, err := os.Stat(legacy); err != nil {
		t.Errorf("legacy database lost after a failed migration: %v", err)
	}
	if _, err := os.Stat(legacy + "-wal"); err != nil {
		t.Errorf("legacy WAL lost after a failed migration: %v", err)
	}
}
