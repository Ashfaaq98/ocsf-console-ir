package paths

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The layout pre-v0.2.0 builds created relative to the working directory.
const (
	legacyDataDir   = "data"
	legacyConfigDir = "config"
	legacyLogDir    = "logs"
)

// Migration records one file moved out of the legacy layout.
type Migration struct {
	From string
	To   string
}

// MigrateLegacy moves a pre-v0.2.0 working-directory database and LLM settings
// into d, if they exist there and d does not already hold them. Callers are
// expected to report the returned migrations: switching paths silently would
// look exactly like losing every case.
//
// A file that cannot be moved is left where it is and reported as an error, so
// a failed migration never destroys data.
func MigrateLegacy(d Dirs) ([]Migration, error) {
	var moved []Migration
	var errs []error

	// The database first, along with any WAL sidecars left by an unclean
	// shutdown. If one of the group fails to move the rest are abandoned:
	// a database separated from its WAL is worse than one left in place.
	legacyDB := filepath.Join(legacyDataDir, DBName)
	if exists(legacyDB) && !exists(d.DB()) {
		for _, src := range []string{legacyDB, legacyDB + "-wal", legacyDB + "-shm"} {
			if !exists(src) {
				continue
			}
			dst := filepath.Join(d.Data, filepath.Base(src))
			if err := move(src, dst); err != nil {
				errs = append(errs, err)
				break
			}
			moved = append(moved, Migration{From: src, To: dst})
		}
	}

	// Then the LLM settings, which is where the plaintext API key lives.
	legacyCfg := filepath.Join(legacyConfigDir, LLMSettingsName)
	if dst := d.ConfigFile(LLMSettingsName); exists(legacyCfg) && !exists(dst) {
		if err := move(legacyCfg, dst); err != nil {
			errs = append(errs, err)
		} else {
			moved = append(moved, Migration{From: legacyCfg, To: dst})
		}
	}

	return moved, errors.Join(errs...)
}

// move renames src to dst, falling back to copy-and-remove because os.Rename
// fails across filesystems — and $HOME is routinely a different mount from a
// working directory on a USB stick or a container volume.
func move(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("copied %s to %s but could not remove the original (it is now in both places): %w", src, dst, err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
