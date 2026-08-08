package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// What the screen can find out about this machine before it has a database.
//
// Every probe here is local, cheap and total: it reads one directory or one
// environment variable, and it has a defined answer for every failure. A first
// run has no database to fall back on, so a probe that panicked would be a
// crash on the first screen with nothing behind it.
//
// They run once, when the view is built, rather than per frame.

// welcomePathWidth caps how much of a path the brand column will show. Beyond
// this the column stops being a column and starts being a path.
const welcomePathWidth = 44

// probe reads what this machine can tell the screen.
func (v *welcomeView) probe() {
	v.watchStatus = watchFolderStatus(v.opts.WatchDir)
}

// watchFolderStatus describes the drop folder: which one, and whether anything
// is already sitting in it.
//
// "Watch a folder" is the one action whose usefulness depends entirely on a
// fact the analyst cannot see from here. Naming the folder and counting what is
// waiting turns a guess into a decision.
func watchFolderStatus(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	shown := shortenPath(dir, welcomePathWidth/2)

	entries, err := os.ReadDir(dir)
	if err != nil {
		// Not an error worth reporting on this screen: a folder that is not
		// there yet is the ordinary case on a first run, and the action itself
		// creates it. Anything else — a permission failure, a file where a
		// folder should be — is reported when the action runs and fails, where
		// there is room to say what went wrong.
		return shown + " · will be created"
	}

	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".json", ".jsonl":
			n++
		}
	}

	switch n {
	case 0:
		return shown + " · empty"
	case 1:
		return shown + " · 1 file waiting"
	default:
		return fmt.Sprintf("%s · %d files waiting", shown, n)
	}
}

// shortenPath abbreviates the home directory to ~ and elides the middle of
// anything still too long.
//
// The end is kept rather than the start: the tail is the filename and the last
// folder, which is the part that says which path this is.
func shortenPath(path string, max int) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if path == home {
			path = "~"
		} else if strings.HasPrefix(path, home+string(os.PathSeparator)) {
			path = "~" + path[len(home):]
		}
	}

	runes := []rune(path)
	if max < 8 || len(runes) <= max {
		return path
	}
	return "…" + string(runes[len(runes)-(max-1):])
}
