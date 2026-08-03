//go:build cgo
// +build cgo

package store

import (
	_ "github.com/mattn/go-sqlite3"
)

const sqliteDriver = "sqlite3"

// sqliteDSNParams configures WAL, foreign-key enforcement and write locking.
// The two drivers take different DSN syntax, so this must stay alongside the
// driver selection: mattn reads _journal_mode/_foreign_keys/_busy_timeout,
// modernc reads _pragma=...(). Passing one driver's spelling to the other is
// silently ignored, which is how foreign keys ended up unenforced on the shipped
// CGO_ENABLED=0 build. See sqliteBusyTimeoutMS for what the last two settle.
const sqliteDSNParams = "?_journal_mode=WAL&_foreign_keys=on" +
	"&_busy_timeout=5000&_txlock=immediate"
