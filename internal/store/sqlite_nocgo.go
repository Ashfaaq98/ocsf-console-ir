//go:build !cgo
// +build !cgo

package store

import (
	_ "modernc.org/sqlite"
)

const sqliteDriver = "sqlite"

// sqliteDSNParams configures WAL, foreign-key enforcement and write locking.
// modernc uses _pragma=name(value) rather than mattn's _journal_mode/_foreign_keys
// spelling; the mattn form is silently ignored here, which left foreign keys
// unenforced on the shipped CGO_ENABLED=0 build (so ON DELETE CASCADE / SET NULL
// never fired). See sqliteBusyTimeoutMS for what the last two settle.
const sqliteDSNParams = "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" +
	"&_pragma=busy_timeout(5000)&_txlock=immediate"
