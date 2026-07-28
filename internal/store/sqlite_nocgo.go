//go:build !cgo
// +build !cgo

package store

import (
	_ "modernc.org/sqlite"
)

const sqliteDriver = "sqlite"

// sqliteDSNParams configures WAL and foreign-key enforcement. modernc uses
// _pragma=name(value) rather than mattn's _journal_mode/_foreign_keys spelling;
// the mattn form is silently ignored here, which left foreign keys unenforced on
// the shipped CGO_ENABLED=0 build (so ON DELETE CASCADE / SET NULL never fired).
const sqliteDSNParams = "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
