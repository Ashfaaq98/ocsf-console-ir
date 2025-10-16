//go:build !cgo
// +build !cgo

package store

import (
	_ "modernc.org/sqlite"
)

const sqliteDriver = "sqlite"
