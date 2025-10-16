//go:build cgo
// +build cgo

package store

import (
	_ "github.com/mattn/go-sqlite3"
)

const sqliteDriver = "sqlite3"
