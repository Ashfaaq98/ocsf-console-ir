package store

// SQLiteDriverName exposes the compiled-in driver name to external tests, which
// need it to open a database directly and simulate a pre-migration state.
func SQLiteDriverName() string { return sqliteDriver }
