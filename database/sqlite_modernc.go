//go:build moderncsqlite && !nosqlite

package database

import (
	_ "modernc.org/sqlite"
)

var sqliteDriver = "sqlite"

// Keep in sync with mattn counterpart.
const sqliteOptions = "_pragma=foreign_keys(true)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
