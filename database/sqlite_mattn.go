//go:build !moderncsqlite && !nosqlite

package database

import (
	_ "git.sr.ht/~emersion/go-sqlite3-fts5"
	_ "github.com/mattn/go-sqlite3"
)

var sqliteDriver = "sqlite3"

// See https://kerkour.com/sqlite-for-servers
// Keep in sync with modernc counterpart.
const sqliteOptions = "_foreign_keys=true&_busy_timeout=5000&_journal_mode=WAL&_synchronous=NORMAL&_txlock=immediate"
