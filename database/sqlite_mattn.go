//go:build !moderncsqlite && !nosqlite

package database

import (
	_ "git.sr.ht/~emersion/go-sqlite3-fts5"
	_ "github.com/mattn/go-sqlite3"
)

var sqliteDriver = "sqlite3"
