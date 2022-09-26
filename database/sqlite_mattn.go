//go:build !moderncsqlite && !nosqlite

package database

import (
	_ "github.com/mattn/go-sqlite3"
)

var sqliteDriver = "sqlite3"
