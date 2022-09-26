//go:build moderncsqlite && !nosqlite

package database

import (
	_ "modernc.org/sqlite"
)

var sqliteDriver = "sqlite"
