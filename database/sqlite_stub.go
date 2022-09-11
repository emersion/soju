//go:build nosqlite

package database

import (
	"errors"
)

const SqliteEnabled = false

func OpenSqliteDB(source string) (Database, error) {
	return nil, errors.New("SQLite support is disabled")
}

func OpenTempSqliteDB() (Database, error) {
	return OpenSqliteDB("")
}
