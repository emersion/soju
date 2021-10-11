package soju

import (
	"database/sql"
	"testing"
)

// SQLite version 0 schema. DO NOT EDIT.
const sqliteV0Schema = `
CREATE TABLE User (
	username VARCHAR(255) NOT NULL UNIQUE,
	password VARCHAR(255)
);

CREATE TABLE Network (
	id INTEGER PRIMARY KEY,
	name VARCHAR(255),
	user VARCHAR(255) NOT NULL,
	addr VARCHAR(255) NOT NULL,
	nick VARCHAR(255) NOT NULL,
	username VARCHAR(255),
	realname VARCHAR(255),
	pass VARCHAR(255),
	sasl_mechanism VARCHAR(255),
	sasl_plain_username VARCHAR(255),
	sasl_plain_password VARCHAR(255),
	UNIQUE(user, addr, nick),
	UNIQUE(user, name)
);

CREATE TABLE Channel (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	name VARCHAR(255) NOT NULL,
	key VARCHAR(255),
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, name)
);

PRAGMA user_version = 1;
`

func TestSqliteMigrations(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to create temporary SQLite database: %v", err)
	}

	if _, err := sqlDB.Exec(sqliteV0Schema); err != nil {
		t.Fatalf("DB.Exec() failed for v0 schema: %v", err)
	}

	db := &SqliteDB{db: sqlDB}
	defer db.Close()

	if err := db.upgrade(); err != nil {
		t.Fatalf("SqliteDB.Upgrade() failed: %v", err)
	}
}
