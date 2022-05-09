package database

import (
	"os"
	"testing"
)

// PostgreSQL version 0 schema. DO NOT EDIT.
const postgresV0Schema = `
CREATE TABLE "Config" (
	id SMALLINT PRIMARY KEY,
	version INTEGER NOT NULL,
	CHECK(id = 1)
);

INSERT INTO "Config" (id, version) VALUES (1, 1);

CREATE TABLE "User" (
	id SERIAL PRIMARY KEY,
	username VARCHAR(255) NOT NULL UNIQUE,
	password VARCHAR(255),
	admin BOOLEAN NOT NULL DEFAULT FALSE,
	realname VARCHAR(255)
);

CREATE TABLE "Network" (
	id SERIAL PRIMARY KEY,
	name VARCHAR(255),
	"user" INTEGER NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
	addr VARCHAR(255) NOT NULL,
	nick VARCHAR(255) NOT NULL,
	username VARCHAR(255),
	realname VARCHAR(255),
	pass VARCHAR(255),
	connect_commands VARCHAR(1023),
	sasl_mechanism VARCHAR(255),
	sasl_plain_username VARCHAR(255),
	sasl_plain_password VARCHAR(255),
	sasl_external_cert BYTEA DEFAULT NULL,
	sasl_external_key BYTEA DEFAULT NULL,
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	UNIQUE("user", addr, nick),
	UNIQUE("user", name)
);

CREATE TABLE "Channel" (
	id SERIAL PRIMARY KEY,
	network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
	name VARCHAR(255) NOT NULL,
	key VARCHAR(255),
	detached BOOLEAN NOT NULL DEFAULT FALSE,
	detached_internal_msgid VARCHAR(255),
	relay_detached INTEGER NOT NULL DEFAULT 0,
	reattach_on INTEGER NOT NULL DEFAULT 0,
	detach_after INTEGER NOT NULL DEFAULT 0,
	detach_on INTEGER NOT NULL DEFAULT 0,
	UNIQUE(network, name)
);

CREATE TABLE "DeliveryReceipt" (
	id SERIAL PRIMARY KEY,
	network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
	target VARCHAR(255) NOT NULL,
	client VARCHAR(255) NOT NULL DEFAULT '',
	internal_msgid VARCHAR(255) NOT NULL,
	UNIQUE(network, target, client)
);
`

func TestPostgresMigrations(t *testing.T) {
	source, ok := os.LookupEnv("SOJU_TEST_POSTGRES")
	if !ok {
		t.Skip("set SOJU_TEST_POSTGRES to a connection string to execute PostgreSQL tests")
	}

	sqlDB, err := openTempPostgresDB(source)
	if err != nil {
		t.Fatalf("openTempPostgresDB() failed: %v", err)
	}

	if _, err := sqlDB.Exec(postgresV0Schema); err != nil {
		t.Fatalf("DB.Exec() failed for v0 schema: %v", err)
	}

	db := &PostgresDB{db: sqlDB}
	defer db.Close()

	if err := db.upgrade(); err != nil {
		t.Fatalf("PostgresDB.Upgrade() failed: %v", err)
	}
}
