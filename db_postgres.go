package soju

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

const postgresConfigSchema = `
CREATE TABLE IF NOT EXISTS "Config" (
	id SMALLINT PRIMARY KEY,
	version INTEGER NOT NULL,
	CHECK(id = 1)
);
`

const postgresSchema = `
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

var postgresMigrations = []string{
	"", // migration #0 is reserved for schema initialization
}

type PostgresDB struct {
	db *sql.DB
}

func OpenPostgresDB(source string) (Database, error) {
	sqlPostgresDB, err := sql.Open("postgres", source)
	if err != nil {
		return nil, err
	}

	db := &PostgresDB{db: sqlPostgresDB}
	if err := db.upgrade(); err != nil {
		sqlPostgresDB.Close()
		return nil, err
	}

	return db, nil
}

func (db *PostgresDB) upgrade() error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(postgresConfigSchema); err != nil {
		return fmt.Errorf("failed to create Config table: %s", err)
	}

	var version int
	err = tx.QueryRow(`SELECT version FROM "Config"`).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to query schema version: %s", err)
	}

	if version == len(postgresMigrations) {
		return nil
	}
	if version > len(postgresMigrations) {
		return fmt.Errorf("soju (version %d) older than schema (version %d)", len(postgresMigrations), version)
	}

	if version == 0 {
		if _, err := tx.Exec(postgresSchema); err != nil {
			return fmt.Errorf("failed to initialize schema: %s", err)
		}
	} else {
		for i := version; i < len(postgresMigrations); i++ {
			if _, err := tx.Exec(postgresMigrations[i]); err != nil {
				return fmt.Errorf("failed to execute migration #%v: %v", i, err)
			}
		}
	}

	_, err = tx.Exec(`INSERT INTO "Config" (id, version) VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET version = $1`, len(postgresMigrations))
	if err != nil {
		return fmt.Errorf("failed to bump schema version: %v", err)
	}

	return tx.Commit()
}

func (db *PostgresDB) Close() error {
	return db.db.Close()
}

func (db *PostgresDB) Stats() (*DatabaseStats, error) {
	var stats DatabaseStats
	row := db.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM "User") AS users,
		(SELECT COUNT(*) FROM "Network") AS networks,
		(SELECT COUNT(*) FROM "Channel") AS channels`)
	if err := row.Scan(&stats.Users, &stats.Networks, &stats.Channels); err != nil {
		return nil, err
	}

	return &stats, nil
}

func (db *PostgresDB) ListUsers() ([]User, error) {
	rows, err := db.db.Query(`SELECT id, username, password, admin, realname FROM "User"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var password, realname sql.NullString
		if err := rows.Scan(&user.ID, &user.Username, &password, &user.Admin, &realname); err != nil {
			return nil, err
		}
		user.Password = password.String
		user.Realname = realname.String
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (db *PostgresDB) GetUser(username string) (*User, error) {
	user := &User{Username: username}

	var password, realname sql.NullString
	row := db.db.QueryRow(
		`SELECT id, password, admin, realname FROM "User" WHERE username = $1`,
		username)
	if err := row.Scan(&user.ID, &password, &user.Admin, &realname); err != nil {
		return nil, err
	}
	user.Password = password.String
	user.Realname = realname.String
	return user, nil
}

func (db *PostgresDB) StoreUser(user *User) error {
	password := toNullString(user.Password)
	realname := toNullString(user.Realname)

	var err error
	if user.ID == 0 {
		err = db.db.QueryRow(`
			INSERT INTO "User" (username, password, admin, realname)
			VALUES ($1, $2, $3, $4)
			RETURNING id`,
			user.Username, password, user.Admin, realname).Scan(&user.ID)
	} else {
		_, err = db.db.Exec(`
			UPDATE "User"
			SET password = $1, admin = $2, realname = $3
			WHERE id = $4`,
			password, user.Admin, realname, user.ID)
	}
	return err
}

func (db *PostgresDB) DeleteUser(id int64) error {
	_, err := db.db.Exec(`DELETE FROM "User" WHERE id = $1`, id)
	return err
}

func (db *PostgresDB) ListNetworks(userID int64) ([]Network, error) {
	rows, err := db.db.Query(`
		SELECT id, name, addr, nick, username, realname, pass, connect_commands, sasl_mechanism,
			sasl_plain_username, sasl_plain_password, sasl_external_cert, sasl_external_key, enabled
		FROM "Network"
		WHERE "user" = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []Network
	for rows.Next() {
		var net Network
		var name, username, realname, pass, connectCommands sql.NullString
		var saslMechanism, saslPlainUsername, saslPlainPassword sql.NullString
		err := rows.Scan(&net.ID, &name, &net.Addr, &net.Nick, &username, &realname,
			&pass, &connectCommands, &saslMechanism, &saslPlainUsername, &saslPlainPassword,
			&net.SASL.External.CertBlob, &net.SASL.External.PrivKeyBlob, &net.Enabled)
		if err != nil {
			return nil, err
		}
		net.Name = name.String
		net.Username = username.String
		net.Realname = realname.String
		net.Pass = pass.String
		if connectCommands.Valid {
			net.ConnectCommands = strings.Split(connectCommands.String, "\r\n")
		}
		net.SASL.Mechanism = saslMechanism.String
		net.SASL.Plain.Username = saslPlainUsername.String
		net.SASL.Plain.Password = saslPlainPassword.String
		networks = append(networks, net)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return networks, nil
}

func (db *PostgresDB) StoreNetwork(userID int64, network *Network) error {
	netName := toNullString(network.Name)
	netUsername := toNullString(network.Username)
	realname := toNullString(network.Realname)
	pass := toNullString(network.Pass)
	connectCommands := toNullString(strings.Join(network.ConnectCommands, "\r\n"))

	var saslMechanism, saslPlainUsername, saslPlainPassword sql.NullString
	if network.SASL.Mechanism != "" {
		saslMechanism = toNullString(network.SASL.Mechanism)
		switch network.SASL.Mechanism {
		case "PLAIN":
			saslPlainUsername = toNullString(network.SASL.Plain.Username)
			saslPlainPassword = toNullString(network.SASL.Plain.Password)
			network.SASL.External.CertBlob = nil
			network.SASL.External.PrivKeyBlob = nil
		case "EXTERNAL":
			// keep saslPlain* nil
		default:
			return fmt.Errorf("soju: cannot store network: unsupported SASL mechanism %q", network.SASL.Mechanism)
		}
	}

	var err error
	if network.ID == 0 {
		err = db.db.QueryRow(`
			INSERT INTO "Network" ("user", name, addr, nick, username, realname, pass, connect_commands,
				sasl_mechanism, sasl_plain_username, sasl_plain_password, sasl_external_cert,
				sasl_external_key, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			RETURNING id`,
			userID, netName, network.Addr, network.Nick, netUsername, realname, pass, connectCommands,
			saslMechanism, saslPlainUsername, saslPlainPassword, network.SASL.External.CertBlob,
			network.SASL.External.PrivKeyBlob, network.Enabled).Scan(&network.ID)
	} else {
		_, err = db.db.Exec(`
			UPDATE "Network"
			SET name = $2, addr = $3, nick = $4, username = $5, realname = $6, pass = $7,
				connect_commands = $8, sasl_mechanism = $9, sasl_plain_username = $10,
				sasl_plain_password = $11, sasl_external_cert = $12, sasl_external_key = $13,
				enabled = $14
			WHERE id = $1`,
			network.ID, netName, network.Addr, network.Nick, netUsername, realname, pass, connectCommands,
			saslMechanism, saslPlainUsername, saslPlainPassword, network.SASL.External.CertBlob,
			network.SASL.External.PrivKeyBlob, network.Enabled)
	}
	return err
}

func (db *PostgresDB) DeleteNetwork(id int64) error {
	_, err := db.db.Exec(`DELETE FROM "Network" WHERE id = $1`, id)
	return err
}

func (db *PostgresDB) ListChannels(networkID int64) ([]Channel, error) {
	rows, err := db.db.Query(`
		SELECT id, name, key, detached, detached_internal_msgid, relay_detached, reattach_on, detach_after,
			detach_on
		FROM "Channel"
		WHERE network = $1`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var channels []Channel
	for rows.Next() {
		var ch Channel
		var key, detachedInternalMsgID sql.NullString
		var detachAfter int64
		if err := rows.Scan(&ch.ID, &ch.Name, &key, &ch.Detached, &detachedInternalMsgID, &ch.RelayDetached, &ch.ReattachOn, &detachAfter, &ch.DetachOn); err != nil {
			return nil, err
		}
		ch.Key = key.String
		ch.DetachedInternalMsgID = detachedInternalMsgID.String
		ch.DetachAfter = time.Duration(detachAfter) * time.Second
		channels = append(channels, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return channels, nil
}

func (db *PostgresDB) StoreChannel(networkID int64, ch *Channel) error {
	key := toNullString(ch.Key)
	detachAfter := int64(math.Ceil(ch.DetachAfter.Seconds()))

	var err error
	if ch.ID == 0 {
		err = db.db.QueryRow(`
			INSERT INTO "Channel" (network, name, key, detached, detached_internal_msgid, relay_detached, reattach_on,
				detach_after, detach_on)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING id`,
			networkID, ch.Name, key, ch.Detached, toNullString(ch.DetachedInternalMsgID),
			ch.RelayDetached, ch.ReattachOn, detachAfter, ch.DetachOn).Scan(&ch.ID)
	} else {
		_, err = db.db.Exec(`
			UPDATE "Channel"
			SET name = $2, key = $3, detached = $4, detached_internal_msgid = $5,
				relay_detached = $6, reattach_on = $7, detach_after = $8, detach_on = $9
			WHERE id = $1`,
			ch.ID, ch.Name, key, ch.Detached, toNullString(ch.DetachedInternalMsgID),
			ch.RelayDetached, ch.ReattachOn, detachAfter, ch.DetachOn)
	}
	return err
}

func (db *PostgresDB) DeleteChannel(id int64) error {
	_, err := db.db.Exec(`DELETE FROM "Channel" WHERE id = $1`, id)
	return err
}

func (db *PostgresDB) ListDeliveryReceipts(networkID int64) ([]DeliveryReceipt, error) {
	rows, err := db.db.Query(`
		SELECT id, target, client, internal_msgid
		FROM "DeliveryReceipt"
		WHERE network = $1`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var receipts []DeliveryReceipt
	for rows.Next() {
		var rcpt DeliveryReceipt
		if err := rows.Scan(&rcpt.ID, &rcpt.Target, &rcpt.Client, &rcpt.InternalMsgID); err != nil {
			return nil, err
		}
		receipts = append(receipts, rcpt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return receipts, nil
}

func (db *PostgresDB) StoreClientDeliveryReceipts(networkID int64, client string, receipts []DeliveryReceipt) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM DeliveryReceipt WHERE network = $1 AND client = $2",
		networkID, client)
	if err != nil {
		return err
	}

	stmt, err := db.db.Prepare(`
		INSERT INTO "DeliveryReceipt" (network, target, client, internal_msgid)
		VALUES ($1, $2, $3, $4)
		RETURNING id`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range receipts {
		rcpt := &receipts[i]
		err := stmt.QueryRow(networkID, rcpt.Target, client, rcpt.InternalMsgID).Scan(&rcpt.ID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
