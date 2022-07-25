package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
)

const postgresQueryTimeout = 5 * time.Second

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
	nick VARCHAR(255),
	realname VARCHAR(255)
);

CREATE TYPE sasl_mechanism AS ENUM ('PLAIN', 'EXTERNAL');

CREATE TABLE "Network" (
	id SERIAL PRIMARY KEY,
	name VARCHAR(255),
	"user" INTEGER NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
	addr VARCHAR(255) NOT NULL,
	nick VARCHAR(255),
	username VARCHAR(255),
	realname VARCHAR(255),
	pass VARCHAR(255),
	connect_commands VARCHAR(1023),
	sasl_mechanism sasl_mechanism,
	sasl_plain_username VARCHAR(255),
	sasl_plain_password VARCHAR(255),
	sasl_external_cert BYTEA,
	sasl_external_key BYTEA,
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

CREATE TABLE "ReadReceipt" (
	id SERIAL PRIMARY KEY,
	network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
	target VARCHAR(255) NOT NULL,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	UNIQUE(network, target)
);

CREATE TABLE "WebPushConfig" (
	id SERIAL PRIMARY KEY,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	vapid_key_public TEXT NOT NULL,
	vapid_key_private TEXT NOT NULL,
	UNIQUE(vapid_key_public)
);

CREATE TABLE "WebPushSubscription" (
	id SERIAL PRIMARY KEY,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	"user" INTEGER NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
	network INTEGER REFERENCES "Network"(id) ON DELETE CASCADE,
	endpoint TEXT NOT NULL,
	key_vapid TEXT,
	key_auth TEXT,
	key_p256dh TEXT,
	UNIQUE(network, endpoint)
);
`

var postgresMigrations = []string{
	"", // migration #0 is reserved for schema initialization
	`ALTER TABLE "Network" ALTER COLUMN nick DROP NOT NULL`,
	`
		CREATE TYPE sasl_mechanism AS ENUM ('PLAIN', 'EXTERNAL');
		ALTER TABLE "Network"
			ALTER COLUMN sasl_mechanism
			TYPE sasl_mechanism
			USING sasl_mechanism::sasl_mechanism;
	`,
	`
		CREATE TABLE "ReadReceipt" (
			id SERIAL PRIMARY KEY,
			network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
			target VARCHAR(255) NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			UNIQUE(network, target)
		);
	`,
	`
		CREATE TABLE "WebPushConfig" (
			id SERIAL PRIMARY KEY,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			vapid_key_public TEXT NOT NULL,
			vapid_key_private TEXT NOT NULL,
			UNIQUE(vapid_key_public)
		);

		CREATE TABLE "WebPushSubscription" (
			id SERIAL PRIMARY KEY,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
			network INTEGER REFERENCES "Network"(id) ON DELETE CASCADE,
			endpoint TEXT NOT NULL,
			key_vapid TEXT,
			key_auth TEXT,
			key_p256dh TEXT,
			UNIQUE(network, endpoint)
		);
	`,
	`
		ALTER TABLE "WebPushSubscription"
		ADD COLUMN "user" INTEGER
		REFERENCES "User"(id) ON DELETE CASCADE
	`,
	`ALTER TABLE "User" ADD COLUMN nick VARCHAR(255)`,
	// Before this migration, a bug swapped user and network, so empty the
	// web push subscriptions table
	`
		DELETE FROM "WebPushSubscription";
		ALTER TABLE "WebPushSubscription"
		ALTER COLUMN "user"
		SET NOT NULL;
	`,
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

func openTempPostgresDB(source string) (*sql.DB, error) {
	db, err := sql.Open("postgres", source)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}

	// Store all tables in a temporary schema which will be dropped when the
	// connection to PostgreSQL is closed.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("SET search_path TO pg_temp"); err != nil {
		return nil, fmt.Errorf("failed to set PostgreSQL search_path: %v", err)
	}

	return db, nil
}

func OpenTempPostgresDB(source string) (Database, error) {
	sqlPostgresDB, err := openTempPostgresDB(source)
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

func (db *PostgresDB) RegisterMetrics(r prometheus.Registerer) error {
	if err := r.Register(&postgresMetricsCollector{db}); err != nil {
		return err
	}
	return r.Register(promcollectors.NewDBStatsCollector(db.db, "main"))
}

func (db *PostgresDB) Stats(ctx context.Context) (*DatabaseStats, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	var stats DatabaseStats
	row := db.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM "User") AS users,
		(SELECT COUNT(*) FROM "Network") AS networks,
		(SELECT COUNT(*) FROM "Channel") AS channels`)
	if err := row.Scan(&stats.Users, &stats.Networks, &stats.Channels); err != nil {
		return nil, err
	}

	return &stats, nil
}

func (db *PostgresDB) ListUsers(ctx context.Context) ([]User, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx,
		`SELECT id, username, password, admin, nick, realname FROM "User"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var password, nick, realname sql.NullString
		if err := rows.Scan(&user.ID, &user.Username, &password, &user.Admin, &nick, &realname); err != nil {
			return nil, err
		}
		user.Password = password.String
		user.Nick = nick.String
		user.Realname = realname.String
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (db *PostgresDB) GetUser(ctx context.Context, username string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	user := &User{Username: username}

	var password, nick, realname sql.NullString
	row := db.db.QueryRowContext(ctx,
		`SELECT id, password, admin, nick, realname FROM "User" WHERE username = $1`,
		username)
	if err := row.Scan(&user.ID, &password, &user.Admin, &nick, &realname); err != nil {
		return nil, err
	}
	user.Password = password.String
	user.Nick = nick.String
	user.Realname = realname.String
	return user, nil
}

func (db *PostgresDB) StoreUser(ctx context.Context, user *User) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	password := toNullString(user.Password)
	nick := toNullString(user.Nick)
	realname := toNullString(user.Realname)

	var err error
	if user.ID == 0 {
		err = db.db.QueryRowContext(ctx, `
			INSERT INTO "User" (username, password, admin, nick, realname)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id`,
			user.Username, password, user.Admin, nick, realname).Scan(&user.ID)
	} else {
		_, err = db.db.ExecContext(ctx, `
			UPDATE "User"
			SET password = $1, admin = $2, nick = $3, realname = $4
			WHERE id = $5`,
			password, user.Admin, nick, realname, user.ID)
	}
	return err
}

func (db *PostgresDB) DeleteUser(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	_, err := db.db.ExecContext(ctx, `DELETE FROM "User" WHERE id = $1`, id)
	return err
}

func (db *PostgresDB) ListNetworks(ctx context.Context, userID int64) ([]Network, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
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
		var name, nick, username, realname, pass, connectCommands sql.NullString
		var saslMechanism, saslPlainUsername, saslPlainPassword sql.NullString
		err := rows.Scan(&net.ID, &name, &net.Addr, &nick, &username, &realname,
			&pass, &connectCommands, &saslMechanism, &saslPlainUsername, &saslPlainPassword,
			&net.SASL.External.CertBlob, &net.SASL.External.PrivKeyBlob, &net.Enabled)
		if err != nil {
			return nil, err
		}
		net.Name = name.String
		net.Nick = nick.String
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

func (db *PostgresDB) StoreNetwork(ctx context.Context, userID int64, network *Network) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	netName := toNullString(network.Name)
	nick := toNullString(network.Nick)
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
		err = db.db.QueryRowContext(ctx, `
			INSERT INTO "Network" ("user", name, addr, nick, username, realname, pass, connect_commands,
				sasl_mechanism, sasl_plain_username, sasl_plain_password, sasl_external_cert,
				sasl_external_key, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			RETURNING id`,
			userID, netName, network.Addr, nick, netUsername, realname, pass, connectCommands,
			saslMechanism, saslPlainUsername, saslPlainPassword, network.SASL.External.CertBlob,
			network.SASL.External.PrivKeyBlob, network.Enabled).Scan(&network.ID)
	} else {
		_, err = db.db.ExecContext(ctx, `
			UPDATE "Network"
			SET name = $2, addr = $3, nick = $4, username = $5, realname = $6, pass = $7,
				connect_commands = $8, sasl_mechanism = $9, sasl_plain_username = $10,
				sasl_plain_password = $11, sasl_external_cert = $12, sasl_external_key = $13,
				enabled = $14
			WHERE id = $1`,
			network.ID, netName, network.Addr, nick, netUsername, realname, pass, connectCommands,
			saslMechanism, saslPlainUsername, saslPlainPassword, network.SASL.External.CertBlob,
			network.SASL.External.PrivKeyBlob, network.Enabled)
	}
	return err
}

func (db *PostgresDB) DeleteNetwork(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	_, err := db.db.ExecContext(ctx, `DELETE FROM "Network" WHERE id = $1`, id)
	return err
}

func (db *PostgresDB) ListChannels(ctx context.Context, networkID int64) ([]Channel, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
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

func (db *PostgresDB) StoreChannel(ctx context.Context, networkID int64, ch *Channel) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	key := toNullString(ch.Key)
	detachAfter := int64(math.Ceil(ch.DetachAfter.Seconds()))

	var err error
	if ch.ID == 0 {
		err = db.db.QueryRowContext(ctx, `
			INSERT INTO "Channel" (network, name, key, detached, detached_internal_msgid, relay_detached, reattach_on,
				detach_after, detach_on)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING id`,
			networkID, ch.Name, key, ch.Detached, toNullString(ch.DetachedInternalMsgID),
			ch.RelayDetached, ch.ReattachOn, detachAfter, ch.DetachOn).Scan(&ch.ID)
	} else {
		_, err = db.db.ExecContext(ctx, `
			UPDATE "Channel"
			SET name = $2, key = $3, detached = $4, detached_internal_msgid = $5,
				relay_detached = $6, reattach_on = $7, detach_after = $8, detach_on = $9
			WHERE id = $1`,
			ch.ID, ch.Name, key, ch.Detached, toNullString(ch.DetachedInternalMsgID),
			ch.RelayDetached, ch.ReattachOn, detachAfter, ch.DetachOn)
	}
	return err
}

func (db *PostgresDB) DeleteChannel(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	_, err := db.db.ExecContext(ctx, `DELETE FROM "Channel" WHERE id = $1`, id)
	return err
}

func (db *PostgresDB) ListDeliveryReceipts(ctx context.Context, networkID int64) ([]DeliveryReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
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

func (db *PostgresDB) StoreClientDeliveryReceipts(ctx context.Context, networkID int64, client string, receipts []DeliveryReceipt) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`DELETE FROM "DeliveryReceipt" WHERE network = $1 AND client = $2`,
		networkID, client)
	if err != nil {
		return err
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO "DeliveryReceipt" (network, target, client, internal_msgid)
		VALUES ($1, $2, $3, $4)
		RETURNING id`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range receipts {
		rcpt := &receipts[i]
		err := stmt.
			QueryRowContext(ctx, networkID, rcpt.Target, client, rcpt.InternalMsgID).
			Scan(&rcpt.ID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *PostgresDB) GetReadReceipt(ctx context.Context, networkID int64, name string) (*ReadReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	receipt := &ReadReceipt{
		Target: name,
	}

	row := db.db.QueryRowContext(ctx,
		`SELECT id, timestamp FROM "ReadReceipt" WHERE network = $1 AND target = $2`,
		networkID, name)
	if err := row.Scan(&receipt.ID, &receipt.Timestamp); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return receipt, nil
}

func (db *PostgresDB) StoreReadReceipt(ctx context.Context, networkID int64, receipt *ReadReceipt) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	var err error
	if receipt.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE "ReadReceipt"
			SET timestamp = $1
			WHERE id = $2`,
			receipt.Timestamp, receipt.ID)
	} else {
		err = db.db.QueryRowContext(ctx, `
			INSERT INTO "ReadReceipt" (network, target, timestamp)
			VALUES ($1, $2, $3)
			RETURNING id`,
			networkID, receipt.Target, receipt.Timestamp).Scan(&receipt.ID)
	}
	return err
}

func (db *PostgresDB) listTopNetworkAddrs(ctx context.Context) (map[string]int, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	addrs := make(map[string]int)

	rows, err := db.db.QueryContext(ctx, `
		SELECT addr, COUNT(addr) AS n
		FROM "Network"
		GROUP BY addr
		ORDER BY n DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			addr string
			n    int
		)
		if err := rows.Scan(&addr, &n); err != nil {
			return nil, err
		}
		addrs[addr] = n
	}

	return addrs, rows.Err()
}

func (db *PostgresDB) ListWebPushConfigs(ctx context.Context) ([]WebPushConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, vapid_key_public, vapid_key_private
		FROM "WebPushConfig"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []WebPushConfig
	for rows.Next() {
		var config WebPushConfig
		if err := rows.Scan(&config.ID, &config.VAPIDKeys.Public, &config.VAPIDKeys.Private); err != nil {
			return nil, err
		}
		configs = append(configs, config)
	}

	return configs, rows.Err()
}

func (db *PostgresDB) StoreWebPushConfig(ctx context.Context, config *WebPushConfig) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	if config.ID != 0 {
		return fmt.Errorf("cannot update a WebPushConfig")
	}

	err := db.db.QueryRowContext(ctx, `
		INSERT INTO "WebPushConfig" (created_at, vapid_key_public, vapid_key_private)
		VALUES (NOW(), $1, $2)
		RETURNING id`,
		config.VAPIDKeys.Public, config.VAPIDKeys.Private).Scan(&config.ID)
	return err
}

func (db *PostgresDB) ListWebPushSubscriptions(ctx context.Context, userID, networkID int64) ([]WebPushSubscription, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	nullNetworkID := sql.NullInt64{
		Int64: networkID,
		Valid: networkID == 0,
	}

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, endpoint, key_auth, key_p256dh, key_vapid
		FROM "WebPushSubscription"
		WHERE "user" = $1 AND network IS NOT DISTINCT FROM $2`, userID, nullNetworkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []WebPushSubscription
	for rows.Next() {
		var sub WebPushSubscription
		if err := rows.Scan(&sub.ID, &sub.Endpoint, &sub.Keys.Auth, &sub.Keys.P256DH, &sub.Keys.VAPID); err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}

	return subs, rows.Err()
}

func (db *PostgresDB) StoreWebPushSubscription(ctx context.Context, userID, networkID int64, sub *WebPushSubscription) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	nullNetworkID := sql.NullInt64{
		Int64: networkID,
		Valid: networkID == 0,
	}

	var err error
	if sub.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE "WebPushSubscription"
			SET updated_at = NOW(), key_auth = $1, key_p256dh = $2,
				key_vapid = $3
			WHERE id = $4`,
			sub.Keys.Auth, sub.Keys.P256DH, sub.Keys.VAPID, sub.ID)
	} else {
		err = db.db.QueryRowContext(ctx, `
			INSERT INTO "WebPushSubscription" (created_at, updated_at, "user",
				network, endpoint, key_auth, key_p256dh, key_vapid)
			VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, $6)
			RETURNING id`,
			userID, nullNetworkID, sub.Endpoint, sub.Keys.Auth, sub.Keys.P256DH,
			sub.Keys.VAPID).Scan(&sub.ID)
	}

	return err
}

func (db *PostgresDB) DeleteWebPushSubscription(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()

	_, err := db.db.ExecContext(ctx, `DELETE FROM "WebPushSubscription" WHERE id = $1`, id)
	return err
}

var postgresNetworksTotalDesc = prometheus.NewDesc("soju_networks_total", "Number of networks", []string{"hostname"}, nil)

type postgresMetricsCollector struct {
	db *PostgresDB
}

var _ prometheus.Collector = (*postgresMetricsCollector)(nil)

func (c *postgresMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- postgresNetworksTotalDesc
}

func (c *postgresMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	addrs, err := c.db.listTopNetworkAddrs(context.TODO())
	if err != nil {
		ch <- prometheus.NewInvalidMetric(postgresNetworksTotalDesc, err)
		return
	}

	// Group by hostname
	hostnames := make(map[string]int)
	for addr, n := range addrs {
		hostname := addr
		network := Network{Addr: addr}
		if u, err := network.URL(); err == nil {
			hostname = u.Hostname()
		}
		hostnames[hostname] += n
	}

	// Group networks with low counts for privacy
	watermark := 10
	grouped := 0
	for hostname, n := range hostnames {
		if n >= watermark && hostname != "" && hostname != "*" {
			ch <- prometheus.MustNewConstMetric(postgresNetworksTotalDesc, prometheus.GaugeValue, float64(n), hostname)
		} else {
			grouped += n
		}
	}
	if grouped > 0 {
		ch <- prometheus.MustNewConstMetric(postgresNetworksTotalDesc, prometheus.GaugeValue, float64(grouped), "*")
	}
}
