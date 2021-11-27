package database

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
)

const sqliteQueryTimeout = 5 * time.Second

const sqliteTimeLayout = "2006-01-02T15:04:05.000Z"

func formatSqliteTime(t time.Time) string {
	return t.UTC().Format(sqliteTimeLayout)
}

const sqliteSchema = `
CREATE TABLE User (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password TEXT,
	admin INTEGER NOT NULL DEFAULT 0,
	realname TEXT
);

CREATE TABLE Network (
	id INTEGER PRIMARY KEY,
	name TEXT,
	user INTEGER NOT NULL,
	addr TEXT NOT NULL,
	nick TEXT,
	username TEXT,
	realname TEXT,
	pass TEXT,
	connect_commands TEXT,
	sasl_mechanism TEXT,
	sasl_plain_username TEXT,
	sasl_plain_password TEXT,
	sasl_external_cert BLOB,
	sasl_external_key BLOB,
	enabled INTEGER NOT NULL DEFAULT 1,
	FOREIGN KEY(user) REFERENCES User(id),
	UNIQUE(user, addr, nick),
	UNIQUE(user, name)
);

CREATE TABLE Channel (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	name TEXT NOT NULL,
	key TEXT,
	detached INTEGER NOT NULL DEFAULT 0,
	detached_internal_msgid TEXT,
	relay_detached INTEGER NOT NULL DEFAULT 0,
	reattach_on INTEGER NOT NULL DEFAULT 0,
	detach_after INTEGER NOT NULL DEFAULT 0,
	detach_on INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, name)
);

CREATE TABLE DeliveryReceipt (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	target TEXT NOT NULL,
	client TEXT,
	internal_msgid TEXT NOT NULL,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, target, client)
);

CREATE TABLE ReadReceipt (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	target TEXT NOT NULL,
	timestamp TEXT NOT NULL,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, target)
);

CREATE TABLE WebPushConfig (
	id INTEGER PRIMARY KEY,
	created_at TEXT NOT NULL,
	vapid_key_public TEXT NOT NULL,
	vapid_key_private TEXT NOT NULL,
	UNIQUE(vapid_key_public)
);

CREATE TABLE WebPushSubscription (
	id INTEGER PRIMARY KEY,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	network INTEGER,
	endpoint TEXT NOT NULL,
	key_vapid TEXT,
	key_auth TEXT,
	key_p256dh TEXT,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, endpoint)
);
`

var sqliteMigrations = []string{
	"", // migration #0 is reserved for schema initialization
	"ALTER TABLE Network ADD COLUMN connect_commands VARCHAR(1023)",
	"ALTER TABLE Channel ADD COLUMN detached INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE Network ADD COLUMN sasl_external_cert BLOB DEFAULT NULL",
	"ALTER TABLE Network ADD COLUMN sasl_external_key BLOB DEFAULT NULL",
	"ALTER TABLE User ADD COLUMN admin INTEGER NOT NULL DEFAULT 0",
	`
		CREATE TABLE UserNew (
			id INTEGER PRIMARY KEY,
			username VARCHAR(255) NOT NULL UNIQUE,
			password VARCHAR(255),
			admin INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO UserNew SELECT rowid, username, password, admin FROM User;
		DROP TABLE User;
		ALTER TABLE UserNew RENAME TO User;
	`,
	`
		CREATE TABLE NetworkNew (
			id INTEGER PRIMARY KEY,
			name VARCHAR(255),
			user INTEGER NOT NULL,
			addr VARCHAR(255) NOT NULL,
			nick VARCHAR(255) NOT NULL,
			username VARCHAR(255),
			realname VARCHAR(255),
			pass VARCHAR(255),
			connect_commands VARCHAR(1023),
			sasl_mechanism VARCHAR(255),
			sasl_plain_username VARCHAR(255),
			sasl_plain_password VARCHAR(255),
			sasl_external_cert BLOB DEFAULT NULL,
			sasl_external_key BLOB DEFAULT NULL,
			FOREIGN KEY(user) REFERENCES User(id),
			UNIQUE(user, addr, nick),
			UNIQUE(user, name)
		);
		INSERT INTO NetworkNew
			SELECT Network.id, name, User.id as user, addr, nick,
				Network.username, realname, pass, connect_commands,
				sasl_mechanism, sasl_plain_username, sasl_plain_password,
				sasl_external_cert, sasl_external_key
			FROM Network
			JOIN User ON Network.user = User.username;
		DROP TABLE Network;
		ALTER TABLE NetworkNew RENAME TO Network;
	`,
	`
		ALTER TABLE Channel ADD COLUMN relay_detached INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE Channel ADD COLUMN reattach_on INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE Channel ADD COLUMN detach_after INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE Channel ADD COLUMN detach_on INTEGER NOT NULL DEFAULT 0;
	`,
	`
		CREATE TABLE DeliveryReceipt (
			id INTEGER PRIMARY KEY,
			network INTEGER NOT NULL,
			target VARCHAR(255) NOT NULL,
			client VARCHAR(255),
			internal_msgid VARCHAR(255) NOT NULL,
			FOREIGN KEY(network) REFERENCES Network(id),
			UNIQUE(network, target, client)
		);
	`,
	"ALTER TABLE Channel ADD COLUMN detached_internal_msgid VARCHAR(255)",
	"ALTER TABLE Network ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
	"ALTER TABLE User ADD COLUMN realname VARCHAR(255)",
	`
		CREATE TABLE NetworkNew (
			id INTEGER PRIMARY KEY,
			name TEXT,
			user INTEGER NOT NULL,
			addr TEXT NOT NULL,
			nick TEXT,
			username TEXT,
			realname TEXT,
			pass TEXT,
			connect_commands TEXT,
			sasl_mechanism TEXT,
			sasl_plain_username TEXT,
			sasl_plain_password TEXT,
			sasl_external_cert BLOB,
			sasl_external_key BLOB,
			enabled INTEGER NOT NULL DEFAULT 1,
			FOREIGN KEY(user) REFERENCES User(id),
			UNIQUE(user, addr, nick),
			UNIQUE(user, name)
		);
		INSERT INTO NetworkNew
			SELECT id, name, user, addr, nick, username, realname, pass,
				connect_commands, sasl_mechanism, sasl_plain_username,
				sasl_plain_password, sasl_external_cert, sasl_external_key,
				enabled
			FROM Network;
		DROP TABLE Network;
		ALTER TABLE NetworkNew RENAME TO Network;
	`,
	`
		CREATE TABLE ReadReceipt (
			id INTEGER PRIMARY KEY,
			network INTEGER NOT NULL,
			target TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			FOREIGN KEY(network) REFERENCES Network(id),
			UNIQUE(network, target)
		);
	`,
	`
		CREATE TABLE WebPushConfig (
			id INTEGER PRIMARY KEY,
			created_at TEXT NOT NULL,
			vapid_key_public TEXT NOT NULL,
			vapid_key_private TEXT NOT NULL,
			UNIQUE(vapid_key_public)
		);

		CREATE TABLE WebPushSubscription (
			id INTEGER PRIMARY KEY,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			network INTEGER,
			endpoint TEXT NOT NULL,
			key_vapid TEXT,
			key_auth TEXT,
			key_p256dh TEXT,
			FOREIGN KEY(network) REFERENCES Network(id),
			UNIQUE(network, endpoint)
		);
	`,
}

type SqliteDB struct {
	db *sql.DB
}

func OpenSqliteDB(source string) (Database, error) {
	// Open the DB with cache=shared and SetMaxOpenConns(1) to allow usage from
	// multiple goroutines
	sqlSqliteDB, err := sql.Open("sqlite3", source+"?cache=shared")
	if err != nil {
		return nil, err
	}
	sqlSqliteDB.SetMaxOpenConns(1)

	db := &SqliteDB{db: sqlSqliteDB}
	if err := db.upgrade(); err != nil {
		sqlSqliteDB.Close()
		return nil, err
	}

	return db, nil
}

func OpenTempSqliteDB() (Database, error) {
	// :memory: will open a separate database for each new connection. Make
	// sure the sql package only uses a single connection via SetMaxOpenConns.
	// An alternative solution is to use "file::memory:?cache=shared".
	return OpenSqliteDB(":memory:")
}

func (db *SqliteDB) Close() error {
	return db.db.Close()
}

func (db *SqliteDB) upgrade() error {
	var version int
	if err := db.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("failed to query schema version: %v", err)
	}

	if version == len(sqliteMigrations) {
		return nil
	} else if version > len(sqliteMigrations) {
		return fmt.Errorf("soju (version %d) older than schema (version %d)", len(sqliteMigrations), version)
	}

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if version == 0 {
		if _, err := tx.Exec(sqliteSchema); err != nil {
			return fmt.Errorf("failed to initialize schema: %v", err)
		}
	} else {
		for i := version; i < len(sqliteMigrations); i++ {
			if _, err := tx.Exec(sqliteMigrations[i]); err != nil {
				return fmt.Errorf("failed to execute migration #%v: %v", i, err)
			}
		}
	}

	// For some reason prepared statements don't work here
	_, err = tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", len(sqliteMigrations)))
	if err != nil {
		return fmt.Errorf("failed to bump schema version: %v", err)
	}

	return tx.Commit()
}

func (db *SqliteDB) RegisterMetrics(r prometheus.Registerer) error {
	return r.Register(promcollectors.NewDBStatsCollector(db.db, "main"))
}

func (db *SqliteDB) Stats(ctx context.Context) (*DatabaseStats, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	var stats DatabaseStats
	row := db.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM User) AS users,
		(SELECT COUNT(*) FROM Network) AS networks,
		(SELECT COUNT(*) FROM Channel) AS channels`)
	if err := row.Scan(&stats.Users, &stats.Networks, &stats.Channels); err != nil {
		return nil, err
	}

	return &stats, nil
}

func toNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}

func (db *SqliteDB) ListUsers(ctx context.Context) ([]User, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx,
		"SELECT id, username, password, admin, realname FROM User")
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

func (db *SqliteDB) GetUser(ctx context.Context, username string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	user := &User{Username: username}

	var password, realname sql.NullString
	row := db.db.QueryRowContext(ctx,
		"SELECT id, password, admin, realname FROM User WHERE username = ?",
		username)
	if err := row.Scan(&user.ID, &password, &user.Admin, &realname); err != nil {
		return nil, err
	}
	user.Password = password.String
	user.Realname = realname.String
	return user, nil
}

func (db *SqliteDB) StoreUser(ctx context.Context, user *User) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("username", user.Username),
		sql.Named("password", toNullString(user.Password)),
		sql.Named("admin", user.Admin),
		sql.Named("realname", toNullString(user.Realname)),
	}

	var err error
	if user.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE User SET password = :password, admin = :admin,
				realname = :realname WHERE username = :username`,
			args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `
			INSERT INTO
			User(username, password, admin, realname)
			VALUES (:username, :password, :admin, :realname)`,
			args...)
		if err != nil {
			return err
		}
		user.ID, err = res.LastInsertId()
	}

	return err
}

func (db *SqliteDB) DeleteUser(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `DELETE FROM DeliveryReceipt
		WHERE id IN (
			SELECT DeliveryReceipt.id
			FROM DeliveryReceipt
			JOIN Network ON DeliveryReceipt.network = Network.id
			WHERE Network.user = ?
		)`, id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM ReadReceipt
		WHERE id IN (
			SELECT ReadReceipt.id
			FROM ReadReceipt
			JOIN Network ON ReadReceipt.network = Network.id
			WHERE Network.user = ?
		)`, id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM Channel
		WHERE id IN (
			SELECT Channel.id
			FROM Channel
			JOIN Network ON Channel.network = Network.id
			WHERE Network.user = ?
		)`, id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM Network WHERE user = ?", id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM User WHERE id = ?", id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (db *SqliteDB) ListNetworks(ctx context.Context, userID int64) ([]Network, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, name, addr, nick, username, realname, pass,
			connect_commands, sasl_mechanism, sasl_plain_username, sasl_plain_password,
			sasl_external_cert, sasl_external_key, enabled
		FROM Network
		WHERE user = ?`,
		userID)
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

func (db *SqliteDB) StoreNetwork(ctx context.Context, userID int64, network *Network) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

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

	args := []interface{}{
		sql.Named("name", toNullString(network.Name)),
		sql.Named("addr", network.Addr),
		sql.Named("nick", toNullString(network.Nick)),
		sql.Named("username", toNullString(network.Username)),
		sql.Named("realname", toNullString(network.Realname)),
		sql.Named("pass", toNullString(network.Pass)),
		sql.Named("connect_commands", toNullString(strings.Join(network.ConnectCommands, "\r\n"))),
		sql.Named("sasl_mechanism", saslMechanism),
		sql.Named("sasl_plain_username", saslPlainUsername),
		sql.Named("sasl_plain_password", saslPlainPassword),
		sql.Named("sasl_external_cert", network.SASL.External.CertBlob),
		sql.Named("sasl_external_key", network.SASL.External.PrivKeyBlob),
		sql.Named("enabled", network.Enabled),

		sql.Named("id", network.ID), // only for UPDATE
		sql.Named("user", userID),   // only for INSERT
	}

	var err error
	if network.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE Network
			SET name = :name, addr = :addr, nick = :nick, username = :username,
				realname = :realname, pass = :pass, connect_commands = :connect_commands,
				sasl_mechanism = :sasl_mechanism, sasl_plain_username = :sasl_plain_username, sasl_plain_password = :sasl_plain_password,
				sasl_external_cert = :sasl_external_cert, sasl_external_key = :sasl_external_key,
				enabled = :enabled
			WHERE id = :id`, args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `
			INSERT INTO Network(user, name, addr, nick, username, realname, pass,
				connect_commands, sasl_mechanism, sasl_plain_username,
				sasl_plain_password, sasl_external_cert, sasl_external_key, enabled)
			VALUES (:user, :name, :addr, :nick, :username, :realname, :pass,
				:connect_commands, :sasl_mechanism, :sasl_plain_username,
				:sasl_plain_password, :sasl_external_cert, :sasl_external_key, :enabled)`,
			args...)
		if err != nil {
			return err
		}
		network.ID, err = res.LastInsertId()
	}
	return err
}

func (db *SqliteDB) DeleteNetwork(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "DELETE FROM WebPushSubscription WHERE network = ?", id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM DeliveryReceipt WHERE network = ?", id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM ReadReceipt WHERE network = ?", id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM Channel WHERE network = ?", id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM Network WHERE id = ?", id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (db *SqliteDB) ListChannels(ctx context.Context, networkID int64) ([]Channel, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `SELECT
			id, name, key, detached, detached_internal_msgid,
			relay_detached, reattach_on, detach_after, detach_on
		FROM Channel
		WHERE network = ?`, networkID)
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

func (db *SqliteDB) StoreChannel(ctx context.Context, networkID int64, ch *Channel) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("network", networkID),
		sql.Named("name", ch.Name),
		sql.Named("key", toNullString(ch.Key)),
		sql.Named("detached", ch.Detached),
		sql.Named("detached_internal_msgid", toNullString(ch.DetachedInternalMsgID)),
		sql.Named("relay_detached", ch.RelayDetached),
		sql.Named("reattach_on", ch.ReattachOn),
		sql.Named("detach_after", int64(math.Ceil(ch.DetachAfter.Seconds()))),
		sql.Named("detach_on", ch.DetachOn),

		sql.Named("id", ch.ID), // only for UPDATE
	}

	var err error
	if ch.ID != 0 {
		_, err = db.db.ExecContext(ctx, `UPDATE Channel
			SET network = :network, name = :name, key = :key, detached = :detached,
				detached_internal_msgid = :detached_internal_msgid, relay_detached = :relay_detached,
				reattach_on = :reattach_on, detach_after = :detach_after, detach_on = :detach_on
			WHERE id = :id`, args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `INSERT INTO Channel(network, name, key, detached, detached_internal_msgid, relay_detached, reattach_on, detach_after, detach_on)
			VALUES (:network, :name, :key, :detached, :detached_internal_msgid, :relay_detached, :reattach_on, :detach_after, :detach_on)`, args...)
		if err != nil {
			return err
		}
		ch.ID, err = res.LastInsertId()
	}
	return err
}

func (db *SqliteDB) DeleteChannel(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	_, err := db.db.ExecContext(ctx, "DELETE FROM Channel WHERE id = ?", id)
	return err
}

func (db *SqliteDB) ListDeliveryReceipts(ctx context.Context, networkID int64) ([]DeliveryReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, target, client, internal_msgid
		FROM DeliveryReceipt
		WHERE network = ?`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var receipts []DeliveryReceipt
	for rows.Next() {
		var rcpt DeliveryReceipt
		var client sql.NullString
		if err := rows.Scan(&rcpt.ID, &rcpt.Target, &client, &rcpt.InternalMsgID); err != nil {
			return nil, err
		}
		rcpt.Client = client.String
		receipts = append(receipts, rcpt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return receipts, nil
}

func (db *SqliteDB) StoreClientDeliveryReceipts(ctx context.Context, networkID int64, client string, receipts []DeliveryReceipt) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "DELETE FROM DeliveryReceipt WHERE network = ? AND client IS ?",
		networkID, toNullString(client))
	if err != nil {
		return err
	}

	for i := range receipts {
		rcpt := &receipts[i]

		res, err := tx.ExecContext(ctx, `
			INSERT INTO DeliveryReceipt(network, target, client, internal_msgid)
			VALUES (:network, :target, :client, :internal_msgid)`,
			sql.Named("network", networkID),
			sql.Named("target", rcpt.Target),
			sql.Named("client", toNullString(client)),
			sql.Named("internal_msgid", rcpt.InternalMsgID))
		if err != nil {
			return err
		}
		rcpt.ID, err = res.LastInsertId()
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *SqliteDB) GetReadReceipt(ctx context.Context, networkID int64, name string) (*ReadReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	receipt := &ReadReceipt{
		Target: name,
	}

	row := db.db.QueryRowContext(ctx, `
		SELECT id, timestamp FROM ReadReceipt WHERE network = :network AND target = :target`,
		sql.Named("network", networkID),
		sql.Named("target", name),
	)
	var timestamp string
	if err := row.Scan(&receipt.ID, &timestamp); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if t, err := time.Parse(sqliteTimeLayout, timestamp); err != nil {
		return nil, err
	} else {
		receipt.Timestamp = t
	}
	return receipt, nil
}

func (db *SqliteDB) StoreReadReceipt(ctx context.Context, networkID int64, receipt *ReadReceipt) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("id", receipt.ID),
		sql.Named("timestamp", formatSqliteTime(receipt.Timestamp)),
		sql.Named("network", networkID),
		sql.Named("target", receipt.Target),
	}

	var err error
	if receipt.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE ReadReceipt SET timestamp = :timestamp WHERE id = :id`,
			args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `
			INSERT INTO
			ReadReceipt(network, target, timestamp)
			VALUES (:network, :target, :timestamp)`,
			args...)
		if err != nil {
			return err
		}
		receipt.ID, err = res.LastInsertId()
	}

	return err
}

func (db *SqliteDB) ListWebPushConfigs(ctx context.Context) ([]WebPushConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, vapid_key_public, vapid_key_private
		FROM WebPushConfig`)
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

func (db *SqliteDB) StoreWebPushConfig(ctx context.Context, config *WebPushConfig) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	if config.ID != 0 {
		return fmt.Errorf("cannot update a WebPushConfig")
	}

	res, err := db.db.ExecContext(ctx, `
		INSERT INTO WebPushConfig(created_at, vapid_key_public, vapid_key_private)
		VALUES (:now, :vapid_key_public, :vapid_key_private)`,
		sql.Named("vapid_key_public", config.VAPIDKeys.Public),
		sql.Named("vapid_key_private", config.VAPIDKeys.Private),
		sql.Named("now", formatSqliteTime(time.Now())))
	if err != nil {
		return err
	}
	config.ID, err = res.LastInsertId()
	return err
}

func (db *SqliteDB) ListWebPushSubscriptions(ctx context.Context, networkID int64) ([]WebPushSubscription, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	nullNetworkID := sql.NullInt64{
		Int64: networkID,
		Valid: networkID != 0,
	}

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, endpoint, key_auth, key_p256dh, key_vapid
		FROM WebPushSubscription
		WHERE network IS ?`, nullNetworkID)
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

func (db *SqliteDB) StoreWebPushSubscription(ctx context.Context, networkID int64, sub *WebPushSubscription) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("id", sub.ID),
		sql.Named("network", sql.NullInt64{
			Int64: networkID,
			Valid: networkID != 0,
		}),
		sql.Named("now", formatSqliteTime(time.Now())),
		sql.Named("endpoint", sub.Endpoint),
		sql.Named("key_auth", sub.Keys.Auth),
		sql.Named("key_p256dh", sub.Keys.P256DH),
		sql.Named("key_vapid", sub.Keys.VAPID),
	}

	var err error
	if sub.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE WebPushSubscription
			SET updated_at = :now, key_auth = :key_auth, key_p256dh = :key_p256dh,
				key_vapid = :key_vapid
			WHERE id = :id`,
			args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `
			INSERT INTO
			WebPushSubscription(created_at, updated_at, network, endpoint,
				key_auth, key_p256dh, key_vapid)
			VALUES (:now, :now, :network, :endpoint, :key_auth, :key_p256dh,
				:key_vapid)`,
			args...)
		if err != nil {
			return err
		}
		sub.ID, err = res.LastInsertId()
	}

	return err
}

func (db *SqliteDB) DeleteWebPushSubscription(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	_, err := db.db.ExecContext(ctx, "DELETE FROM WebPushSubscription WHERE id = ?", id)
	return err
}
