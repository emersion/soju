//go:build !nosqlite

package database

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"gopkg.in/irc.v4"

	"codeberg.org/emersion/soju/xirc"
)

const SqliteEnabled = true

const sqliteQueryTimeout = 5 * time.Second

const sqliteTimeLayout = "2006-01-02T15:04:05.000Z"
const sqliteTimeFormat = "%Y-%m-%dT%H:%M:%fZ"

type sqliteTime struct {
	time.Time
}

var (
	_ sql.Scanner      = (*sqliteTime)(nil)
	_ sqldriver.Valuer = sqliteTime{}
)

func (t *sqliteTime) Scan(value interface{}) error {
	if value == nil {
		t.Time = time.Time{}
		return nil
	}
	if s, ok := value.(string); ok {
		tt, err := time.Parse(sqliteTimeLayout, s)
		if err != nil {
			return err
		}
		t.Time = tt
		return nil
	}
	return fmt.Errorf("cannot scan time from type %T", value)
}

func (t sqliteTime) Value() (sqldriver.Value, error) {
	if t.Time.IsZero() {
		return nil, nil
	}
	return t.UTC().Format(sqliteTimeLayout), nil
}

//go:embed sqlite_schema.sql
var sqliteSchema string

type SqliteDB struct {
	db *sql.DB
}

func OpenSqliteDB(source string) (Database, error) {
	sqlSqliteDB, err := sql.Open(sqliteDriver, source+"?"+sqliteOptions)
	if err != nil {
		return nil, err
	}

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
	db, err := OpenSqliteDB(":memory:")
	if err != nil {
		return nil, err
	}

	db.(*SqliteDB).db.SetMaxOpenConns(1)

	return db, nil
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

func (db *SqliteDB) isErrUnique(err error) bool {
	var sqliteErr *sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique
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

func (db *SqliteDB) ListUsers(ctx context.Context) ([]User, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx,
		`SELECT id, username, password, admin, nick, realname, enabled,
			downstream_interacted_at, max_networks
		FROM User`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var password, nick, realname sql.NullString
		var downstreamInteractedAt sqliteTime
		if err := rows.Scan(&user.ID, &user.Username, &password, &user.Admin, &nick, &realname, &user.Enabled, &downstreamInteractedAt, &user.MaxNetworks); err != nil {
			return nil, err
		}
		user.Password = password.String
		user.Nick = nick.String
		user.Realname = realname.String
		user.DownstreamInteractedAt = downstreamInteractedAt.Time
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

	var password, nick, realname sql.NullString
	var downstreamInteractedAt sqliteTime
	row := db.db.QueryRowContext(ctx,
		`SELECT id, password, admin, nick, realname, enabled,
			downstream_interacted_at, max_networks
		FROM User
		WHERE username = ?`,
		username)
	if err := row.Scan(&user.ID, &password, &user.Admin, &nick, &realname, &user.Enabled, &downstreamInteractedAt, &user.MaxNetworks); err != nil {
		return nil, err
	}
	user.Password = password.String
	user.Nick = nick.String
	user.Realname = realname.String
	user.DownstreamInteractedAt = downstreamInteractedAt.Time
	return user, nil
}

func (db *SqliteDB) GetUsernameByID(ctx context.Context, id int64) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	var username string
	row := db.db.QueryRowContext(ctx,
		`SELECT username
		FROM User
		WHERE id = ?`,
		id)
	if err := row.Scan(&username); err != nil {
		return "", err
	}
	return username, nil
}

func (db *SqliteDB) ListInactiveUsernames(ctx context.Context, limit time.Time) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx,
		"SELECT username FROM User WHERE coalesce(downstream_interacted_at, created_at) < ?",
		sqliteTime{limit})
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usernames []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, err
		}
		usernames = append(usernames, username)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return usernames, nil
}

func (db *SqliteDB) StoreUser(ctx context.Context, user *User) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("username", user.Username),
		sql.Named("password", toNullString(user.Password)),
		sql.Named("admin", user.Admin),
		sql.Named("nick", toNullString(user.Nick)),
		sql.Named("realname", toNullString(user.Realname)),
		sql.Named("enabled", user.Enabled),
		sql.Named("now", sqliteTime{time.Now()}),
		sql.Named("downstream_interacted_at", sqliteTime{user.DownstreamInteractedAt}),
		sql.Named("max_networks", user.MaxNetworks),
	}

	var err error
	if user.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE User
			SET password = :password, admin = :admin, nick = :nick,
				realname = :realname, enabled = :enabled,
				downstream_interacted_at = :downstream_interacted_at,
				max_networks = :max_networks
			WHERE username = :username`,
			args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `
			INSERT INTO
			User(username, password, admin, nick, realname, created_at,
				enabled, downstream_interacted_at, max_networks)
			VALUES (:username, :password, :admin, :nick, :realname, :now,
				:enabled, :downstream_interacted_at, :max_networks)`,
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

	_, err = tx.ExecContext(ctx, `DELETE FROM Message
		WHERE id IN (
			SELECT Message.id
			FROM Message, MessageTarget, Network
			WHERE Message.target = MessageTarget.id
			AND MessageTarget.network = Network.id
			AND Network.user = ?
		)`, id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM MessageTarget
		WHERE id IN (
			SELECT MessageTarget.id
			FROM MessageTarget, Network
			WHERE MessageTarget.network = Network.id
			AND Network.user = ?
		)`, id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM WebPushSubscription
		WHERE user = ?`, id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM DeviceCertificate
		WHERE user = ?`, id)
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
		SELECT id, name, addr, nick, username, realname, certfp, pass,
			connect_commands, sasl_mechanism, sasl_plain_username, sasl_plain_password,
			sasl_external_cert, sasl_external_key, auto_away, enabled
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
		var name, nick, username, realname, certfp, pass, connectCommands sql.NullString
		var saslMechanism, saslPlainUsername, saslPlainPassword sql.NullString
		err := rows.Scan(&net.ID, &name, &net.Addr, &nick, &username, &realname, &certfp,
			&pass, &connectCommands, &saslMechanism, &saslPlainUsername, &saslPlainPassword,
			&net.SASL.External.CertBlob, &net.SASL.External.PrivKeyBlob, &net.AutoAway, &net.Enabled)
		if err != nil {
			return nil, err
		}
		net.Name = name.String
		net.Nick = nick.String
		net.Username = username.String
		net.Realname = realname.String
		net.CertFP = certfp.String
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
		sql.Named("certfp", toNullString(network.CertFP)),
		sql.Named("pass", toNullString(network.Pass)),
		sql.Named("connect_commands", toNullString(strings.Join(network.ConnectCommands, "\r\n"))),
		sql.Named("sasl_mechanism", saslMechanism),
		sql.Named("sasl_plain_username", saslPlainUsername),
		sql.Named("sasl_plain_password", saslPlainPassword),
		sql.Named("sasl_external_cert", network.SASL.External.CertBlob),
		sql.Named("sasl_external_key", network.SASL.External.PrivKeyBlob),
		sql.Named("auto_away", network.AutoAway),
		sql.Named("enabled", network.Enabled),

		sql.Named("id", network.ID), // only for UPDATE
		sql.Named("user", userID),   // only for INSERT
	}

	var err error
	if network.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE Network
			SET name = :name, addr = :addr, nick = :nick, username = :username,
				realname = :realname, certfp = :certfp, pass = :pass, connect_commands = :connect_commands,
				sasl_mechanism = :sasl_mechanism, sasl_plain_username = :sasl_plain_username, sasl_plain_password = :sasl_plain_password,
				sasl_external_cert = :sasl_external_cert, sasl_external_key = :sasl_external_key,
				auto_away = :auto_away, enabled = :enabled
			WHERE id = :id`, args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `
			INSERT INTO Network(user, name, addr, nick, username, realname, certfp, pass,
				connect_commands, sasl_mechanism, sasl_plain_username,
				sasl_plain_password, sasl_external_cert, sasl_external_key, auto_away, enabled)
			VALUES (:user, :name, :addr, :nick, :username, :realname, :certfp, :pass,
				:connect_commands, :sasl_mechanism, :sasl_plain_username,
				:sasl_plain_password, :sasl_external_cert, :sasl_external_key, :auto_away, :enabled)`,
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

	_, err = tx.ExecContext(ctx, "DELETE FROM Message WHERE target IN (SELECT id FROM MessageTarget WHERE network = ?)", id)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM MessageTarget WHERE network = ?", id)
	if err != nil {
		return err
	}

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

func (db *SqliteDB) GetDeviceCertificate(ctx context.Context, fingerprint []byte) (int64, *DeviceCertificate, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	var user int64
	cert := &DeviceCertificate{
		Fingerprint: fingerprint,
	}
	var lastUsed sqliteTime
	err := db.db.QueryRowContext(ctx, `
		SELECT user, id, label, last_used, last_ip
		FROM DeviceCertificate
		WHERE fingerprint = ?`, fingerprint).Scan(&user, &cert.ID, &cert.Label, &lastUsed, &cert.LastIP)
	if err == sql.ErrNoRows {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	cert.LastUsed = lastUsed.Time
	return user, cert, nil
}

func (db *SqliteDB) ListDeviceCertificates(ctx context.Context, userID int64) ([]DeviceCertificate, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, label, fingerprint, last_used, last_ip
		FROM DeviceCertificate
		WHERE user = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []DeviceCertificate
	for rows.Next() {
		var cert DeviceCertificate
		var lastUsed sqliteTime
		if err := rows.Scan(&cert.ID, &cert.Label, &cert.Fingerprint, &lastUsed, &cert.LastIP); err != nil {
			return nil, err
		}
		cert.LastUsed = lastUsed.Time
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return certs, nil
}

func (db *SqliteDB) StoreDeviceCertificate(ctx context.Context, userID int64, cert *DeviceCertificate) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("label", cert.Label),
		sql.Named("fingerprint", cert.Fingerprint),
		sql.Named("last_used", sqliteTime{cert.LastUsed}),
		sql.Named("last_ip", cert.LastIP),

		sql.Named("id", cert.ID),  // only for UPDATE
		sql.Named("user", userID), // only for INSERT
	}

	var err error
	if cert.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE DeviceCertificate
			SET label = :label, fingerprint = :fingerprint, last_used = :last_used, last_ip = :last_ip
			WHERE id = :id`,
			args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `
			INSERT INTO DeviceCertificate(user, label, fingerprint, last_used, last_ip)
			VALUES (:user, :label, :fingerprint, :last_used, :last_ip)`,
			args...)
		if err != nil {
			return err
		}
		cert.ID, err = res.LastInsertId()
	}
	if db.isErrUnique(err) {
		return ErrDuplicateDeviceCertificate
	}
	return err
}

func (db *SqliteDB) DeleteDeviceCertificate(ctx context.Context, userID int64, fingerprint []byte) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	_, err := db.db.ExecContext(ctx, "DELETE FROM DeviceCertificate WHERE user = ? AND fingerprint = ?", userID, fingerprint)
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
	var timestamp sqliteTime
	if err := row.Scan(&receipt.ID, &timestamp); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	receipt.Timestamp = timestamp.Time
	return receipt, nil
}

func (db *SqliteDB) StoreReadReceipt(ctx context.Context, networkID int64, receipt *ReadReceipt) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("id", receipt.ID),
		sql.Named("timestamp", sqliteTime{receipt.Timestamp}),
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
		sql.Named("now", sqliteTime{time.Now()}))
	if err != nil {
		return err
	}
	config.ID, err = res.LastInsertId()
	return err
}

func (db *SqliteDB) ListWebPushSubscriptions(ctx context.Context, userID, networkID int64) ([]WebPushSubscription, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	nullNetworkID := sql.NullInt64{
		Int64: networkID,
		Valid: networkID != 0,
	}

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, endpoint, created_at, updated_at, key_auth, key_p256dh, key_vapid
		FROM WebPushSubscription
		WHERE user = ? AND network IS ?`, userID, nullNetworkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []WebPushSubscription
	for rows.Next() {
		var sub WebPushSubscription
		var createdAt, updatedAt sqliteTime
		if err := rows.Scan(&sub.ID, &sub.Endpoint, &createdAt, &updatedAt, &sub.Keys.Auth, &sub.Keys.P256DH, &sub.Keys.VAPID); err != nil {
			return nil, err
		}
		sub.CreatedAt = createdAt.Time
		sub.UpdatedAt = updatedAt.Time
		subs = append(subs, sub)
	}

	return subs, rows.Err()
}

func (db *SqliteDB) StoreWebPushSubscription(ctx context.Context, userID, networkID int64, sub *WebPushSubscription) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("id", sub.ID),
		sql.Named("user", userID),
		sql.Named("network", sql.NullInt64{
			Int64: networkID,
			Valid: networkID != 0,
		}),
		sql.Named("now", sqliteTime{time.Now()}),
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
			WebPushSubscription(created_at, updated_at, user, network, endpoint,
				key_auth, key_p256dh, key_vapid)
			VALUES (:now, :now, :user, :network, :endpoint, :key_auth,
				:key_p256dh, :key_vapid)`,
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

func (db *SqliteDB) GetMessageLastID(ctx context.Context, networkID int64, name string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	var msgID int64
	row := db.db.QueryRowContext(ctx, `
		SELECT m.id FROM Message AS m, MessageTarget AS t
		WHERE t.network = :network AND t.target = :target AND m.target = t.id
		ORDER BY m.time DESC LIMIT 1`,
		sql.Named("network", networkID),
		sql.Named("target", name),
	)
	if err := row.Scan(&msgID); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return msgID, nil
}

func (db *SqliteDB) GetMessageTarget(ctx context.Context, networkID int64, target string) (*MessageTarget, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	mt := &MessageTarget{
		Target: target,
	}

	row := db.db.QueryRowContext(ctx, `
		SELECT id, pinned, muted, blocked FROM MessageTarget WHERE network = :network AND target = :target`,
		sql.Named("network", networkID),
		sql.Named("target", target),
	)
	if err := row.Scan(&mt.ID, &mt.Pinned, &mt.Muted, &mt.Blocked); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return mt, nil
}

func (db *SqliteDB) ListMessageTargets(ctx context.Context, networkID int64) ([]MessageTarget, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	rows, err := db.db.QueryContext(ctx, `
		SELECT id, target, pinned, muted, blocked
		FROM MessageTarget
		WHERE network = ? AND (pinned OR muted OR blocked)`,
		networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mts []MessageTarget
	for rows.Next() {
		var mt MessageTarget
		err := rows.Scan(&mt.ID, &mt.Target, &mt.Pinned, &mt.Muted, &mt.Blocked)
		if err != nil {
			return nil, err
		}
		mts = append(mts, mt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return mts, nil
}

func (db *SqliteDB) StoreMessageTarget(ctx context.Context, networkID int64, mt *MessageTarget) error {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	args := []interface{}{
		sql.Named("id", mt.ID),
		sql.Named("network", networkID),
		sql.Named("target", mt.Target),
		sql.Named("pinned", mt.Pinned),
		sql.Named("muted", mt.Muted),
		sql.Named("blocked", mt.Blocked),
	}

	var err error
	if mt.ID != 0 {
		_, err = db.db.ExecContext(ctx, `
			UPDATE MessageTarget SET pinned = :pinned, muted = :muted, blocked = :blocked WHERE id = :id`,
			args...)
	} else {
		var res sql.Result
		res, err = db.db.ExecContext(ctx, `
			INSERT INTO
			MessageTarget(network, target, pinned, muted, blocked)
			VALUES (:network, :target, :pinned, :muted, :blocked)`,
			args...)
		if err != nil {
			return err
		}
		mt.ID, err = res.LastInsertId()
	}

	return err
}

func (db *SqliteDB) StoreMessages(ctx context.Context, networkID int64, name string, msgs []*irc.Message) ([]int64, error) {
	if len(msgs) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(len(msgs))*sqliteQueryTimeout)
	defer cancel()

	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO MessageTarget(network, target)
		VALUES (:network, :target)
		ON CONFLICT DO NOTHING`,
		sql.Named("network", networkID),
		sql.Named("target", name),
	)
	if err != nil {
		return nil, err
	}

	insertStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO Message(target, raw, time, sender, text)
		SELECT id, :raw, :time, :sender, :text
		FROM MessageTarget as t
		WHERE network = :network AND target = :target`)
	if err != nil {
		return nil, err
	}

	ids := make([]int64, len(msgs))
	for i, msg := range msgs {
		var t time.Time
		if tag, ok := msg.Tags["time"]; ok {
			var err error
			t, err = time.Parse(xirc.ServerTimeLayout, tag)
			if err != nil {
				return nil, fmt.Errorf("failed to parse message time tag: %w", err)
			}
		} else {
			t = time.Now()
		}

		var text sql.NullString
		switch msg.Command {
		case "PRIVMSG", "NOTICE":
			if len(msg.Params) > 1 {
				text.Valid = true
				text.String = stripANSI(msg.Params[1])
			}
		}

		res, err = insertStmt.ExecContext(ctx,
			sql.Named("network", networkID),
			sql.Named("target", name),
			sql.Named("raw", msg.String()),
			sql.Named("time", sqliteTime{t}),
			sql.Named("sender", msg.Name),
			sql.Named("text", text),
		)
		if err != nil {
			return nil, err
		}
		ids[i], err = res.LastInsertId()
		if err != nil {
			return nil, err
		}
	}

	err = tx.Commit()
	return ids, err
}

func (db *SqliteDB) ListMessageLastPerTarget(ctx context.Context, networkID int64, options *MessageOptions) ([]MessageTargetLast, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	innerQuery := `
		SELECT time
		FROM Message
		WHERE target = MessageTarget.id `
	if !options.Events {
		innerQuery += `AND text IS NOT NULL `
	}
	innerQuery += `
		ORDER BY time DESC
		LIMIT 1
	`

	query := `
		SELECT target, (` + innerQuery + `) latest
		FROM MessageTarget
		WHERE network = :network `
	if !options.AfterTime.IsZero() {
		// compares time strings by lexicographical order
		query += `AND latest > :after `
	}
	if !options.BeforeTime.IsZero() {
		// compares time strings by lexicographical order
		query += `AND latest < :before `
	}
	if options.TakeLast {
		query += `ORDER BY latest DESC `
	} else {
		query += `ORDER BY latest ASC `
	}
	query += `LIMIT :limit`

	rows, err := db.db.QueryContext(ctx, query,
		sql.Named("network", networkID),
		sql.Named("after", sqliteTime{options.AfterTime}),
		sql.Named("before", sqliteTime{options.BeforeTime}),
		sql.Named("limit", options.Limit),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var l []MessageTargetLast
	for rows.Next() {
		var mt MessageTargetLast
		var ts sqliteTime
		if err := rows.Scan(&mt.Name, &ts); err != nil {
			return nil, err
		}

		mt.LatestMessage = ts.Time
		l = append(l, mt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if options.TakeLast {
		// We ordered by DESC to limit to the last lines.
		// Reverse the list to order by ASC these last lines.
		for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
			l[i], l[j] = l[j], l[i]
		}
	}

	return l, nil
}

func (db *SqliteDB) ListMessages(ctx context.Context, networkID int64, name string, options *MessageOptions) ([]*irc.Message, error) {
	ctx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()

	query := `
		SELECT m.raw
		FROM Message AS m, MessageTarget AS t
		WHERE m.target = t.id AND t.network = :network AND t.target = :target `
	if options.AfterID > 0 {
		query += `AND m.id > :afterID `
	}
	if !options.AfterTime.IsZero() {
		// compares time strings by lexicographical order
		query += `AND m.time > :after `
	}
	if !options.BeforeTime.IsZero() {
		// compares time strings by lexicographical order
		query += `AND m.time < :before `
	}
	if options.Sender != "" {
		query += `AND m.sender = :sender `
	}
	if options.Text != "" {
		query += `AND m.id IN (SELECT ROWID FROM MessageFTS WHERE MessageFTS MATCH :text) `
	}
	if !options.Events {
		query += `AND m.text IS NOT NULL `
	}
	if options.TakeLast {
		query += `ORDER BY m.time DESC `
	} else {
		query += `ORDER BY m.time ASC `
	}
	query += `LIMIT :limit`

	rows, err := db.db.QueryContext(ctx, query,
		sql.Named("network", networkID),
		sql.Named("target", name),
		sql.Named("afterID", options.AfterID),
		sql.Named("after", sqliteTime{options.AfterTime}),
		sql.Named("before", sqliteTime{options.BeforeTime}),
		sql.Named("sender", options.Sender),
		sql.Named("text", quoteFTSQuery(options.Text)),
		sql.Named("limit", options.Limit),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var l []*irc.Message
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}

		msg, err := irc.ParseMessage(raw)
		if err != nil {
			return nil, err
		}

		l = append(l, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if options.TakeLast {
		// We ordered by DESC to limit to the last lines.
		// Reverse the list to order by ASC these last lines.
		for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
			l[i], l[j] = l[j], l[i]
		}
	}

	return l, nil
}

var ftsQueryTokenEscaper = strings.NewReplacer(`"`, `""`)

func quoteFTSQuery(query string) string {
	// By default, FTS5 queries have a specific syntax, can include logical operators, ...
	// In order to mirror the behavior of the other stores, we quote the query so that the string is matched as is.
	// We could quote the whole string, e.g. `"foo baz"`, but then this would match the exact substring, and not the
	// presence of the two tokens `foo` and `baz` in the line, like in `foo bar baz`, which would be nice to have.
	// So, we need to quote each token, i.e. `"foo" "baz"`.
	// In order to quote each token, we must split on "separators", then quote each token with `"`.
	// The specification of a separator depends on the tokenizer used. We currently use the default tokenizer, which
	// specifies separators as anything that is not \pL, \pN, \p{Co} (see below).
	// We must additionally escape double quote characters in the tokens, with a simple replacer.

	// https://www.sqlite.org/fts5.html#fts5_strings
	// Within an FTS expression a string may be specified in one of two ways:
	// * By enclosing it in double quotes (").
	//   Within a string, any embedded double quote characters may be escaped SQL-style by adding a second double-quote
	//   character.
	// * As an FTS5 bareword [...] a string of one or more consecutive characters that are all [...].
	//   Strings that include any other characters must be quoted.
	// [...]
	// FTS5 features three built-in tokenizer modules [...]:
	// * The unicode61 tokenizer, based on the Unicode 6.1 standard. This is the default.
	// [...]
	// The unicode tokenizer classifies all unicode characters as either "separator" or "token" characters. [...]
	// All unicode characters assigned to a general category beginning with "L" or "N" (letters and numbers,
	// specifically) or to category "Co" ("other, private use") are considered tokens.
	// All other characters are separators.
	tokens := strings.FieldsFunc(query, func(r rune) bool {
		return !unicode.In(r, unicode.L, unicode.N, unicode.Co)
	})
	var sb strings.Builder
	for _, token := range tokens {
		if sb.Len() > 0 {
			sb.WriteRune(' ')
		}
		sb.WriteRune('"')
		ftsQueryTokenEscaper.WriteString(&sb, token)
		sb.WriteRune('"')
	}
	return sb.String()
}
