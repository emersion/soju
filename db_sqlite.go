package soju

import (
	"database/sql"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const sqliteSchema = `
CREATE TABLE User (
	id INTEGER PRIMARY KEY,
	username VARCHAR(255) NOT NULL UNIQUE,
	password VARCHAR(255),
	admin INTEGER NOT NULL DEFAULT 0,
	realname VARCHAR(255)
);

CREATE TABLE Network (
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
	enabled INTEGER NOT NULL DEFAULT 1,
	FOREIGN KEY(user) REFERENCES User(id),
	UNIQUE(user, addr, nick),
	UNIQUE(user, name)
);

CREATE TABLE Channel (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	name VARCHAR(255) NOT NULL,
	key VARCHAR(255),
	detached INTEGER NOT NULL DEFAULT 0,
	detached_internal_msgid VARCHAR(255),
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
	target VARCHAR(255) NOT NULL,
	client VARCHAR(255),
	internal_msgid VARCHAR(255) NOT NULL,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, target, client)
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
}

type SqliteDB struct {
	lock sync.RWMutex
	db   *sql.DB
}

func OpenSqliteDB(driver, source string) (Database, error) {
	sqlSqliteDB, err := sql.Open(driver, source)
	if err != nil {
		return nil, err
	}

	db := &SqliteDB{db: sqlSqliteDB}
	if err := db.upgrade(); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *SqliteDB) Close() error {
	db.lock.Lock()
	defer db.lock.Unlock()
	return db.db.Close()
}

func (db *SqliteDB) upgrade() error {
	db.lock.Lock()
	defer db.lock.Unlock()

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

func toNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}

func (db *SqliteDB) ListUsers() ([]User, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query("SELECT id, username, password, admin FROM User")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var password sql.NullString
		if err := rows.Scan(&user.ID, &user.Username, &password, &user.Admin); err != nil {
			return nil, err
		}
		user.Password = password.String
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (db *SqliteDB) GetUser(username string) (*User, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	user := &User{Username: username}

	var password, realname sql.NullString
	row := db.db.QueryRow("SELECT id, password, admin, realname FROM User WHERE username = ?", username)
	if err := row.Scan(&user.ID, &password, &user.Admin, &realname); err != nil {
		return nil, err
	}
	user.Password = password.String
	user.Realname = realname.String
	return user, nil
}

func (db *SqliteDB) StoreUser(user *User) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	password := toNullString(user.Password)
	realname := toNullString(user.Realname)

	var err error
	if user.ID != 0 {
		_, err = db.db.Exec("UPDATE User SET password = ?, admin = ?, realname = ? WHERE username = ?",
			password, user.Admin, realname, user.Username)
	} else {
		var res sql.Result
		res, err = db.db.Exec("INSERT INTO User(username, password, admin, realname) VALUES (?, ?, ?, ?)",
			user.Username, password, user.Admin, realname)
		if err != nil {
			return err
		}
		user.ID, err = res.LastInsertId()
	}

	return err
}

func (db *SqliteDB) DeleteUser(id int64) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`DELETE FROM Channel
		WHERE id IN (
			SELECT Channel.id
			FROM Channel
			JOIN Network ON Channel.network = Network.id
			WHERE Network.user = ?
		)`, id)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM Network WHERE user = ?", id)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM User WHERE id = ?", id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (db *SqliteDB) ListNetworks(userID int64) ([]Network, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query(`SELECT id, name, addr, nick, username, realname, pass,
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

func (db *SqliteDB) StoreNetwork(userID int64, network *Network) error {
	db.lock.Lock()
	defer db.lock.Unlock()

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
	if network.ID != 0 {
		_, err = db.db.Exec(`UPDATE Network
			SET name = ?, addr = ?, nick = ?, username = ?, realname = ?, pass = ?, connect_commands = ?,
				sasl_mechanism = ?, sasl_plain_username = ?, sasl_plain_password = ?,
				sasl_external_cert = ?, sasl_external_key = ?, enabled = ?
			WHERE id = ?`,
			netName, network.Addr, network.Nick, netUsername, realname, pass, connectCommands,
			saslMechanism, saslPlainUsername, saslPlainPassword,
			network.SASL.External.CertBlob, network.SASL.External.PrivKeyBlob, network.Enabled,
			network.ID)
	} else {
		var res sql.Result
		res, err = db.db.Exec(`INSERT INTO Network(user, name, addr, nick, username,
				realname, pass, connect_commands, sasl_mechanism, sasl_plain_username,
				sasl_plain_password, sasl_external_cert, sasl_external_key, enabled)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			userID, netName, network.Addr, network.Nick, netUsername, realname, pass, connectCommands,
			saslMechanism, saslPlainUsername, saslPlainPassword, network.SASL.External.CertBlob,
			network.SASL.External.PrivKeyBlob, network.Enabled)
		if err != nil {
			return err
		}
		network.ID, err = res.LastInsertId()
	}
	return err
}

func (db *SqliteDB) DeleteNetwork(id int64) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM Channel WHERE network = ?", id)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM Network WHERE id = ?", id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (db *SqliteDB) ListChannels(networkID int64) ([]Channel, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query(`SELECT
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

func (db *SqliteDB) StoreChannel(networkID int64, ch *Channel) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	key := toNullString(ch.Key)
	detachAfter := int64(math.Ceil(ch.DetachAfter.Seconds()))

	var err error
	if ch.ID != 0 {
		_, err = db.db.Exec(`UPDATE Channel
			SET network = ?, name = ?, key = ?, detached = ?, detached_internal_msgid = ?, relay_detached = ?, reattach_on = ?, detach_after = ?, detach_on = ?
			WHERE id = ?`,
			networkID, ch.Name, key, ch.Detached, toNullString(ch.DetachedInternalMsgID), ch.RelayDetached, ch.ReattachOn, detachAfter, ch.DetachOn, ch.ID)
	} else {
		var res sql.Result
		res, err = db.db.Exec(`INSERT INTO Channel(network, name, key, detached, detached_internal_msgid, relay_detached, reattach_on, detach_after, detach_on)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			networkID, ch.Name, key, ch.Detached, toNullString(ch.DetachedInternalMsgID), ch.RelayDetached, ch.ReattachOn, detachAfter, ch.DetachOn)
		if err != nil {
			return err
		}
		ch.ID, err = res.LastInsertId()
	}
	return err
}

func (db *SqliteDB) DeleteChannel(id int64) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	_, err := db.db.Exec("DELETE FROM Channel WHERE id = ?", id)
	return err
}

func (db *SqliteDB) ListDeliveryReceipts(networkID int64) ([]DeliveryReceipt, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query(`SELECT id, target, client, internal_msgid
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

func (db *SqliteDB) StoreClientDeliveryReceipts(networkID int64, client string, receipts []DeliveryReceipt) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM DeliveryReceipt WHERE network = ? AND client = ?",
		networkID, toNullString(client))
	if err != nil {
		return err
	}

	for i := range receipts {
		rcpt := &receipts[i]

		res, err := tx.Exec("INSERT INTO DeliveryReceipt(network, target, client, internal_msgid) VALUES (?, ?, ?, ?)",
			networkID, rcpt.Target, toNullString(client), rcpt.InternalMsgID)
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
