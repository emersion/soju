package soju

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID       int64
	Username string
	Password string // hashed
	Admin    bool
}

type SASL struct {
	Mechanism string

	Plain struct {
		Username string
		Password string
	}

	// TLS client certificate authentication.
	External struct {
		// X.509 certificate in DER form.
		CertBlob []byte
		// PKCS#8 private key in DER form.
		PrivKeyBlob []byte
	}
}

type Network struct {
	ID              int64
	Name            string
	Addr            string
	Nick            string
	Username        string
	Realname        string
	Pass            string
	ConnectCommands []string
	SASL            SASL
}

func (net *Network) GetName() string {
	if net.Name != "" {
		return net.Name
	}
	return net.Addr
}

type Channel struct {
	ID       int64
	Name     string
	Key      string
	Detached bool
}

const schema = `
CREATE TABLE User (
	id INTEGER PRIMARY KEY,
	username VARCHAR(255) NOT NULL UNIQUE,
	password VARCHAR(255),
	admin INTEGER NOT NULL DEFAULT 0
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
	connect_commands VARCHAR(1023),
	sasl_mechanism VARCHAR(255),
	sasl_plain_username VARCHAR(255),
	sasl_plain_password VARCHAR(255),
	sasl_external_cert BLOB DEFAULT NULL,
	sasl_external_key BLOB DEFAULT NULL,
	FOREIGN KEY(user) REFERENCES User(username),
	UNIQUE(user, addr, nick)
);

CREATE TABLE Channel (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	name VARCHAR(255) NOT NULL,
	key VARCHAR(255),
	detached INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, name)
);
`

var migrations = []string{
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
}

type DB struct {
	lock sync.RWMutex
	db   *sql.DB
}

func OpenSQLDB(driver, source string) (*DB, error) {
	sqlDB, err := sql.Open(driver, source)
	if err != nil {
		return nil, err
	}

	db := &DB{db: sqlDB}
	if err := db.upgrade(); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DB) Close() error {
	db.lock.Lock()
	defer db.lock.Unlock()
	return db.db.Close()
}

func (db *DB) upgrade() error {
	db.lock.Lock()
	defer db.lock.Unlock()

	var version int
	if err := db.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("failed to query schema version: %v", err)
	}

	if version == len(migrations) {
		return nil
	} else if version > len(migrations) {
		return fmt.Errorf("soju (version %d) older than schema (version %d)", len(migrations), version)
	}

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if version == 0 {
		if _, err := tx.Exec(schema); err != nil {
			return fmt.Errorf("failed to initialize schema: %v", err)
		}
	} else {
		for i := version; i < len(migrations); i++ {
			if _, err := tx.Exec(migrations[i]); err != nil {
				return fmt.Errorf("failed to execute migration #%v: %v", i, err)
			}
		}
	}

	// For some reason prepared statements don't work here
	_, err = tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", len(migrations)))
	if err != nil {
		return fmt.Errorf("failed to bump schema version: %v", err)
	}

	return tx.Commit()
}

func fromStringPtr(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

func toStringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (db *DB) ListUsers() ([]User, error) {
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
		var password *string
		if err := rows.Scan(&user.ID, &user.Username, &password, &user.Admin); err != nil {
			return nil, err
		}
		user.Password = fromStringPtr(password)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (db *DB) GetUser(username string) (*User, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	user := &User{Username: username}

	var password *string
	row := db.db.QueryRow("SELECT id, password, admin FROM User WHERE username = ?", username)
	if err := row.Scan(&user.ID, &password, &user.Admin); err != nil {
		return nil, err
	}
	user.Password = fromStringPtr(password)
	return user, nil
}

func (db *DB) StoreUser(user *User) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	password := toStringPtr(user.Password)

	var err error
	if user.ID != 0 {
		_, err = db.db.Exec("UPDATE User SET password = ?, admin = ? WHERE username = ?",
			password, user.Admin, user.Username)
	} else {
		var res sql.Result
		res, err = db.db.Exec("INSERT INTO User(username, password, admin) VALUES (?, ?, ?)",
			user.Username, password, user.Admin)
		if err != nil {
			return err
		}
		user.ID, err = res.LastInsertId()
	}

	return err
}

func (db *DB) DeleteUser(username string) error {
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
		)`, username)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM Network WHERE user = ?", username)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM User WHERE username = ?", username)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (db *DB) ListNetworks(username string) ([]Network, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query(`SELECT id, name, addr, nick, username, realname, pass,
			connect_commands, sasl_mechanism, sasl_plain_username, sasl_plain_password,
			sasl_external_cert, sasl_external_key
		FROM Network
		WHERE user = ?`,
		username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []Network
	for rows.Next() {
		var net Network
		var name, username, realname, pass, connectCommands *string
		var saslMechanism, saslPlainUsername, saslPlainPassword *string
		err := rows.Scan(&net.ID, &name, &net.Addr, &net.Nick, &username, &realname,
			&pass, &connectCommands, &saslMechanism, &saslPlainUsername, &saslPlainPassword,
			&net.SASL.External.CertBlob, &net.SASL.External.PrivKeyBlob)
		if err != nil {
			return nil, err
		}
		net.Name = fromStringPtr(name)
		net.Username = fromStringPtr(username)
		net.Realname = fromStringPtr(realname)
		net.Pass = fromStringPtr(pass)
		if connectCommands != nil {
			net.ConnectCommands = strings.Split(*connectCommands, "\r\n")
		}
		net.SASL.Mechanism = fromStringPtr(saslMechanism)
		net.SASL.Plain.Username = fromStringPtr(saslPlainUsername)
		net.SASL.Plain.Password = fromStringPtr(saslPlainPassword)
		networks = append(networks, net)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return networks, nil
}

func (db *DB) StoreNetwork(username string, network *Network) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	netName := toStringPtr(network.Name)
	netUsername := toStringPtr(network.Username)
	realname := toStringPtr(network.Realname)
	pass := toStringPtr(network.Pass)
	connectCommands := toStringPtr(strings.Join(network.ConnectCommands, "\r\n"))

	var saslMechanism, saslPlainUsername, saslPlainPassword *string
	if network.SASL.Mechanism != "" {
		saslMechanism = &network.SASL.Mechanism
		switch network.SASL.Mechanism {
		case "PLAIN":
			saslPlainUsername = toStringPtr(network.SASL.Plain.Username)
			saslPlainPassword = toStringPtr(network.SASL.Plain.Password)
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
				sasl_external_cert = ?, sasl_external_key = ?
			WHERE id = ?`,
			netName, network.Addr, network.Nick, netUsername, realname, pass, connectCommands,
			saslMechanism, saslPlainUsername, saslPlainPassword,
			network.SASL.External.CertBlob, network.SASL.External.PrivKeyBlob,
			network.ID)
	} else {
		var res sql.Result
		res, err = db.db.Exec(`INSERT INTO Network(user, name, addr, nick, username,
				realname, pass, connect_commands, sasl_mechanism, sasl_plain_username,
				sasl_plain_password, sasl_external_cert, sasl_external_key)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			username, netName, network.Addr, network.Nick, netUsername, realname, pass, connectCommands,
			saslMechanism, saslPlainUsername, saslPlainPassword, network.SASL.External.CertBlob,
			network.SASL.External.PrivKeyBlob)
		if err != nil {
			return err
		}
		network.ID, err = res.LastInsertId()
	}
	return err
}

func (db *DB) DeleteNetwork(id int64) error {
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

func (db *DB) ListChannels(networkID int64) ([]Channel, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query(`SELECT id, name, key, detached
		FROM Channel
		WHERE network = ?`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var channels []Channel
	for rows.Next() {
		var ch Channel
		var key *string
		if err := rows.Scan(&ch.ID, &ch.Name, &key, &ch.Detached); err != nil {
			return nil, err
		}
		ch.Key = fromStringPtr(key)
		channels = append(channels, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return channels, nil
}

func (db *DB) StoreChannel(networkID int64, ch *Channel) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	key := toStringPtr(ch.Key)

	var err error
	if ch.ID != 0 {
		_, err = db.db.Exec(`UPDATE Channel
			SET network = ?, name = ?, key = ?, detached = ?
			WHERE id = ?`,
			networkID, ch.Name, key, ch.Detached, ch.ID)
	} else {
		var res sql.Result
		res, err = db.db.Exec(`INSERT INTO Channel(network, name, key, detached)
			VALUES (?, ?, ?, ?)`,
			networkID, ch.Name, key, ch.Detached)
		if err != nil {
			return err
		}
		ch.ID, err = res.LastInsertId()
	}
	return err
}

func (db *DB) DeleteChannel(id int64) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	_, err := db.db.Exec("DELETE FROM Channel WHERE id = ?", id)
	return err
}
