package soju

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Username string
	Password string // hashed
}

type SASL struct {
	Mechanism string

	Plain struct {
		Username string
		Password string
	}
}

type Network struct {
	ID       int64
	Name     string
	Addr     string
	Nick     string
	Username string
	Realname string
	Pass     string
	SASL     SASL
}

type Channel struct {
	ID   int64
	Name string
	Key  string
}

type DB struct {
	lock sync.RWMutex
	db   *sql.DB
}

func OpenSQLDB(driver, source string) (*DB, error) {
	db, err := sql.Open(driver, source)
	if err != nil {
		return nil, err
	}
	return &DB{db: db}, nil
}

func (db *DB) Close() error {
	db.lock.Lock()
	defer db.lock.Unlock()
	return db.Close()
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

	rows, err := db.db.Query("SELECT username, password FROM User")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var password *string
		if err := rows.Scan(&user.Username, &password); err != nil {
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

func (db *DB) CreateUser(user *User) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	password := toStringPtr(user.Password)
	_, err := db.db.Exec("INSERT INTO User(username, password) VALUES (?, ?)", user.Username, password)
	return err
}

func (db *DB) ListNetworks(username string) ([]Network, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query(`SELECT id, name, addr, nick, username, realname, pass,
			sasl_mechanism, sasl_plain_username, sasl_plain_password
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
		var name, username, realname, pass *string
		var saslMechanism, saslPlainUsername, saslPlainPassword *string
		err := rows.Scan(&net.ID, &name, &net.Addr, &net.Nick, &username, &realname,
			&pass, &saslMechanism, &saslPlainUsername, &saslPlainPassword)
		if err != nil {
			return nil, err
		}
		net.Name = fromStringPtr(name)
		net.Username = fromStringPtr(username)
		net.Realname = fromStringPtr(realname)
		net.Pass = fromStringPtr(pass)
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

	var saslMechanism, saslPlainUsername, saslPlainPassword *string
	if network.SASL.Mechanism != "" {
		saslMechanism = &network.SASL.Mechanism
		switch network.SASL.Mechanism {
		case "PLAIN":
			saslPlainUsername = toStringPtr(network.SASL.Plain.Username)
			saslPlainPassword = toStringPtr(network.SASL.Plain.Password)
		default:
			return fmt.Errorf("soju: cannot store network: unsupported SASL mechanism %q", network.SASL.Mechanism)
		}
	}

	var err error
	if network.ID != 0 {
		_, err = db.db.Exec(`UPDATE Network
			SET name = ?, addr = ?, nick = ?, username = ?, realname = ?, pass = ?,
				sasl_mechanism = ?, sasl_plain_username = ?, sasl_plain_password = ?
			WHERE id = ?`,
			netName, network.Addr, network.Nick, netUsername, realname, pass,
			saslMechanism, saslPlainUsername, saslPlainPassword, network.ID)
	} else {
		var res sql.Result
		res, err = db.db.Exec(`INSERT INTO Network(user, name, addr, nick, username,
				realname, pass, sasl_mechanism, sasl_plain_username,
				sasl_plain_password)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			username, netName, network.Addr, network.Nick, netUsername, realname, pass,
			saslMechanism, saslPlainUsername, saslPlainPassword)
		if err != nil {
			return err
		}
		network.ID, err = res.LastInsertId()
	}
	return err
}

func (db *DB) ListChannels(networkID int64) ([]Channel, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query("SELECT id, name, key FROM Channel WHERE network = ?", networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var channels []Channel
	for rows.Next() {
		var ch Channel
		var key *string
		if err := rows.Scan(&ch.ID, &ch.Name, &key); err != nil {
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
	_, err := db.db.Exec(`INSERT OR REPLACE INTO Channel(network, name, key)
		VALUES (?, ?, ?)`, networkID, ch.Name, key)
	return err
}

func (db *DB) DeleteChannel(networkID int64, name string) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	_, err := db.db.Exec("DELETE FROM Channel WHERE network = ? AND name = ?", networkID, name)
	return err
}

func (net *Network) GetName() string {
	if net.Name != "" {
		return net.Name
	}
	return net.Addr
}
