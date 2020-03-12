package jounce

import (
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Username string
	Password string // hashed
}

type Network struct {
	ID       int64
	Addr     string
	Nick     string
	Username string
	Realname string
}

type Channel struct {
	ID   int64
	Name string
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
		if password != nil {
			user.Password = *password
		}
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

	var password *string
	if user.Password != "" {
		password = &user.Password
	}
	_, err := db.db.Exec("INSERT INTO User(username, password) VALUES (?, ?)", user.Username, password)
	return err
}

func (db *DB) ListNetworks(username string) ([]Network, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query("SELECT id, addr, nick, username, realname FROM Network WHERE user = ?", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []Network
	for rows.Next() {
		var net Network
		var username, realname *string
		if err := rows.Scan(&net.ID, &net.Addr, &net.Nick, &username, &realname); err != nil {
			return nil, err
		}
		if username != nil {
			net.Username = *username
		}
		if realname != nil {
			net.Realname = *realname
		}
		networks = append(networks, net)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return networks, nil
}

func (db *DB) ListChannels(networkID int64) ([]Channel, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	rows, err := db.db.Query("SELECT id, name FROM Channel WHERE network = ?", networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var channels []Channel
	for rows.Next() {
		var ch Channel
		if err := rows.Scan(&ch.ID, &ch.Name); err != nil {
			return nil, err
		}
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

	_, err := db.db.Exec("INSERT OR REPLACE INTO Channel(network, name) VALUES (?, ?)", networkID, ch.Name)
	return err
}

func (db *DB) DeleteChannel(networkID int64, name string) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	_, err := db.db.Exec("DELETE FROM Channel WHERE network = ? AND name = ?", networkID, name)
	return err
}
