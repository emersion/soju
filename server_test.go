package soju

import (
	"net"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/irc.v3"
)

const (
	testUsername = "soju-test-user"
	testPassword = testUsername
)

func ircPipe() (ircConn, ircConn) {
	c1, c2 := net.Pipe()
	return newNetIRCConn(c1), newNetIRCConn(c2)
}

func createTempDB(t *testing.T) Database {
	db, err := OpenSqliteDB("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to create temporary SQLite database: %v", err)
	}
	// :memory: will open a separate database for each new connection. Make
	// sure the sql package only uses a single connection. An alternative
	// solution is to use "file::memory:?cache=shared".
	db.(*SqliteDB).db.SetMaxOpenConns(1)
	return db
}

func createTestUser(t *testing.T) *Server {
	db := createTempDB(t)

	hashed, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}

	record := &User{Username: testUsername, Password: string(hashed)}
	if err := db.StoreUser(record); err != nil {
		t.Fatalf("failed to store test user: %v", err)
	}

	return NewServer(db)
}

func expectMessage(t *testing.T, c ircConn, cmd string) *irc.Message {
	msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read IRC message (want %q): %v", cmd, err)
	}
	if msg.Command != cmd {
		t.Fatalf("invalid message received: want %q, got: %v", cmd, msg)
	}
	return msg
}

func authTestUser(t *testing.T, c ircConn) {
	c.WriteMessage(&irc.Message{
		Command: "PASS",
		Params:  []string{testPassword},
	})
	c.WriteMessage(&irc.Message{
		Command: "NICK",
		Params:  []string{testUsername},
	})
	c.WriteMessage(&irc.Message{
		Command: "USER",
		Params:  []string{testUsername, "0", "*", testUsername},
	})

	expectMessage(t, c, irc.RPL_WELCOME)
}

func TestServer(t *testing.T) {
	srv := createTestUser(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Shutdown()

	c, srvConn := ircPipe()
	defer c.Close()
	go srv.handle(srvConn)

	authTestUser(t, c)
}
