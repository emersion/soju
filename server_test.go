package soju

import (
	"context"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"gopkg.in/irc.v4"

	"codeberg.org/emersion/soju/config"
	"codeberg.org/emersion/soju/database"
	"codeberg.org/emersion/soju/xirc"
)

var testServerPrefix = &irc.Prefix{Name: "soju-test-server"}

const (
	testUsername = "soju-test-user"
	testPassword = testUsername
)

type testingLogger struct {
	t *testing.T
}

func (tl testingLogger) Printf(format string, v ...interface{}) {
	tl.t.Logf(format, v...)
}

func createTempSqliteDB(t *testing.T) database.Database {
	if !database.SqliteEnabled {
		t.Skip("SQLite support is disabled")
	}

	db, err := database.OpenTempSqliteDB()
	if err != nil {
		t.Fatalf("failed to create temporary SQLite database: %v", err)
	}
	return db
}

func createTempPostgresDB(t *testing.T) database.Database {
	source, ok := os.LookupEnv("SOJU_TEST_POSTGRES")
	if !ok {
		t.Skip("set SOJU_TEST_POSTGRES to a connection string to execute PostgreSQL tests")
	}

	db, err := database.OpenTempPostgresDB(source)
	if err != nil {
		t.Fatalf("failed to create temporary PostgreSQL database: %v", err)
	}

	return db
}

func createTestUser(t *testing.T, db database.Database) *database.User {
	record := database.NewUser(testUsername)
	if err := record.SetPassword(testPassword); err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}
	if err := db.StoreUser(context.Background(), record); err != nil {
		t.Fatalf("failed to store test user: %v", err)
	}

	return record
}

func createTestDownstream(t *testing.T, srv *Server) ircConn {
	c1, c2 := net.Pipe()
	go srv.serveConn(newNetIRCConn(c1))
	return newNetIRCConn(c2)
}

func createTestUpstream(t *testing.T, db database.Database, user *database.User) (*database.Network, net.Listener) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to create TCP listener: %v", err)
	}

	network := database.NewNetwork("irc+insecure://" + ln.Addr().String())
	network.Name = "testnet"
	if err := db.StoreNetwork(context.Background(), user.ID, network); err != nil {
		t.Fatalf("failed to store test network: %v", err)
	}

	return network, ln
}

func mustAccept(t *testing.T, ln net.Listener) ircConn {
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("failed accepting connection: %v", err)
	}
	return newNetIRCConn(c)
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

func roundtrip(t *testing.T, c ircConn) []*irc.Message {
	c.WriteMessage(&irc.Message{Command: "PING", Params: []string{"roundtrip"}})

	var msgs []*irc.Message
	for {
		msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read IRC message: %v", err)
		}

		if msg.Command == "PONG" {
			break
		}

		msgs = append(msgs, msg)
	}

	return msgs
}

func registerDownstreamConn(t *testing.T, c ircConn, network *database.Network) {
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
		Params:  []string{testUsername + "/" + network.Name, "0", "*", testUsername},
	})

	expectMessage(t, c, irc.RPL_WELCOME)
}

func registerUpstreamConn(t *testing.T, c ircConn) {
	msg := expectMessage(t, c, "CAP")
	if msg.Params[0] != "LS" {
		t.Fatalf("invalid CAP LS: got: %v", msg)
	}
	msg = expectMessage(t, c, "NICK")
	nick := msg.Params[0]
	if nick != testUsername {
		t.Fatalf("invalid NICK: want %q, got: %v", testUsername, msg)
	}
	expectMessage(t, c, "USER")

	c.WriteMessage(&irc.Message{
		Prefix:  testServerPrefix,
		Command: irc.RPL_WELCOME,
		Params:  []string{nick, "Welcome!"},
	})
	c.WriteMessage(&irc.Message{
		Prefix:  testServerPrefix,
		Command: irc.RPL_YOURHOST,
		Params:  []string{nick, "Your host is soju-test-server"},
	})
	c.WriteMessage(&irc.Message{
		Prefix:  testServerPrefix,
		Command: irc.RPL_CREATED,
		Params:  []string{nick, "Who cares when the server was created?"},
	})
	c.WriteMessage(&irc.Message{
		Prefix:  testServerPrefix,
		Command: irc.RPL_MYINFO,
		Params:  []string{nick, testServerPrefix.Name, "soju", "aiwroO", "OovaimnqpsrtklbeI"},
	})
	c.WriteMessage(&irc.Message{
		Prefix:  testServerPrefix,
		Command: irc.ERR_NOMOTD,
		Params:  []string{nick, "No MOTD"},
	})
}

func newDebugLogger(t *testing.T) *DebugLogger {
	l := &DebugLogger{
		logger: &testingLogger{t},
	}
	l.debug.Store(true)
	return l
}

func testBroadcast(t *testing.T, db database.Database) {
	user := createTestUser(t, db)
	network, upstream := createTestUpstream(t, db, user)
	defer upstream.Close()

	srv := NewServer(db)
	srv.Logger = newDebugLogger(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Shutdown()

	uc := mustAccept(t, upstream)
	defer uc.Close()
	registerUpstreamConn(t, uc)

	dc := createTestDownstream(t, srv)
	defer dc.Close()
	registerDownstreamConn(t, dc, network)

	noticeText := "This is a very important server notice."
	uc.WriteMessage(&irc.Message{
		Prefix:  testServerPrefix,
		Command: "NOTICE",
		Params:  []string{testUsername, noticeText},
	})

	var msg *irc.Message
	for {
		var err error
		msg, err = dc.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read IRC message: %v", err)
		}
		if msg.Command == "NOTICE" {
			break
		}
	}

	if msg.Params[1] != noticeText {
		t.Fatalf("invalid NOTICE text: want %q, got: %v", noticeText, msg)
	}
}

func TestServer_broadcast(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		db := createTempSqliteDB(t)
		testBroadcast(t, db)
	})

	t.Run("postgres", func(t *testing.T) {
		db := createTempPostgresDB(t)
		testBroadcast(t, db)
	})
}

func testChatHistory(t *testing.T, msgStoreDriver, msgStorePath string) {
	db := createTempSqliteDB(t)

	user := createTestUser(t, db)
	network, upstream := createTestUpstream(t, db, user)
	defer upstream.Close()

	srv := NewServer(db)
	srv.Logger = newDebugLogger(t)

	cfg := *srv.Config()
	cfg.MsgStore = config.MsgStore{Driver: msgStoreDriver, Source: msgStorePath}
	srv.SetConfig(&cfg)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Shutdown()

	uc := mustAccept(t, upstream)
	defer uc.Close()
	registerUpstreamConn(t, uc)

	texts := []string{
		"Hiya!",
		"How are you doing?",
		"Can I take a sip from your glass of soju?",
	}

	baseTime := time.Date(2023, 05, 23, 6, 0, 0, 0, time.UTC)
	for i, text := range texts {
		msgTime := baseTime.Add(time.Duration(i) * time.Second)
		uc.WriteMessage(&irc.Message{
			Tags:    irc.Tags{"time": xirc.FormatServerTime(msgTime)},
			Prefix:  &irc.Prefix{Name: "foo"},
			Command: "PRIVMSG",
			Params:  []string{testUsername, text},
		})
	}
	roundtrip(t, uc)

	dc := createTestDownstream(t, srv)
	defer dc.Close()
	registerDownstreamConn(t, dc, network)
	roundtrip(t, dc) // drain post-connection-registration messages

	testCases := []struct {
		Name  string
		After time.Time
		Texts []string
	}{
		{
			Name:  "all",
			After: baseTime.Add(-time.Second),
			Texts: texts,
		},
		{
			Name:  "none",
			After: baseTime.Add(time.Duration(len(texts)-1) * time.Second),
			Texts: nil,
		},
		{
			Name:  "all_but_first",
			After: baseTime,
			Texts: texts[1:],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			dc.WriteMessage(&irc.Message{
				Command: "CHATHISTORY",
				Params:  []string{"AFTER", "foo", "timestamp=" + xirc.FormatServerTime(tc.After), "100"},
			})

			var got []string
			for _, msg := range roundtrip(t, dc) {
				if msg.Command != "PRIVMSG" {
					t.Fatalf("unexpected reply: %v", msg)
				}
				got = append(got, msg.Params[1])
			}

			if !reflect.DeepEqual(got, tc.Texts) {
				t.Errorf("got %v, want %v", got, tc.Texts)
			}
		})
	}
}

func TestServer_chatHistory(t *testing.T) {
	t.Run("fs", func(t *testing.T) {
		testChatHistory(t, "fs", t.TempDir())
	})

	t.Run("db", func(t *testing.T) {
		testChatHistory(t, "db", "")
	})
}
