package soju

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/irc.v3"
	"nhooyr.io/websocket"
)

// TODO: make configurable
var retryConnectMinDelay = time.Minute
var connectTimeout = 15 * time.Second
var writeTimeout = 10 * time.Second

type Logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
}

type prefixLogger struct {
	logger Logger
	prefix string
}

var _ Logger = (*prefixLogger)(nil)

func (l *prefixLogger) Print(v ...interface{}) {
	v = append([]interface{}{l.prefix}, v...)
	l.logger.Print(v...)
}

func (l *prefixLogger) Printf(format string, v ...interface{}) {
	v = append([]interface{}{l.prefix}, v...)
	l.logger.Printf("%v"+format, v...)
}

type Server struct {
	Hostname     string
	Logger       Logger
	RingCap      int
	HistoryLimit int
	LogPath      string
	Debug        bool
	HTTPOrigins  []string

	db *DB

	lock  sync.Mutex
	users map[string]*user
}

func NewServer(db *DB) *Server {
	return &Server{
		Logger:       log.New(log.Writer(), "", log.LstdFlags),
		RingCap:      4096,
		HistoryLimit: 1000,
		users:        make(map[string]*user),
		db:           db,
	}
}

func (s *Server) prefix() *irc.Prefix {
	return &irc.Prefix{Name: s.Hostname}
}

func (s *Server) Run() error {
	users, err := s.db.ListUsers()
	if err != nil {
		return err
	}

	s.lock.Lock()
	for _, record := range users {
		s.Logger.Printf("starting bouncer for user %q", record.Username)
		u := newUser(s, &record)
		s.users[u.Username] = u

		go u.run()
	}
	s.lock.Unlock()

	select {}
}

func (s *Server) getUser(name string) *user {
	s.lock.Lock()
	u := s.users[name]
	s.lock.Unlock()
	return u
}

var lastDownstreamID uint64 = 0

func (s *Server) handle(ic ircConn, remoteAddr string) {
	id := atomic.AddUint64(&lastDownstreamID, 1)
	dc := newDownstreamConn(s, ic, remoteAddr, id)
	if err := dc.runUntilRegistered(); err != nil {
		dc.logger.Print(err)
	} else {
		dc.user.events <- eventDownstreamConnected{dc}
		if err := dc.readMessages(dc.user.events); err != nil {
			dc.logger.Print(err)
		}
		dc.user.events <- eventDownstreamDisconnected{dc}
	}
	dc.Close()
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go s.handle(newNetIRCConn(conn), conn.RemoteAddr().String())
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		OriginPatterns: s.HTTPOrigins,
	})
	if err != nil {
		s.Logger.Printf("failed to serve HTTP connection: %v", err)
		return
	}
	s.handle(newWebsocketIRCConn(conn), req.RemoteAddr)
}
