package soju

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"gopkg.in/irc.v3"
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

func (s *Server) Serve(ln net.Listener) error {
	var nextDownstreamID uint64 = 1
	for {
		netConn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		dc := newDownstreamConn(s, netConn, nextDownstreamID)
		nextDownstreamID++
		go func() {
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
		}()
	}
}
