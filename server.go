package jounce

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"gopkg.in/irc.v3"
)

// TODO: make configurable
var keepAlivePeriod = time.Minute
var retryConnectMinDelay = time.Minute

func setKeepAlive(c net.Conn) error {
	tcpConn, ok := c.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("cannot enable keep-alive on a non-TCP connection")
	}
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return err
	}
	return tcpConn.SetKeepAlivePeriod(keepAlivePeriod)
}

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

type network struct {
	Network
	user *user
	conn *upstreamConn
}

func newNetwork(user *user, record *Network) *network {
	return &network{
		Network: *record,
		user:    user,
	}
}

func (net *network) run() {
	var lastTry time.Time
	for {
		if dur := time.Now().Sub(lastTry); dur < retryConnectMinDelay {
			delay := retryConnectMinDelay - dur
			net.user.srv.Logger.Printf("waiting %v before trying to reconnect to %q", delay.Truncate(time.Second), net.Addr)
			time.Sleep(delay)
		}
		lastTry = time.Now()

		uc, err := connectToUpstream(net)
		if err != nil {
			net.user.srv.Logger.Printf("failed to connect to upstream server %q: %v", net.Addr, err)
			continue
		}

		uc.register()

		net.user.lock.Lock()
		net.conn = uc
		net.user.lock.Unlock()

		if err := uc.readMessages(); err != nil {
			uc.logger.Printf("failed to handle messages: %v", err)
		}
		uc.Close()

		net.user.lock.Lock()
		net.conn = nil
		net.user.lock.Unlock()
	}
}

type user struct {
	User
	srv *Server

	lock            sync.Mutex
	networks        []*network
	downstreamConns []*downstreamConn
}

func newUser(srv *Server, record *User) *user {
	return &user{
		User: *record,
		srv:  srv,
	}
}

func (u *user) forEachNetwork(f func(*network)) {
	u.lock.Lock()
	for _, network := range u.networks {
		f(network)
	}
	u.lock.Unlock()
}

func (u *user) forEachUpstream(f func(uc *upstreamConn)) {
	u.lock.Lock()
	for _, network := range u.networks {
		uc := network.conn
		if uc == nil || !uc.registered || uc.closed {
			continue
		}
		f(uc)
	}
	u.lock.Unlock()
}

func (u *user) forEachDownstream(f func(dc *downstreamConn)) {
	u.lock.Lock()
	for _, dc := range u.downstreamConns {
		f(dc)
	}
	u.lock.Unlock()
}

func (u *user) getNetwork(name string) *network {
	for _, network := range u.networks {
		if network.Addr == name {
			return network
		}
	}
	return nil
}

func (u *user) run() {
	networks, err := u.srv.db.ListNetworks(u.Username)
	if err != nil {
		u.srv.Logger.Printf("failed to list networks for user %q: %v", u.Username, err)
		return
	}

	u.lock.Lock()
	for _, record := range networks {
		network := newNetwork(u, &record)
		u.networks = append(u.networks, network)

		go network.run()
	}
	u.lock.Unlock()
}

type Server struct {
	Hostname string
	Logger   Logger
	RingCap  int
	Debug    bool

	db *DB

	lock            sync.Mutex
	users           map[string]*user
	downstreamConns []*downstreamConn
}

func NewServer(db *DB) *Server {
	return &Server{
		Logger:  log.New(log.Writer(), "", log.LstdFlags),
		RingCap: 4096,
		users:   make(map[string]*user),
		db:      db,
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
	for {
		netConn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		setKeepAlive(netConn)

		dc := newDownstreamConn(s, netConn)
		go func() {
			s.lock.Lock()
			s.downstreamConns = append(s.downstreamConns, dc)
			s.lock.Unlock()

			if err := dc.readMessages(); err != nil {
				dc.logger.Printf("failed to handle messages: %v", err)
			}
			dc.Close()

			s.lock.Lock()
			for i := range s.downstreamConns {
				if s.downstreamConns[i] == dc {
					s.downstreamConns = append(s.downstreamConns[:i], s.downstreamConns[i+1:]...)
					break
				}
			}
			s.lock.Unlock()
		}()
	}
}
