package jounce

import (
	"fmt"
	"log"
	"net"
	"sync"

	"gopkg.in/irc.v3"
)

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

type user struct {
	username string
	srv      *Server

	lock            sync.Mutex
	upstreamConns   []*upstreamConn
	downstreamConns []*downstreamConn
}

func newUser(srv *Server, username string) *user {
	return &user{
		username: username,
		srv:      srv,
	}
}

func (u *user) forEachUpstream(f func(uc *upstreamConn)) {
	u.lock.Lock()
	for _, uc := range u.upstreamConns {
		if !uc.registered || uc.closed {
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

func (u *user) getChannel(name string) (*upstreamChannel, error) {
	var channel *upstreamChannel
	var err error
	u.forEachUpstream(func(uc *upstreamConn) {
		if err != nil {
			return
		}
		if ch, ok := uc.channels[name]; ok {
			if channel != nil {
				err = fmt.Errorf("ambiguous channel name %q", name)
			} else {
				channel = ch
			}
		}
	})
	if channel == nil {
		return nil, ircError{&irc.Message{
			Command: irc.ERR_NOSUCHCHANNEL,
			Params:  []string{name, "No such channel"},
		}}
	}
	return channel, nil
}

type Upstream struct {
	Addr     string
	Nick     string
	Username string
	Realname string
	Channels []string
}

type Server struct {
	Hostname  string
	Logger    Logger
	RingCap   int
	Upstreams []Upstream // TODO: per-user

	lock            sync.Mutex
	users           map[string]*user
	downstreamConns []*downstreamConn
}

func NewServer() *Server {
	return &Server{
		Logger:  log.New(log.Writer(), "", log.LstdFlags),
		RingCap: 4096,
		users:   make(map[string]*user),
	}
}

func (s *Server) prefix() *irc.Prefix {
	return &irc.Prefix{Name: s.Hostname}
}

func (s *Server) Run() {
	// TODO: multi-user
	u := newUser(s, "jounce")

	s.lock.Lock()
	s.users[u.username] = u
	s.lock.Unlock()

	for i := range s.Upstreams {
		upstream := &s.Upstreams[i]
		// TODO: retry connecting
		go func() {
			conn, err := connectToUpstream(u, upstream)
			if err != nil {
				s.Logger.Printf("failed to connect to upstream server %q: %v", upstream.Addr, err)
				return
			}

			conn.register()

			u.lock.Lock()
			u.upstreamConns = append(u.upstreamConns, conn)
			u.lock.Unlock()

			if err := conn.readMessages(); err != nil {
				conn.logger.Printf("failed to handle messages: %v", err)
			}

			u.lock.Lock()
			for i, c := range u.upstreamConns {
				if c == conn {
					u.upstreamConns = append(u.upstreamConns[:i], u.upstreamConns[i+1:]...)
					break
				}
			}
			u.lock.Unlock()
		}()
	}
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

		conn := newDownstreamConn(s, netConn)
		go func() {
			s.lock.Lock()
			s.downstreamConns = append(s.downstreamConns, conn)
			s.lock.Unlock()

			if err := conn.readMessages(); err != nil {
				conn.logger.Printf("failed to handle messages: %v", err)
			}

			s.lock.Lock()
			for i, c := range s.downstreamConns {
				if c == conn {
					s.downstreamConns = append(s.downstreamConns[:i], s.downstreamConns[i+1:]...)
					break
				}
			}
			s.lock.Unlock()
		}()
	}
}
