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
	Debug     bool
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

func (s *Server) runUpstream(u *user, upstream *Upstream) {
	var lastTry time.Time
	for {
		if dur := time.Now().Sub(lastTry); dur < retryConnectMinDelay {
			delay := retryConnectMinDelay - dur
			s.Logger.Printf("waiting %v before trying to reconnect to %q", delay.Truncate(time.Second), upstream.Addr)
			time.Sleep(delay)
		}
		lastTry = time.Now()

		uc, err := connectToUpstream(u, upstream)
		if err != nil {
			s.Logger.Printf("failed to connect to upstream server %q: %v", upstream.Addr, err)
			continue
		}

		uc.register()

		u.lock.Lock()
		u.upstreamConns = append(u.upstreamConns, uc)
		u.lock.Unlock()

		if err := uc.readMessages(); err != nil {
			uc.logger.Printf("failed to handle messages: %v", err)
		}
		uc.Close()

		u.lock.Lock()
		for i := range u.upstreamConns {
			if u.upstreamConns[i] == uc {
				u.upstreamConns = append(u.upstreamConns[:i], u.upstreamConns[i+1:]...)
				break
			}
		}
		u.lock.Unlock()
	}
}

func (s *Server) Run() {
	// TODO: multi-user
	u := newUser(s, "jounce")

	s.lock.Lock()
	s.users[u.username] = u
	s.lock.Unlock()

	for i := range s.Upstreams {
		go s.runUpstream(u, &s.Upstreams[i])
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
