package jounce

import (
	"fmt"
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
	Upstreams []Upstream // TODO: per-user

	lock            sync.Mutex
	downstreamConns []*downstreamConn
}

func (s *Server) prefix() *irc.Prefix {
	return &irc.Prefix{Name: s.Hostname}
}

func (s *Server) Run() {
	for i := range s.Upstreams {
		upstream := &s.Upstreams[i]
		// TODO: retry connecting
		go func() {
			conn, err := connectToUpstream(s, upstream)
			if err != nil {
				s.Logger.Printf("failed to connect to upstream server %q: %v", upstream.Addr, err)
				return
			}
			if err := conn.readMessages(); err != nil {
				conn.logger.Printf("failed to handle messages: %v", err)
			}
		}()
	}
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
