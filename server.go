package jounce

import (
	"fmt"
	"net"

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
			if err := connect(s, upstream); err != nil {
				s.Logger.Printf("Failed to connect to upstream server %q: %v", upstream.Addr, err)
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
		s.downstreamConns = append(s.downstreamConns, conn)
		go func() {
			if err := conn.readMessages(); err != nil {
				conn.logger.Printf("Error handling messages: %v", err)
			}
		}()
	}
}
