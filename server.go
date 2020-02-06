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
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go func() {
			if err := handleConn(s, c); err != nil {
				s.Logger.Printf("Error handling connection: %v", err)
			}
		}()
	}
}
