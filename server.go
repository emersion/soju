package jounce

import (
	"fmt"
	"io"
	"log"
	"net"

	"gopkg.in/irc.v3"
)

type conn struct {
	net net.Conn
	irc *irc.Conn
}

type Server struct{}

func (s *Server) handleConn(netConn net.Conn) error {
	defer netConn.Close()

	conn := conn{netConn, irc.NewConn(netConn)}
	for {
		msg, err := conn.irc.ReadMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		log.Println(msg)

		switch msg.Command {
		default:
			err = conn.irc.WriteMessage(&irc.Message{
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params: []string{
					"*",
					msg.Command,
					"Unknown command",
				},
			})
		}
	}

	return netConn.Close()
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go func() {
			if err := s.handleConn(c); err != nil {
				log.Printf("error handling connection: %v", err)
			}
		}()
	}
}
