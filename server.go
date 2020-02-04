package jounce

import (
	"fmt"
	"io"
	"log"
	"net"

	"gopkg.in/irc.v3"
)

type ircError struct {
	Message *irc.Message
}

func newUnknownCommandError(cmd string) ircError {
	return ircError{&irc.Message{
		Command: irc.ERR_UNKNOWNCOMMAND,
		Params: []string{
			"*",
			cmd,
			"Unknown command",
		},
	}}
}

func newNeedMoreParamsError(cmd string) ircError {
	return ircError{&irc.Message{
		Command: irc.ERR_NEEDMOREPARAMS,
		Params: []string{
			"*",
			cmd,
			"Not enough parameters",
		},
	}}
}

func (err ircError) Error() string {
	return err.Message.String()
}

type conn struct {
	net        net.Conn
	irc        *irc.Conn
	registered bool
	nick       string
	username   string
	realname   string
}

func (c *conn) handleMessageUnregistered(msg *irc.Message) error {
	switch msg.Command {
	case "NICK":
		if len(msg.Params) != 1 {
			return newNeedMoreParamsError(msg.Command)
		}
		c.nick = msg.Params[0]
	case "USER":
		if len(msg.Params) != 4 {
			return newNeedMoreParamsError(msg.Command)
		}
		c.username = "~" + msg.Params[0]
		c.realname = msg.Params[3]
		c.registered = true
	default:
		return newUnknownCommandError(msg.Command)
	}
	return nil
}

func (c *conn) handleMessage(msg *irc.Message) error {
	switch msg.Command {
	case "NICK", "USER":
		return ircError{&irc.Message{
			Command: irc.ERR_ALREADYREGISTERED,
			Params: []string{
				c.nick,
				"You may not reregister",
			},
		}}
	default:
		return newUnknownCommandError(msg.Command)
	}
}

type Server struct{}

func (s *Server) handleConn(netConn net.Conn) error {
	defer netConn.Close()

	c := conn{net: netConn, irc: irc.NewConn(netConn)}
	for {
		msg, err := c.irc.ReadMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read IRC command: %v", err)
		}
		log.Println(msg)

		if c.registered {
			err = c.handleMessage(msg)
		} else {
			err = c.handleMessageUnregistered(msg)
		}
		if ircErr, ok := err.(ircError); ok {
			if err := c.irc.WriteMessage(ircErr.Message); err != nil {
				return fmt.Errorf("failed to write IRC reply: %v", err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to handle IRC command %q: %v", msg.Command, err)
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
