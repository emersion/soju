package jounce

import (
	"fmt"
	"io"
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

type downstreamConn struct {
	net    net.Conn
	irc    *irc.Conn
	srv    *Server
	logger Logger

	registered bool
	closed     bool
	nick       string
	username   string
	realname   string
}

func newDownstreamConn(srv *Server, netConn net.Conn) *downstreamConn {
	return &downstreamConn{
		net:    netConn,
		irc:    irc.NewConn(netConn),
		srv:    srv,
		logger: &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", netConn.RemoteAddr())},
	}
}

func (c *downstreamConn) readMessages() error {
	c.logger.Printf("new connection")
	defer c.Close()

	for {
		msg, err := c.irc.ReadMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read IRC command: %v", err)
		}

		err = c.handleMessage(msg)
		if ircErr, ok := err.(ircError); ok {
			ircErr.Message.Prefix = c.srv.prefix()
			if err := c.WriteMessage(ircErr.Message); err != nil {
				return fmt.Errorf("failed to write IRC reply: %v", err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to handle IRC command %q: %v", msg.Command, err)
		}

		if c.closed {
			return nil
		}
	}

	return c.Close()
}

func (c *downstreamConn) Close() error {
	if err := c.net.Close(); err != nil {
		return err
	}
	c.closed = true
	return nil
}

func (c *downstreamConn) WriteMessage(msg *irc.Message) error {
	msg.Prefix = c.srv.prefix()
	return c.irc.WriteMessage(msg)
}

func (c *downstreamConn) handleMessage(msg *irc.Message) error {
	switch msg.Command {
	case "PING":
		// TODO: handle params
		return c.WriteMessage(&irc.Message{
			Command: "PONG",
			Params:  []string{c.srv.Hostname},
		})
	default:
		if c.registered {
			return c.handleMessageRegistered(msg)
		} else {
			return c.handleMessageUnregistered(msg)
		}
	}
}

func (c *downstreamConn) handleMessageUnregistered(msg *irc.Message) error {
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
	case "QUIT":
		return c.Close()
	default:
		c.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	if c.username != "" && c.nick != "" {
		return c.register()
	}
	return nil
}

func (c *downstreamConn) register() error {
	c.registered = true

	err := c.WriteMessage(&irc.Message{
		Command: irc.RPL_WELCOME,
		Params:  []string{c.nick, "Welcome to jounce, " + c.nick},
	})
	if err != nil {
		return err
	}

	err = c.WriteMessage(&irc.Message{
		Command: irc.RPL_YOURHOST,
		Params:  []string{c.nick, "Your host is " + c.srv.Hostname},
	})
	if err != nil {
		return err
	}

	err = c.WriteMessage(&irc.Message{
		Command: irc.RPL_CREATED,
		Params:  []string{c.nick, "This server was created <datetime>"}, // TODO
	})
	if err != nil {
		return err
	}

	err = c.WriteMessage(&irc.Message{
		Command: irc.RPL_MYINFO,
		Params:  []string{c.nick, c.srv.Hostname, "unknown", "aiwroO", "OovaimnqpsrtklbeI"},
	})
	if err != nil {
		return err
	}

	err = c.WriteMessage(&irc.Message{
		Command: irc.ERR_NOMOTD,
		Params:  []string{c.nick, "No MOTD"},
	})
	if err != nil {
		return err
	}

	return nil
}

func (c *downstreamConn) handleMessageRegistered(msg *irc.Message) error {
	switch msg.Command {
	case "NICK", "USER":
		return ircError{&irc.Message{
			Command: irc.ERR_ALREADYREGISTERED,
			Params: []string{
				c.nick,
				"You may not reregister",
			},
		}}
	case "QUIT":
		return c.Close()
	default:
		c.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
}
