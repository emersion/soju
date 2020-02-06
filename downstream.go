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
	net      net.Conn
	irc      *irc.Conn
	srv      *Server
	logger   Logger
	messages chan<- *irc.Message

	registered bool
	closed     bool
	nick       string
	username   string
	realname   string
}

func newDownstreamConn(srv *Server, netConn net.Conn) *downstreamConn {
	msgs := make(chan *irc.Message, 64)
	conn := &downstreamConn{
		net:      netConn,
		irc:      irc.NewConn(netConn),
		srv:      srv,
		logger:   &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", netConn.RemoteAddr())},
		messages: msgs,
	}

	go func() {
		for msg := range msgs {
			if err := conn.irc.WriteMessage(msg); err != nil {
				conn.logger.Printf("failed to write message: %v", err)
			}
		}
	}()

	return conn
}

func (c *downstreamConn) prefix() *irc.Prefix {
	return &irc.Prefix{
		Name: c.nick,
		User: c.username,
		// TODO: fill the host?
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
			c.messages <- ircErr.Message
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
	if c.closed {
		return fmt.Errorf("downstream connection already closed")
	}
	if err := c.net.Close(); err != nil {
		return err
	}
	close(c.messages)
	c.closed = true
	return nil
}

func (c *downstreamConn) handleMessage(msg *irc.Message) error {
	switch msg.Command {
	case "QUIT":
		return c.Close()
	case "PING":
		// TODO: handle params
		c.messages <- &irc.Message{
			Prefix:  c.srv.prefix(),
			Command: "PONG",
			Params:  []string{c.srv.Hostname},
		}
		return nil
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

	c.messages <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.RPL_WELCOME,
		Params:  []string{c.nick, "Welcome to jounce, " + c.nick},
	}

	c.messages <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.RPL_YOURHOST,
		Params:  []string{c.nick, "Your host is " + c.srv.Hostname},
	}

	c.messages <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.RPL_CREATED,
		Params:  []string{c.nick, "This server was created <datetime>"}, // TODO
	}

	c.messages <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.RPL_MYINFO,
		Params:  []string{c.nick, c.srv.Hostname, "jounce", "aiwroO", "OovaimnqpsrtklbeI"},
	}

	c.messages <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.ERR_NOMOTD,
		Params:  []string{c.nick, "No MOTD"},
	}

	c.srv.lock.Lock()
	for _, uc := range c.srv.upstreamConns {
		// TODO: fix races accessing upstream connection data
		if !uc.registered {
			continue
		}
		for _, ch := range uc.channels {
			if ch.complete {
				forwardChannel(c, ch)
			}
		}
	}
	c.srv.lock.Unlock()

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
	default:
		c.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
}
