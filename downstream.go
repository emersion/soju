package jounce

import (
	"fmt"
	"io"
	"net"
	"strings"

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
	user       *user
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
		if err := conn.net.Close(); err != nil {
			conn.logger.Printf("failed to close connection: %v", err)
		} else {
			conn.logger.Printf("connection closed")
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

	return nil
}

func (c *downstreamConn) Close() error {
	if c.closed {
		return fmt.Errorf("downstream connection already closed")
	}

	if u := c.user; u != nil {
		u.lock.Lock()
		for i := range u.downstreamConns {
			if u.downstreamConns[i] == c {
				u.downstreamConns = append(u.downstreamConns[:i], u.downstreamConns[i+1:]...)
			}
		}
		u.lock.Unlock()
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
		if err := parseMessageParams(msg, &c.nick); err != nil {
			return err
		}
	case "USER":
		var username string
		if err := parseMessageParams(msg, &username, nil, nil, &c.realname); err != nil {
			return err
		}
		c.username = "~" + username
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
	u := c.srv.getUser(strings.TrimPrefix(c.username, "~"))
	if u == nil {
		c.logger.Printf("failed authentication: unknown username %q", c.username)
		c.messages <- &irc.Message{
			Prefix:  c.srv.prefix(),
			Command: irc.ERR_PASSWDMISMATCH,
			Params:  []string{"*", "Invalid username or password"},
		}
		return nil
	}

	c.registered = true
	c.user = u

	u.lock.Lock()
	u.downstreamConns = append(u.downstreamConns, c)
	u.lock.Unlock()

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
		Params:  []string{c.nick, "Who cares when the server was created?"},
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

	u.forEachUpstream(func(uc *upstreamConn) {
		// TODO: fix races accessing upstream connection data
		for _, ch := range uc.channels {
			if ch.complete {
				forwardChannel(c, ch)
			}
		}

		consumer := uc.ring.Consumer()
		for {
			msg := consumer.Consume()
			if msg == nil {
				break
			}
			c.messages <- msg
		}
	})

	return nil
}

func (c *downstreamConn) handleMessageRegistered(msg *irc.Message) error {
	switch msg.Command {
	case "USER":
		return ircError{&irc.Message{
			Command: irc.ERR_ALREADYREGISTERED,
			Params:  []string{c.nick, "You may not reregister"},
		}}
	case "NICK":
		c.user.forEachUpstream(func(uc *upstreamConn) {
			uc.messages <- msg
		})
	case "JOIN":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		if ch, _ := c.user.getChannel(name); ch != nil {
			break // already joined
		}

		// TODO: extract network name from channel name
		return ircError{&irc.Message{
			Command: irc.ERR_NOSUCHCHANNEL,
			Params:  []string{name, "Channel name ambiguous"},
		}}
	case "PART":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		ch, err := c.user.getChannel(name)
		if err != nil {
			return err
		}

		ch.conn.messages <- msg
		// TODO: remove channel from upstream config
	case "MODE":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		var modeStr string
		if len(msg.Params) > 1 {
			modeStr = msg.Params[1]
		}

		if msg.Prefix.Name != name {
			ch, err := c.user.getChannel(name)
			if err != nil {
				return err
			}

			if modeStr != "" {
				ch.conn.messages <- msg
			} else {
				c.messages <- &irc.Message{
					Prefix:  c.srv.prefix(),
					Command: irc.RPL_CHANNELMODEIS,
					Params:  []string{ch.Name, string(ch.modes)},
				}
			}
		} else {
			if name != c.nick {
				return ircError{&irc.Message{
					Command: irc.ERR_USERSDONTMATCH,
					Params:  []string{c.nick, "Cannot change mode for other users"},
				}}
			}

			if modeStr != "" {
				c.user.forEachUpstream(func(uc *upstreamConn) {
					uc.messages <- msg
				})
			} else {
				c.messages <- &irc.Message{
					Prefix:  c.srv.prefix(),
					Command: irc.RPL_UMODEIS,
					Params:  []string{""}, // TODO
				}
			}
		}
	default:
		c.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	return nil
}
