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
	messages chan *irc.Message

	registered bool
	user       *user
	closed     bool
	nick       string
	username   string
	realname   string
}

func newDownstreamConn(srv *Server, netConn net.Conn) *downstreamConn {
	dc := &downstreamConn{
		net:      netConn,
		irc:      irc.NewConn(netConn),
		srv:      srv,
		logger:   &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", netConn.RemoteAddr())},
		messages: make(chan *irc.Message, 64),
	}

	go func() {
		if err := dc.writeMessages(); err != nil {
			dc.logger.Printf("failed to write message: %v", err)
		}
		if err := dc.net.Close(); err != nil {
			dc.logger.Printf("failed to close connection: %v", err)
		} else {
			dc.logger.Printf("connection closed")
		}
	}()

	return dc
}

func (dc *downstreamConn) prefix() *irc.Prefix {
	return &irc.Prefix{
		Name: dc.nick,
		User: dc.username,
		// TODO: fill the host?
	}
}

func (dc *downstreamConn) readMessages() error {
	dc.logger.Printf("new connection")

	for {
		msg, err := dc.irc.ReadMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read IRC command: %v", err)
		}

		err = dc.handleMessage(msg)
		if ircErr, ok := err.(ircError); ok {
			ircErr.Message.Prefix = dc.srv.prefix()
			dc.SendMessage(ircErr.Message)
		} else if err != nil {
			return fmt.Errorf("failed to handle IRC command %q: %v", msg.Command, err)
		}

		if dc.closed {
			return nil
		}
	}

	return nil
}

func (dc *downstreamConn) writeMessages() error {
	for msg := range dc.messages {
		if err := dc.irc.WriteMessage(msg); err != nil {
			return err
		}
	}
	return nil
}

func (dc *downstreamConn) Close() error {
	if dc.closed {
		return fmt.Errorf("downstream connection already closed")
	}

	if u := dc.user; u != nil {
		u.lock.Lock()
		for i := range u.downstreamConns {
			if u.downstreamConns[i] == dc {
				u.downstreamConns = append(u.downstreamConns[:i], u.downstreamConns[i+1:]...)
			}
		}
		u.lock.Unlock()

		// TODO: figure out a better way to advance the ring buffer consumer cursor
		u.forEachUpstream(func(uc *upstreamConn) {
			// TODO: let clients specify the ring buffer name in their username
			uc.ring.Consumer("").Reset()
		})
	}

	close(dc.messages)
	dc.closed = true

	return nil
}

func (dc *downstreamConn) SendMessage(msg *irc.Message) {
	dc.messages <- msg
}

func (dc *downstreamConn) handleMessage(msg *irc.Message) error {
	switch msg.Command {
	case "QUIT":
		return dc.Close()
	case "PING":
		// TODO: handle params
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "PONG",
			Params:  []string{dc.srv.Hostname},
		})
		return nil
	default:
		if dc.registered {
			return dc.handleMessageRegistered(msg)
		} else {
			return dc.handleMessageUnregistered(msg)
		}
	}
}

func (dc *downstreamConn) handleMessageUnregistered(msg *irc.Message) error {
	switch msg.Command {
	case "NICK":
		if err := parseMessageParams(msg, &dc.nick); err != nil {
			return err
		}
	case "USER":
		var username string
		if err := parseMessageParams(msg, &username, nil, nil, &dc.realname); err != nil {
			return err
		}
		dc.username = "~" + username
	default:
		dc.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	if dc.username != "" && dc.nick != "" {
		return dc.register()
	}
	return nil
}

func (dc *downstreamConn) register() error {
	u := dc.srv.getUser(strings.TrimPrefix(dc.username, "~"))
	if u == nil {
		dc.logger.Printf("failed authentication: unknown username %q", dc.username)
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.ERR_PASSWDMISMATCH,
			Params:  []string{"*", "Invalid username or password"},
		})
		return nil
	}

	dc.registered = true
	dc.user = u

	u.lock.Lock()
	u.downstreamConns = append(u.downstreamConns, dc)
	u.lock.Unlock()

	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_WELCOME,
		Params:  []string{dc.nick, "Welcome to jounce, " + dc.nick},
	})
	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_YOURHOST,
		Params:  []string{dc.nick, "Your host is " + dc.srv.Hostname},
	})
	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_CREATED,
		Params:  []string{dc.nick, "Who cares when the server was created?"},
	})
	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_MYINFO,
		Params:  []string{dc.nick, dc.srv.Hostname, "jounce", "aiwroO", "OovaimnqpsrtklbeI"},
	})
	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.ERR_NOMOTD,
		Params:  []string{dc.nick, "No MOTD"},
	})

	u.forEachUpstream(func(uc *upstreamConn) {
		// TODO: fix races accessing upstream connection data
		for _, ch := range uc.channels {
			if ch.complete {
				forwardChannel(dc, ch)
			}
		}

		// TODO: let clients specify the ring buffer name in their username
		consumer := uc.ring.Consumer("")
		for {
			// TODO: these messages will get lost if the connection is closed
			msg := consumer.Consume()
			if msg == nil {
				break
			}
			dc.SendMessage(msg)
		}
	})

	return nil
}

func (dc *downstreamConn) handleMessageRegistered(msg *irc.Message) error {
	switch msg.Command {
	case "USER":
		return ircError{&irc.Message{
			Command: irc.ERR_ALREADYREGISTERED,
			Params:  []string{dc.nick, "You may not reregister"},
		}}
	case "NICK":
		dc.user.forEachUpstream(func(uc *upstreamConn) {
			uc.messages <- msg
		})
	case "JOIN":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		if ch, _ := dc.user.getChannel(name); ch != nil {
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

		ch, err := dc.user.getChannel(name)
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
			ch, err := dc.user.getChannel(name)
			if err != nil {
				return err
			}

			if modeStr != "" {
				ch.conn.messages <- msg
			} else {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_CHANNELMODEIS,
					Params:  []string{ch.Name, string(ch.modes)},
				})
			}
		} else {
			if name != dc.nick {
				return ircError{&irc.Message{
					Command: irc.ERR_USERSDONTMATCH,
					Params:  []string{dc.nick, "Cannot change mode for other users"},
				}}
			}

			if modeStr != "" {
				dc.user.forEachUpstream(func(uc *upstreamConn) {
					uc.messages <- msg
				})
			} else {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_UMODEIS,
					Params:  []string{""}, // TODO
				})
			}
		}
	default:
		dc.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	return nil
}
