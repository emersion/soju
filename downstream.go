package jounce

import (
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/irc.v3"
)

type ircError struct {
	Message *irc.Message
}

func (err ircError) Error() string {
	return err.Message.String()
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

var errAuthFailed = ircError{&irc.Message{
	Command: irc.ERR_PASSWDMISMATCH,
	Params:  []string{"*", "Invalid username or password"},
}}

type consumption struct {
	consumer     *RingConsumer
	upstreamConn *upstreamConn
}

type downstreamConn struct {
	net          net.Conn
	irc          *irc.Conn
	srv          *Server
	logger       Logger
	messages     chan *irc.Message
	consumptions chan consumption
	closed       chan struct{}

	registered bool
	user       *user
	nick       string
	username   string
	realname   string
	password   string   // empty after authentication
	network    *network // can be nil
}

func newDownstreamConn(srv *Server, netConn net.Conn) *downstreamConn {
	dc := &downstreamConn{
		net:          netConn,
		irc:          irc.NewConn(netConn),
		srv:          srv,
		logger:       &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", netConn.RemoteAddr())},
		messages:     make(chan *irc.Message, 64),
		consumptions: make(chan consumption),
		closed:       make(chan struct{}),
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

func (dc *downstreamConn) marshalChannel(uc *upstreamConn, name string) string {
	return name
}

func (dc *downstreamConn) forEachUpstream(f func(*upstreamConn)) {
	dc.user.forEachUpstream(func(uc *upstreamConn) {
		if dc.network != nil && uc.network != dc.network {
			return
		}
		f(uc)
	})
}

func (dc *downstreamConn) unmarshalChannel(name string) (*upstreamConn, string, error) {
	// TODO: extract network name from channel name if dc.upstream == nil
	var channel *upstreamChannel
	var err error
	dc.forEachUpstream(func(uc *upstreamConn) {
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
		return nil, "", ircError{&irc.Message{
			Command: irc.ERR_NOSUCHCHANNEL,
			Params:  []string{name, "No such channel"},
		}}
	}
	return channel.conn, channel.Name, nil
}

func (dc *downstreamConn) marshalNick(uc *upstreamConn, nick string) string {
	if nick == uc.nick {
		return dc.nick
	}
	return nick
}

func (dc *downstreamConn) marshalUserPrefix(uc *upstreamConn, prefix *irc.Prefix) *irc.Prefix {
	if prefix.Name == uc.nick {
		return dc.prefix()
	}
	return prefix
}

func (dc *downstreamConn) isClosed() bool {
	select {
	case <-dc.closed:
		return true
	default:
		return false
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

		if dc.srv.Debug {
			dc.logger.Printf("received: %v", msg)
		}

		err = dc.handleMessage(msg)
		if ircErr, ok := err.(ircError); ok {
			ircErr.Message.Prefix = dc.srv.prefix()
			dc.SendMessage(ircErr.Message)
		} else if err != nil {
			return fmt.Errorf("failed to handle IRC command %q: %v", msg.Command, err)
		}

		if dc.isClosed() {
			return nil
		}
	}

	return nil
}

func (dc *downstreamConn) writeMessages() error {
	for {
		var err error
		var closed bool
		select {
		case msg := <-dc.messages:
			if dc.srv.Debug {
				dc.logger.Printf("sent: %v", msg)
			}
			err = dc.irc.WriteMessage(msg)
		case consumption := <-dc.consumptions:
			consumer, uc := consumption.consumer, consumption.upstreamConn
			for {
				msg := consumer.Peek()
				if msg == nil {
					break
				}
				msg = msg.Copy()
				switch msg.Command {
				case "PRIVMSG":
					// TODO: detect whether it's a user or a channel
					msg.Params[0] = dc.marshalChannel(uc, msg.Params[0])
				default:
					panic("expected to consume a PRIVMSG message")
				}
				if dc.srv.Debug {
					dc.logger.Printf("sent: %v", msg)
				}
				err = dc.irc.WriteMessage(msg)
				if err != nil {
					break
				}
				consumer.Consume()
			}
		case <-dc.closed:
			closed = true
		}
		if err != nil {
			return err
		}
		if closed {
			break
		}
	}
	return nil
}

func (dc *downstreamConn) Close() error {
	if dc.isClosed() {
		return fmt.Errorf("downstream connection already closed")
	}

	if u := dc.user; u != nil {
		u.lock.Lock()
		for i := range u.downstreamConns {
			if u.downstreamConns[i] == dc {
				u.downstreamConns = append(u.downstreamConns[:i], u.downstreamConns[i+1:]...)
				break
			}
		}
		u.lock.Unlock()
	}

	close(dc.closed)
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
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "PONG",
			Params:  msg.Params,
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
	case "PASS":
		if err := parseMessageParams(msg, &dc.password); err != nil {
			return err
		}
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
	username := strings.TrimPrefix(dc.username, "~")
	var networkName string
	if i := strings.LastIndexAny(username, "/@"); i >= 0 {
		networkName = username[i+1:]
	}
	if i := strings.IndexAny(username, "/@"); i >= 0 {
		username = username[:i]
	}

	password := dc.password
	dc.password = ""

	u := dc.srv.getUser(username)
	if u == nil {
		dc.logger.Printf("failed authentication for %q: unknown username", username)
		return errAuthFailed
	}

	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		dc.logger.Printf("failed authentication for %q: %v", username, err)
		return errAuthFailed
	}

	var network *network
	if networkName != "" {
		network = u.getNetwork(networkName)
		if network == nil {
			dc.logger.Printf("failed registration: unknown network %q", networkName)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.ERR_PASSWDMISMATCH,
				Params:  []string{"*", fmt.Sprintf("Unknown network %q", networkName)},
			})
			return nil
		}
	}

	dc.registered = true
	dc.user = u
	dc.network = network

	u.lock.Lock()
	firstDownstream := len(u.downstreamConns) == 0
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

	dc.forEachUpstream(func(uc *upstreamConn) {
		// TODO: fix races accessing upstream connection data
		for _, ch := range uc.channels {
			if ch.complete {
				forwardChannel(dc, ch)
			}
		}

		historyName := dc.username

		var seqPtr *uint64
		if firstDownstream {
			seq, ok := uc.history[historyName]
			if ok {
				seqPtr = &seq
			}
		}

		consumer, ch := uc.ring.NewConsumer(seqPtr)
		go func() {
			for {
				var closed bool
				select {
				case <-ch:
					dc.consumptions <- consumption{consumer, uc}
				case <-dc.closed:
					closed = true
				}
				if closed {
					break
				}
			}

			seq := consumer.Close()

			dc.user.lock.Lock()
			lastDownstream := len(dc.user.downstreamConns) == 0
			dc.user.lock.Unlock()

			if lastDownstream {
				uc.history[historyName] = seq
			}
		}()
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
		dc.forEachUpstream(func(uc *upstreamConn) {
			uc.SendMessage(msg)
		})
	case "JOIN", "PART":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		uc, upstreamName, err := dc.unmarshalChannel(name)
		if err != nil {
			return ircError{&irc.Message{
				Command: irc.ERR_NOSUCHCHANNEL,
				Params:  []string{name, err.Error()},
			}}
		}

		uc.SendMessage(&irc.Message{
			Command: msg.Command,
			Params:  []string{upstreamName},
		})
		// TODO: add/remove channel from upstream config
	case "MODE":
		if msg.Prefix == nil {
			return fmt.Errorf("missing prefix")
		}

		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		var modeStr string
		if len(msg.Params) > 1 {
			modeStr = msg.Params[1]
		}

		if msg.Prefix.Name != name {
			uc, upstreamName, err := dc.unmarshalChannel(name)
			if err != nil {
				return err
			}

			if modeStr != "" {
				uc.SendMessage(&irc.Message{
					Command: "MODE",
					Params:  []string{upstreamName, modeStr},
				})
			} else {
				ch, ok := uc.channels[upstreamName]
				if !ok {
					return ircError{&irc.Message{
						Command: irc.ERR_NOSUCHCHANNEL,
						Params:  []string{name, "No such channel"},
					}}
				}

				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_CHANNELMODEIS,
					Params:  []string{name, string(ch.modes)},
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
				dc.forEachUpstream(func(uc *upstreamConn) {
					uc.SendMessage(&irc.Message{
						Command: "MODE",
						Params:  []string{uc.nick, modeStr},
					})
				})
			} else {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_UMODEIS,
					Params:  []string{""}, // TODO
				})
			}
		}
	case "PRIVMSG":
		var targetsStr, text string
		if err := parseMessageParams(msg, &targetsStr, &text); err != nil {
			return err
		}

		for _, name := range strings.Split(targetsStr, ",") {
			uc, upstreamName, err := dc.unmarshalChannel(name)
			if err != nil {
				return err
			}

			uc.SendMessage(&irc.Message{
				Command: "PRIVMSG",
				Params:  []string{upstreamName, text},
			})
		}
	default:
		dc.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	return nil
}
