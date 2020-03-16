package soju

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

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
	outgoing     chan *irc.Message
	consumptions chan consumption
	closed       chan struct{}

	registered  bool
	user        *user
	nick        string
	username    string
	rawUsername string
	realname    string
	password    string   // empty after authentication
	network     *network // can be nil
}

func newDownstreamConn(srv *Server, netConn net.Conn) *downstreamConn {
	dc := &downstreamConn{
		net:          netConn,
		irc:          irc.NewConn(netConn),
		srv:          srv,
		logger:       &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", netConn.RemoteAddr())},
		outgoing:     make(chan *irc.Message, 64),
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

func (dc *downstreamConn) forEachNetwork(f func(*network)) {
	if dc.network != nil {
		f(dc.network)
	} else {
		dc.user.forEachNetwork(f)
	}
}

func (dc *downstreamConn) forEachUpstream(f func(*upstreamConn)) {
	dc.user.forEachUpstream(func(uc *upstreamConn) {
		if dc.network != nil && uc.network != dc.network {
			return
		}
		f(uc)
	})
}

// upstream returns the upstream connection, if any. If there are zero or if
// there are multiple upstream connections, it returns nil.
func (dc *downstreamConn) upstream() *upstreamConn {
	if dc.network == nil {
		return nil
	}

	var upstream *upstreamConn
	dc.forEachUpstream(func(uc *upstreamConn) {
		upstream = uc
	})
	return upstream
}

func (dc *downstreamConn) unmarshalChannel(name string) (*upstreamConn, string, error) {
	if uc := dc.upstream(); uc != nil {
		return uc, name, nil
	}

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

func (dc *downstreamConn) readMessages(ch chan<- downstreamIncomingMessage) error {
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

		ch <- downstreamIncomingMessage{msg, dc}
	}

	return nil
}

func (dc *downstreamConn) writeMessages() error {
	for {
		var err error
		var closed bool
		select {
		case msg := <-dc.outgoing:
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
	dc.outgoing <- msg
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
		dc.rawUsername = username
	case "PASS":
		if err := parseMessageParams(msg, &dc.password); err != nil {
			return err
		}
	default:
		dc.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	if dc.rawUsername != "" && dc.nick != "" {
		return dc.register()
	}
	return nil
}

func sanityCheckServer(addr string) error {
	dialer := net.Dialer{Timeout: 30 * time.Second}
	conn, err := tls.DialWithDialer(&dialer, "tcp", addr, nil)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (dc *downstreamConn) register() error {
	username := dc.rawUsername
	var networkName string
	if i := strings.LastIndexAny(username, "/@"); i >= 0 {
		networkName = username[i+1:]
	}
	if i := strings.IndexAny(username, "/@"); i >= 0 {
		username = username[:i]
	}
	dc.username = "~" + username

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
			addr := networkName
			if !strings.ContainsRune(addr, ':') {
				addr = addr + ":6697"
			}

			dc.logger.Printf("trying to connect to new network %q", addr)
			if err := sanityCheckServer(addr); err != nil {
				dc.logger.Printf("failed to connect to %q: %v", addr, err)
				return ircError{&irc.Message{
					Command: irc.ERR_PASSWDMISMATCH,
					Params:  []string{"*", fmt.Sprintf("Failed to connect to %q", networkName)},
				}}
			}

			dc.logger.Printf("auto-saving network %q", networkName)
			network, err = u.createNetwork(networkName, dc.nick)
			if err != nil {
				return err
			}
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
		Params:  []string{dc.nick, "Welcome to soju, " + dc.nick},
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
		Params:  []string{dc.nick, dc.srv.Hostname, "soju", "aiwroO", "OovaimnqpsrtklbeI"},
	})
	// TODO: RPL_ISUPPORT
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

func (dc *downstreamConn) runUntilRegistered() error {
	for !dc.registered {
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
			return fmt.Errorf("failed to handle IRC command %q: %v", msg, err)
		}
	}

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
		var nick string
		if err := parseMessageParams(msg, &nick); err != nil {
			return err
		}

		var err error
		dc.forEachNetwork(func(n *network) {
			if err != nil {
				return
			}
			n.Nick = nick
			err = dc.srv.db.StoreNetwork(dc.user.Username, &n.Network)
		})
		if err != nil {
			return err
		}

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

		switch msg.Command {
		case "JOIN":
			err := dc.srv.db.StoreChannel(uc.network.ID, &Channel{
				Name: upstreamName,
			})
			if err != nil {
				dc.logger.Printf("failed to create channel %q in DB: %v", upstreamName, err)
			}
		case "PART":
			if err := dc.srv.db.DeleteChannel(uc.network.ID, upstreamName); err != nil {
				dc.logger.Printf("failed to delete channel %q in DB: %v", upstreamName, err)
			}
		}
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

			if upstreamName == "NickServ" {
				dc.handleNickServPRIVMSG(uc, text)
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

func (dc *downstreamConn) handleNickServPRIVMSG(uc *upstreamConn, text string) {
	username, password, ok := parseNickServCredentials(text, uc.nick)
	if !ok {
		return
	}

	dc.logger.Printf("auto-saving NickServ credentials with username %q", username)
	n := uc.network
	n.SASL.Mechanism = "PLAIN"
	n.SASL.Plain.Username = username
	n.SASL.Plain.Password = password
	if err := dc.srv.db.StoreNetwork(dc.user.Username, &n.Network); err != nil {
		dc.logger.Printf("failed to save NickServ credentials: %v", err)
	}
}

func parseNickServCredentials(text, nick string) (username, password string, ok bool) {
	fields := strings.Fields(text)
	if len(fields) < 2 {
		return "", "", false
	}
	cmd := strings.ToUpper(fields[0])
	params := fields[1:]
	switch cmd {
	case "REGISTER":
		username = nick
		password = params[0]
	case "IDENTIFY":
		if len(params) == 1 {
			username = nick
		} else {
			username = params[0]
		}
		password = params[1]
	}
	return username, password, true
}
