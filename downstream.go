package soju

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
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

type downstreamConn struct {
	conn

	id uint64

	registered  bool
	user        *user
	nick        string
	rawUsername string
	networkName string
	clientName  string
	realname    string
	hostname    string
	password    string   // empty after authentication
	network     *network // can be nil

	negociatingCaps bool
	capVersion      int
	caps            map[string]bool

	saslServer sasl.Server
}

func newDownstreamConn(srv *Server, netConn net.Conn, id uint64) *downstreamConn {
	logger := &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", netConn.RemoteAddr())}
	dc := &downstreamConn{
		conn: *newConn(srv, netConn, logger),
		id:   id,
		caps: make(map[string]bool),
	}
	dc.hostname = netConn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(dc.hostname); err == nil {
		dc.hostname = host
	}
	return dc
}

func (dc *downstreamConn) prefix() *irc.Prefix {
	return &irc.Prefix{
		Name: dc.nick,
		User: dc.user.Username,
		Host: dc.hostname,
	}
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
	return dc.network.upstream()
}

// marshalEntity converts an upstream entity name (ie. channel or nick) into a
// downstream entity name.
//
// This involves adding a "/<network>" suffix if the entity isn't the current
// user.
func (dc *downstreamConn) marshalEntity(uc *upstreamConn, entity string) string {
	if uc.isChannel(entity) {
		return dc.marshalChannel(uc, entity)
	}
	return dc.marshalNick(uc, entity)
}

func (dc *downstreamConn) marshalChannel(uc *upstreamConn, name string) string {
	if dc.network != nil {
		return name
	}
	return name + "/" + uc.network.GetName()
}

// unmarshalEntity converts a downstream entity name (ie. channel or nick) into
// an upstream entity name.
//
// This involves removing the "/<network>" suffix.
func (dc *downstreamConn) unmarshalEntity(name string) (*upstreamConn, string, error) {
	if uc := dc.upstream(); uc != nil {
		return uc, name, nil
	}

	var conn *upstreamConn
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		network := name[i+1:]
		name = name[:i]

		dc.forEachUpstream(func(uc *upstreamConn) {
			if network != uc.network.GetName() {
				return
			}
			conn = uc
		})
	}

	if conn == nil {
		return nil, "", ircError{&irc.Message{
			Command: irc.ERR_NOSUCHCHANNEL,
			Params:  []string{name, "No such channel"},
		}}
	}
	return conn, name, nil
}

func (dc *downstreamConn) marshalNick(uc *upstreamConn, nick string) string {
	if nick == uc.nick {
		return dc.nick
	}
	if dc.network != nil {
		return nick
	}
	return nick + "/" + uc.network.GetName()
}

func (dc *downstreamConn) marshalUserPrefix(uc *upstreamConn, prefix *irc.Prefix) *irc.Prefix {
	if prefix.Name == uc.nick {
		return dc.prefix()
	}
	if dc.network != nil {
		return prefix
	}
	return &irc.Prefix{
		Name: prefix.Name + "/" + uc.network.GetName(),
		User: prefix.User,
		Host: prefix.Host,
	}
}

func (dc *downstreamConn) readMessages(ch chan<- event) error {
	for {
		msg, err := dc.ReadMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read IRC command: %v", err)
		}

		ch <- eventDownstreamMessage{msg, dc}
	}

	return nil
}

// SendMessage sends an outgoing message.
//
// This can only called from the user goroutine.
func (dc *downstreamConn) SendMessage(msg *irc.Message) {
	if !dc.caps["message-tags"] {
		msg = msg.Copy()
		for name := range msg.Tags {
			supported := false
			switch name {
			case "time":
				supported = dc.caps["server-time"]
			}
			if !supported {
				delete(msg.Tags, name)
			}
		}
	}

	dc.conn.SendMessage(msg)
}

// marshalMessage re-formats a message coming from an upstream connection so
// that it's suitable for being sent on this downstream connection. Only
// messages that may appear in logs are supported.
func (dc *downstreamConn) marshalMessage(msg *irc.Message, uc *upstreamConn) *irc.Message {
	msg = msg.Copy()
	msg.Prefix = dc.marshalUserPrefix(uc, msg.Prefix)

	switch msg.Command {
	case "PRIVMSG", "NOTICE":
		msg.Params[0] = dc.marshalEntity(uc, msg.Params[0])
	case "NICK":
		// Nick change for another user
		msg.Params[0] = dc.marshalNick(uc, msg.Params[0])
	case "JOIN", "PART":
		msg.Params[0] = dc.marshalChannel(uc, msg.Params[0])
	case "KICK":
		msg.Params[0] = dc.marshalChannel(uc, msg.Params[0])
		msg.Params[1] = dc.marshalNick(uc, msg.Params[1])
	case "TOPIC":
		msg.Params[0] = dc.marshalChannel(uc, msg.Params[0])
	case "MODE":
		msg.Params[0] = dc.marshalEntity(uc, msg.Params[0])
	case "QUIT":
		// This space is intentinally left blank
	default:
		panic(fmt.Sprintf("unexpected %q message", msg.Command))
	}

	return msg
}

func (dc *downstreamConn) handleMessage(msg *irc.Message) error {
	switch msg.Command {
	case "QUIT":
		return dc.Close()
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
		var nick string
		if err := parseMessageParams(msg, &nick); err != nil {
			return err
		}
		if nick == serviceNick {
			return ircError{&irc.Message{
				Command: irc.ERR_NICKNAMEINUSE,
				Params:  []string{dc.nick, nick, "Nickname reserved for bouncer service"},
			}}
		}
		dc.nick = nick
	case "USER":
		if err := parseMessageParams(msg, &dc.rawUsername, nil, nil, &dc.realname); err != nil {
			return err
		}
	case "PASS":
		if err := parseMessageParams(msg, &dc.password); err != nil {
			return err
		}
	case "CAP":
		var subCmd string
		if err := parseMessageParams(msg, &subCmd); err != nil {
			return err
		}
		if err := dc.handleCapCommand(subCmd, msg.Params[1:]); err != nil {
			return err
		}
	case "AUTHENTICATE":
		if !dc.caps["sasl"] {
			return ircError{&irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{"*", "AUTHENTICATE requires the \"sasl\" capability to be enabled"},
			}}
		}
		if len(msg.Params) == 0 {
			return ircError{&irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{"*", "Missing AUTHENTICATE argument"},
			}}
		}
		if dc.nick == "" {
			return ircError{&irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{"*", "Expected NICK command before AUTHENTICATE"},
			}}
		}

		var resp []byte
		if dc.saslServer == nil {
			mech := strings.ToUpper(msg.Params[0])
			switch mech {
			case "PLAIN":
				dc.saslServer = sasl.NewPlainServer(sasl.PlainAuthenticator(func(identity, username, password string) error {
					return dc.authenticate(username, password)
				}))
			default:
				return ircError{&irc.Message{
					Command: irc.ERR_SASLFAIL,
					Params:  []string{"*", fmt.Sprintf("Unsupported SASL mechanism %q", mech)},
				}}
			}
		} else if msg.Params[0] == "*" {
			dc.saslServer = nil
			return ircError{&irc.Message{
				Command: irc.ERR_SASLABORTED,
				Params:  []string{"*", "SASL authentication aborted"},
			}}
		} else if msg.Params[0] == "+" {
			resp = nil
		} else {
			// TODO: multi-line messages
			var err error
			resp, err = base64.StdEncoding.DecodeString(msg.Params[0])
			if err != nil {
				dc.saslServer = nil
				return ircError{&irc.Message{
					Command: irc.ERR_SASLFAIL,
					Params:  []string{"*", "Invalid base64-encoded response"},
				}}
			}
		}

		challenge, done, err := dc.saslServer.Next(resp)
		if err != nil {
			dc.saslServer = nil
			if ircErr, ok := err.(ircError); ok && ircErr.Message.Command == irc.ERR_PASSWDMISMATCH {
				return ircError{&irc.Message{
					Command: irc.ERR_SASLFAIL,
					Params:  []string{"*", ircErr.Message.Params[1]},
				}}
			}
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.ERR_SASLFAIL,
				Params:  []string{"*", "SASL error"},
			})
			return fmt.Errorf("SASL authentication failed: %v", err)
		} else if done {
			dc.saslServer = nil
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_LOGGEDIN,
				Params:  []string{dc.nick, dc.nick, dc.user.Username, "You are now logged in"},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_SASLSUCCESS,
				Params:  []string{dc.nick, "SASL authentication successful"},
			})
		} else {
			challengeStr := "+"
			if len(challenge) > 0 {
				challengeStr = base64.StdEncoding.EncodeToString(challenge)
			}

			// TODO: multi-line messages
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "AUTHENTICATE",
				Params:  []string{challengeStr},
			})
		}
	default:
		dc.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	if dc.rawUsername != "" && dc.nick != "" && !dc.negociatingCaps {
		return dc.register()
	}
	return nil
}

func (dc *downstreamConn) handleCapCommand(cmd string, args []string) error {
	cmd = strings.ToUpper(cmd)

	replyTo := dc.nick
	if !dc.registered {
		replyTo = "*"
	}

	switch cmd {
	case "LS":
		if len(args) > 0 {
			var err error
			if dc.capVersion, err = strconv.Atoi(args[0]); err != nil {
				return err
			}
		}

		caps := []string{"message-tags", "server-time", "echo-message"}

		if dc.capVersion >= 302 {
			caps = append(caps, "sasl=PLAIN")
		} else {
			caps = append(caps, "sasl")
		}

		// TODO: multi-line replies
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "CAP",
			Params:  []string{replyTo, "LS", strings.Join(caps, " ")},
		})

		if !dc.registered {
			dc.negociatingCaps = true
		}
	case "LIST":
		var caps []string
		for name := range dc.caps {
			caps = append(caps, name)
		}

		// TODO: multi-line replies
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "CAP",
			Params:  []string{replyTo, "LIST", strings.Join(caps, " ")},
		})
	case "REQ":
		if len(args) == 0 {
			return ircError{&irc.Message{
				Command: err_invalidcapcmd,
				Params:  []string{replyTo, cmd, "Missing argument in CAP REQ command"},
			}}
		}

		caps := strings.Fields(args[0])
		ack := true
		for _, name := range caps {
			name = strings.ToLower(name)
			enable := !strings.HasPrefix(name, "-")
			if !enable {
				name = strings.TrimPrefix(name, "-")
			}

			enabled := dc.caps[name]
			if enable == enabled {
				continue
			}

			switch name {
			case "sasl", "message-tags", "server-time", "echo-message":
				dc.caps[name] = enable
			default:
				ack = false
			}
		}

		reply := "NAK"
		if ack {
			reply = "ACK"
		}
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "CAP",
			Params:  []string{replyTo, reply, args[0]},
		})
	case "END":
		dc.negociatingCaps = false
	default:
		return ircError{&irc.Message{
			Command: err_invalidcapcmd,
			Params:  []string{replyTo, cmd, "Unknown CAP command"},
		}}
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

func unmarshalUsername(rawUsername string) (username, client, network string) {
	username = rawUsername

	i := strings.IndexAny(username, "/@")
	j := strings.LastIndexAny(username, "/@")
	if i >= 0 {
		username = rawUsername[:i]
	}
	if j >= 0 {
		if rawUsername[j] == '@' {
			client = rawUsername[j+1:]
		} else {
			network = rawUsername[j+1:]
		}
	}
	if i >= 0 && j >= 0 && i < j {
		if rawUsername[i] == '@' {
			client = rawUsername[i+1 : j]
		} else {
			network = rawUsername[i+1 : j]
		}
	}

	return username, client, network
}

func (dc *downstreamConn) authenticate(username, password string) error {
	username, clientName, networkName := unmarshalUsername(username)

	u, err := dc.srv.db.GetUser(username)
	if err != nil {
		dc.logger.Printf("failed authentication for %q: %v", username, err)
		return errAuthFailed
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		dc.logger.Printf("failed authentication for %q: %v", username, err)
		return errAuthFailed
	}

	dc.user = dc.srv.getUser(username)
	if dc.user == nil {
		dc.logger.Printf("failed authentication for %q: user not active", username)
		return errAuthFailed
	}
	dc.clientName = clientName
	dc.networkName = networkName
	return nil
}

func (dc *downstreamConn) register() error {
	if dc.registered {
		return fmt.Errorf("tried to register twice")
	}

	password := dc.password
	dc.password = ""
	if dc.user == nil {
		if err := dc.authenticate(dc.rawUsername, password); err != nil {
			return err
		}
	}

	if dc.clientName == "" && dc.networkName == "" {
		_, dc.clientName, dc.networkName = unmarshalUsername(dc.rawUsername)
	}

	dc.registered = true
	dc.logger.Printf("registration complete for user %q", dc.user.Username)
	return nil
}

func (dc *downstreamConn) loadNetwork() error {
	if dc.networkName == "" {
		return nil
	}

	network := dc.user.getNetwork(dc.networkName)
	if network == nil {
		addr := dc.networkName
		if !strings.ContainsRune(addr, ':') {
			addr = addr + ":6697"
		}

		dc.logger.Printf("trying to connect to new network %q", addr)
		if err := sanityCheckServer(addr); err != nil {
			dc.logger.Printf("failed to connect to %q: %v", addr, err)
			return ircError{&irc.Message{
				Command: irc.ERR_PASSWDMISMATCH,
				Params:  []string{"*", fmt.Sprintf("Failed to connect to %q", dc.networkName)},
			}}
		}

		dc.logger.Printf("auto-saving network %q", dc.networkName)
		var err error
		network, err = dc.user.createNetwork(&Network{
			Addr: dc.networkName,
			Nick: dc.nick,
		})
		if err != nil {
			return err
		}
	}

	dc.network = network
	return nil
}

func (dc *downstreamConn) welcome() error {
	if dc.user == nil || !dc.registered {
		panic("tried to welcome an unregistered connection")
	}

	// TODO: doing this might take some time. We should do it in dc.register
	// instead, but we'll potentially be adding a new network and this must be
	// done in the user goroutine.
	if err := dc.loadNetwork(); err != nil {
		return err
	}

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
		for _, ch := range uc.channels {
			if ch.complete {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.prefix(),
					Command: "JOIN",
					Params:  []string{dc.marshalChannel(ch.conn, ch.Name)},
				})

				forwardChannel(dc, ch)
			}
		}
	})

	dc.forEachNetwork(func(net *network) {
		// Only send history if we're the first connected client with that name
		// for the network
		if _, ok := net.offlineClients[dc.clientName]; ok {
			dc.sendNetworkHistory(net)
			delete(net.offlineClients, dc.clientName)
		}
	})

	return nil
}

func (dc *downstreamConn) sendNetworkHistory(net *network) {
	for target, history := range net.history {
		seq, ok := history.offlineClients[dc.clientName]
		if !ok {
			continue
		}
		delete(history.offlineClients, dc.clientName)

		// If all clients have received history, no need to keep the
		// ring buffer around
		if len(history.offlineClients) == 0 {
			delete(net.history, target)
		}

		consumer := history.ring.NewConsumer(seq)

		// TODO: this means all history is lost when trying to send it while the
		// upstream is disconnected. We need to store history differently so that
		// we don't need access to upstreamConn to forward it to a downstream
		// client.
		uc := net.upstream()
		if uc == nil {
			dc.logger.Printf("ignoring messages for upstream %q: upstream is disconnected", net.Addr)
			return
		}

		for {
			msg := consumer.Consume()
			if msg == nil {
				break
			}

			// Don't replay all messages, because that would mess up client
			// state. For instance we just sent the list of users, sending
			// PART messages for one of these users would be incorrect.
			ignore := true
			switch msg.Command {
			case "PRIVMSG", "NOTICE":
				ignore = false
			}
			if ignore {
				continue
			}

			dc.SendMessage(dc.marshalMessage(msg, uc))
		}
	}
}

func (dc *downstreamConn) runUntilRegistered() error {
	for !dc.registered {
		msg, err := dc.ReadMessage()
		if err != nil {
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
	case "CAP":
		var subCmd string
		if err := parseMessageParams(msg, &subCmd); err != nil {
			return err
		}
		if err := dc.handleCapCommand(subCmd, msg.Params[1:]); err != nil {
			return err
		}
	case "PING":
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "PONG",
			Params:  msg.Params,
		})
		return nil
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
	case "JOIN":
		var namesStr string
		if err := parseMessageParams(msg, &namesStr); err != nil {
			return err
		}

		var keys []string
		if len(msg.Params) > 1 {
			keys = strings.Split(msg.Params[1], ",")
		}

		for i, name := range strings.Split(namesStr, ",") {
			uc, upstreamName, err := dc.unmarshalEntity(name)
			if err != nil {
				return err
			}

			var key string
			if len(keys) > i {
				key = keys[i]
			}

			params := []string{upstreamName}
			if key != "" {
				params = append(params, key)
			}
			uc.SendMessage(&irc.Message{
				Command: "JOIN",
				Params:  params,
			})

			ch := &Channel{Name: upstreamName, Key: key}
			if err := uc.network.createUpdateChannel(ch); err != nil {
				dc.logger.Printf("failed to create or update channel %q: %v", upstreamName, err)
			}
		}
	case "PART":
		var namesStr string
		if err := parseMessageParams(msg, &namesStr); err != nil {
			return err
		}

		var reason string
		if len(msg.Params) > 1 {
			reason = msg.Params[1]
		}

		for _, name := range strings.Split(namesStr, ",") {
			uc, upstreamName, err := dc.unmarshalEntity(name)
			if err != nil {
				return err
			}

			params := []string{upstreamName}
			if reason != "" {
				params = append(params, reason)
			}
			uc.SendMessage(&irc.Message{
				Command: "PART",
				Params:  params,
			})

			if err := uc.network.deleteChannel(upstreamName); err != nil {
				dc.logger.Printf("failed to delete channel %q: %v", upstreamName, err)
			}
		}
	case "KICK":
		var channelStr, userStr string
		if err := parseMessageParams(msg, &channelStr, &userStr); err != nil {
			return err
		}

		channels := strings.Split(channelStr, ",")
		users := strings.Split(userStr, ",")

		var reason string
		if len(msg.Params) > 2 {
			reason = msg.Params[2]
		}

		if len(channels) != 1 && len(channels) != len(users) {
			return ircError{&irc.Message{
				Command: irc.ERR_BADCHANMASK,
				Params:  []string{dc.nick, channelStr, "Bad channel mask"},
			}}
		}

		for i, user := range users {
			var channel string
			if len(channels) == 1 {
				channel = channels[0]
			} else {
				channel = channels[i]
			}

			ucChannel, upstreamChannel, err := dc.unmarshalEntity(channel)
			if err != nil {
				return err
			}

			ucUser, upstreamUser, err := dc.unmarshalEntity(user)
			if err != nil {
				return err
			}

			if ucChannel != ucUser {
				return ircError{&irc.Message{
					Command: irc.ERR_USERNOTINCHANNEL,
					Params:  []string{dc.nick, user, channel, "They aren't on that channel"},
				}}
			}
			uc := ucChannel

			params := []string{upstreamChannel, upstreamUser}
			if reason != "" {
				params = append(params, reason)
			}
			uc.SendMessage(&irc.Message{
				Command: "KICK",
				Params:  params,
			})
		}
	case "MODE":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		var modeStr string
		if len(msg.Params) > 1 {
			modeStr = msg.Params[1]
		}

		if name == dc.nick {
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
					Params:  []string{dc.nick, ""}, // TODO
				})
			}
			return nil
		}

		uc, upstreamName, err := dc.unmarshalEntity(name)
		if err != nil {
			return err
		}

		if !uc.isChannel(upstreamName) {
			return ircError{&irc.Message{
				Command: irc.ERR_USERSDONTMATCH,
				Params:  []string{dc.nick, "Cannot change mode for other users"},
			}}
		}

		if modeStr != "" {
			params := []string{upstreamName, modeStr}
			params = append(params, msg.Params[2:]...)
			uc.SendMessage(&irc.Message{
				Command: "MODE",
				Params:  params,
			})
		} else {
			ch, ok := uc.channels[upstreamName]
			if !ok {
				return ircError{&irc.Message{
					Command: irc.ERR_NOSUCHCHANNEL,
					Params:  []string{dc.nick, name, "No such channel"},
				}}
			}

			if ch.modes == nil {
				// we haven't received the initial RPL_CHANNELMODEIS yet
				// ignore the request, we will broadcast the modes later when we receive RPL_CHANNELMODEIS
				return nil
			}

			modeStr, modeParams := ch.modes.Format()
			params := []string{dc.nick, name, modeStr}
			params = append(params, modeParams...)

			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_CHANNELMODEIS,
				Params:  params,
			})
			if ch.creationTime != "" {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: rpl_creationtime,
					Params:  []string{dc.nick, name, ch.creationTime},
				})
			}
		}
	case "TOPIC":
		var channel string
		if err := parseMessageParams(msg, &channel); err != nil {
			return err
		}

		uc, upstreamChannel, err := dc.unmarshalEntity(channel)
		if err != nil {
			return err
		}

		if len(msg.Params) > 1 { // setting topic
			topic := msg.Params[1]
			uc.SendMessage(&irc.Message{
				Command: "TOPIC",
				Params:  []string{upstreamChannel, topic},
			})
		} else { // getting topic
			ch, ok := uc.channels[upstreamChannel]
			if !ok {
				return ircError{&irc.Message{
					Command: irc.ERR_NOSUCHCHANNEL,
					Params:  []string{dc.nick, upstreamChannel, "No such channel"},
				}}
			}
			sendTopic(dc, ch)
		}
	case "LIST":
		// TODO: support ELIST when supported by all upstreams

		pl := pendingLIST{
			downstreamID:    dc.id,
			pendingCommands: make(map[int64]*irc.Message),
		}
		var upstreamChannels map[int64][]string
		if len(msg.Params) > 0 {
			upstreamChannels = make(map[int64][]string)
			channels := strings.Split(msg.Params[0], ",")
			for _, channel := range channels {
				uc, upstreamChannel, err := dc.unmarshalEntity(channel)
				if err != nil {
					return err
				}
				upstreamChannels[uc.network.ID] = append(upstreamChannels[uc.network.ID], upstreamChannel)
			}
		}

		dc.user.pendingLISTs = append(dc.user.pendingLISTs, pl)
		dc.forEachUpstream(func(uc *upstreamConn) {
			var params []string
			if upstreamChannels != nil {
				if channels, ok := upstreamChannels[uc.network.ID]; ok {
					params = []string{strings.Join(channels, ",")}
				} else {
					return
				}
			}
			pl.pendingCommands[uc.network.ID] = &irc.Message{
				Command: "LIST",
				Params:  params,
			}
			uc.trySendLIST(dc.id)
		})
	case "NAMES":
		if len(msg.Params) == 0 {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFNAMES,
				Params:  []string{dc.nick, "*", "End of /NAMES list"},
			})
			return nil
		}

		channels := strings.Split(msg.Params[0], ",")
		for _, channel := range channels {
			uc, upstreamChannel, err := dc.unmarshalEntity(channel)
			if err != nil {
				return err
			}

			ch, ok := uc.channels[upstreamChannel]
			if ok {
				sendNames(dc, ch)
			} else {
				// NAMES on a channel we have not joined, ask upstream
				uc.SendMessageLabeled(dc.id, &irc.Message{
					Command: "NAMES",
					Params:  []string{upstreamChannel},
				})
			}
		}
	case "WHO":
		if len(msg.Params) == 0 {
			// TODO: support WHO without parameters
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{dc.nick, "*", "End of /WHO list"},
			})
			return nil
		}

		// TODO: support WHO masks
		entity := msg.Params[0]

		if entity == dc.nick {
			// TODO: support AWAY (H/G) in self WHO reply
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOREPLY,
				Params:  []string{dc.nick, "*", dc.user.Username, dc.hostname, dc.srv.Hostname, dc.nick, "H", "0 " + dc.realname},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{dc.nick, dc.nick, "End of /WHO list"},
			})
			return nil
		}

		uc, upstreamName, err := dc.unmarshalEntity(entity)
		if err != nil {
			return err
		}

		var params []string
		if len(msg.Params) == 2 {
			params = []string{upstreamName, msg.Params[1]}
		} else {
			params = []string{upstreamName}
		}

		uc.SendMessageLabeled(dc.id, &irc.Message{
			Command: "WHO",
			Params:  params,
		})
	case "WHOIS":
		if len(msg.Params) == 0 {
			return ircError{&irc.Message{
				Command: irc.ERR_NONICKNAMEGIVEN,
				Params:  []string{dc.nick, "No nickname given"},
			}}
		}

		var target, mask string
		if len(msg.Params) == 1 {
			target = ""
			mask = msg.Params[0]
		} else {
			target = msg.Params[0]
			mask = msg.Params[1]
		}
		// TODO: support multiple WHOIS users
		if i := strings.IndexByte(mask, ','); i >= 0 {
			mask = mask[:i]
		}

		if mask == dc.nick {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISUSER,
				Params:  []string{dc.nick, dc.nick, dc.user.Username, dc.hostname, "*", dc.realname},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISSERVER,
				Params:  []string{dc.nick, dc.nick, dc.srv.Hostname, "soju"},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHOIS,
				Params:  []string{dc.nick, dc.nick, "End of /WHOIS list"},
			})
			return nil
		}

		// TODO: support WHOIS masks
		uc, upstreamNick, err := dc.unmarshalEntity(mask)
		if err != nil {
			return err
		}

		var params []string
		if target != "" {
			params = []string{target, upstreamNick}
		} else {
			params = []string{upstreamNick}
		}

		uc.SendMessageLabeled(dc.id, &irc.Message{
			Command: "WHOIS",
			Params:  params,
		})
	case "PRIVMSG":
		var targetsStr, text string
		if err := parseMessageParams(msg, &targetsStr, &text); err != nil {
			return err
		}

		for _, name := range strings.Split(targetsStr, ",") {
			if name == serviceNick {
				handleServicePRIVMSG(dc, text)
				continue
			}

			uc, upstreamName, err := dc.unmarshalEntity(name)
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

			echoMsg := &irc.Message{
				Prefix: &irc.Prefix{
					Name: uc.nick,
					User: uc.username,
				},
				Command: "PRIVMSG",
				Params:  []string{upstreamName, text},
			}

			uc.produce(upstreamName, echoMsg, dc)
		}
	case "NOTICE":
		var targetsStr, text string
		if err := parseMessageParams(msg, &targetsStr, &text); err != nil {
			return err
		}

		for _, name := range strings.Split(targetsStr, ",") {
			uc, upstreamName, err := dc.unmarshalEntity(name)
			if err != nil {
				return err
			}

			uc.SendMessage(&irc.Message{
				Command: "NOTICE",
				Params:  []string{upstreamName, text},
			})
		}
	case "INVITE":
		var user, channel string
		if err := parseMessageParams(msg, &user, &channel); err != nil {
			return err
		}

		ucChannel, upstreamChannel, err := dc.unmarshalEntity(channel)
		if err != nil {
			return err
		}

		ucUser, upstreamUser, err := dc.unmarshalEntity(user)
		if err != nil {
			return err
		}

		if ucChannel != ucUser {
			return ircError{&irc.Message{
				Command: irc.ERR_USERNOTINCHANNEL,
				Params:  []string{dc.nick, user, channel, "They aren't on that channel"},
			}}
		}
		uc := ucChannel

		uc.SendMessageLabeled(dc.id, &irc.Message{
			Command: "INVITE",
			Params:  []string{upstreamUser, upstreamChannel},
		})
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
			password = params[0]
		} else {
			username = params[0]
			password = params[1]
		}
	case "SET":
		if len(params) == 2 && strings.EqualFold(params[0], "PASSWORD") {
			username = nick
			password = params[1]
		}
	}
	return username, password, true
}
