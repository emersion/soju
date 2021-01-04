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

func newChatHistoryError(subcommand string, target string) ircError {
	return ircError{&irc.Message{
		Command: "FAIL",
		Params:  []string{"CHATHISTORY", "MESSAGE_ERROR", subcommand, target, "Messages could not be retrieved"},
	}}
}

var errAuthFailed = ircError{&irc.Message{
	Command: irc.ERR_PASSWDMISMATCH,
	Params:  []string{"*", "Invalid username or password"},
}}

// ' ' and ':' break the IRC message wire format, '@' and '!' break prefixes,
// '*' and '?' break masks
const illegalNickChars = " :@!*?"

// permanentDownstreamCaps is the list of always-supported downstream
// capabilities.
var permanentDownstreamCaps = map[string]string{
	"batch":        "",
	"cap-notify":   "",
	"echo-message": "",
	"message-tags": "",
	"sasl":         "PLAIN",
	"server-time":  "",
}

// needAllDownstreamCaps is the list of downstream capabilities that
// require support from all upstreams to be enabled
var needAllDownstreamCaps = map[string]string{
	"away-notify":   "",
	"extended-join": "",
	"multi-prefix":  "",
}

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
	supportedCaps   map[string]string
	caps            map[string]bool

	saslServer sasl.Server
}

func newDownstreamConn(srv *Server, ic ircConn, id uint64) *downstreamConn {
	remoteAddr := ic.RemoteAddr().String()
	logger := &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", remoteAddr)}
	options := connOptions{Logger: logger}
	dc := &downstreamConn{
		conn:          *newConn(srv, ic, &options),
		id:            id,
		supportedCaps: make(map[string]string),
		caps:          make(map[string]bool),
	}
	dc.hostname = remoteAddr
	if host, _, err := net.SplitHostPort(dc.hostname); err == nil {
		dc.hostname = host
	}
	for k, v := range permanentDownstreamCaps {
		dc.supportedCaps[k] = v
	}
	if srv.LogPath != "" {
		dc.supportedCaps["draft/chathistory"] = ""
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
	return dc.network.conn
}

func isOurNick(net *network, nick string) bool {
	// TODO: this doesn't account for nick changes
	if net.conn != nil {
		return nick == net.conn.nick
	}
	// We're not currently connected to the upstream connection, so we don't
	// know whether this name is our nickname. Best-effort: use the network's
	// configured nickname and hope it was the one being used when we were
	// connected.
	return nick == net.Nick
}

// marshalEntity converts an upstream entity name (ie. channel or nick) into a
// downstream entity name.
//
// This involves adding a "/<network>" suffix if the entity isn't the current
// user.
func (dc *downstreamConn) marshalEntity(net *network, name string) string {
	if isOurNick(net, name) {
		return dc.nick
	}
	if dc.network != nil {
		if dc.network != net {
			panic("soju: tried to marshal an entity for another network")
		}
		return name
	}
	return name + "/" + net.GetName()
}

func (dc *downstreamConn) marshalUserPrefix(net *network, prefix *irc.Prefix) *irc.Prefix {
	if isOurNick(net, prefix.Name) {
		return dc.prefix()
	}
	if dc.network != nil {
		if dc.network != net {
			panic("soju: tried to marshal a user prefix for another network")
		}
		return prefix
	}
	return &irc.Prefix{
		Name: prefix.Name + "/" + net.GetName(),
		User: prefix.User,
		Host: prefix.Host,
	}
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

func (dc *downstreamConn) unmarshalText(uc *upstreamConn, text string) string {
	if dc.upstream() != nil {
		return text
	}
	// TODO: smarter parsing that ignores URLs
	return strings.ReplaceAll(text, "/"+uc.network.GetName(), "")
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
		if msg.Command == "TAGMSG" {
			return
		}
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
	if msg.Command == "JOIN" && !dc.caps["extended-join"] {
		msg.Params = msg.Params[:1]
	}

	dc.conn.SendMessage(msg)
}

// sendMessageWithID sends an outgoing message with the specified internal ID.
func (dc *downstreamConn) sendMessageWithID(msg *irc.Message, id string) {
	dc.SendMessage(msg)

	if id == "" || !dc.messageSupportsHistory(msg) {
		return
	}

	dc.sendPing(id)
}

// advanceMessageWithID advances history to the specified message ID without
// sending a message. This is useful e.g. for self-messages when echo-message
// isn't enabled.
func (dc *downstreamConn) advanceMessageWithID(msg *irc.Message, id string) {
	if id == "" || !dc.messageSupportsHistory(msg) {
		return
	}

	dc.sendPing(id)
}

// ackMsgID acknowledges that a message has been received.
func (dc *downstreamConn) ackMsgID(id string) {
	netID, entity, _, err := parseMsgID(id)
	if err != nil {
		dc.logger.Printf("failed to ACK message ID %q: %v", id, err)
		return
	}

	network := dc.user.getNetworkByID(netID)
	if network == nil {
		return
	}

	history, ok := network.history[entity]
	if !ok {
		return
	}

	history.clients[dc.clientName] = id
}

func (dc *downstreamConn) sendPing(msgID string) {
	token := "soju-msgid-" + base64.RawURLEncoding.EncodeToString([]byte(msgID))
	dc.SendMessage(&irc.Message{
		Command: "PING",
		Params:  []string{token},
	})
}

func (dc *downstreamConn) handlePong(token string) {
	if !strings.HasPrefix(token, "soju-msgid-") {
		dc.logger.Printf("received unrecognized PONG token %q", token)
		return
	}
	token = strings.TrimPrefix(token, "soju-msgid-")
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		dc.logger.Printf("received malformed PONG token: %v", err)
		return
	}
	msgID := string(b)

	dc.ackMsgID(msgID)
}

// marshalMessage re-formats a message coming from an upstream connection so
// that it's suitable for being sent on this downstream connection. Only
// messages that may appear in logs are supported, except MODE.
func (dc *downstreamConn) marshalMessage(msg *irc.Message, net *network) *irc.Message {
	msg = msg.Copy()
	msg.Prefix = dc.marshalUserPrefix(net, msg.Prefix)

	switch msg.Command {
	case "PRIVMSG", "NOTICE", "TAGMSG":
		msg.Params[0] = dc.marshalEntity(net, msg.Params[0])
	case "NICK":
		// Nick change for another user
		msg.Params[0] = dc.marshalEntity(net, msg.Params[0])
	case "JOIN", "PART":
		msg.Params[0] = dc.marshalEntity(net, msg.Params[0])
	case "KICK":
		msg.Params[0] = dc.marshalEntity(net, msg.Params[0])
		msg.Params[1] = dc.marshalEntity(net, msg.Params[1])
	case "TOPIC":
		msg.Params[0] = dc.marshalEntity(net, msg.Params[0])
	case "QUIT":
		// This space is intentionally left blank
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
		if strings.ContainsAny(nick, illegalNickChars) {
			return ircError{&irc.Message{
				Command: irc.ERR_ERRONEUSNICKNAME,
				Params:  []string{dc.nick, nick, "contains illegal characters"},
			}}
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
				Params:  []string{dc.nick, dc.prefix().String(), dc.user.Username, "You are now logged in"},
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
		if !dc.registered && dc.capVersion >= 302 {
			// Let downstream show everything it supports, and trim
			// down the available capabilities when upstreams are
			// known.
			for k, v := range needAllDownstreamCaps {
				dc.supportedCaps[k] = v
			}
		}

		caps := make([]string, 0, len(dc.supportedCaps))
		for k, v := range dc.supportedCaps {
			if dc.capVersion >= 302 && v != "" {
				caps = append(caps, k+"="+v)
			} else {
				caps = append(caps, k)
			}
		}

		// TODO: multi-line replies
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "CAP",
			Params:  []string{replyTo, "LS", strings.Join(caps, " ")},
		})

		if dc.capVersion >= 302 {
			// CAP version 302 implicitly enables cap-notify
			dc.caps["cap-notify"] = true
		}

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

		// TODO: atomically ack/nak the whole capability set
		caps := strings.Fields(args[0])
		ack := true
		for _, name := range caps {
			name = strings.ToLower(name)
			enable := !strings.HasPrefix(name, "-")
			if !enable {
				name = strings.TrimPrefix(name, "-")
			}

			if enable == dc.caps[name] {
				continue
			}

			_, ok := dc.supportedCaps[name]
			if !ok {
				ack = false
				break
			}

			if name == "cap-notify" && dc.capVersion >= 302 && !enable {
				// cap-notify cannot be disabled with CAP version 302
				ack = false
				break
			}

			dc.caps[name] = enable
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

func (dc *downstreamConn) setSupportedCap(name, value string) {
	prevValue, hasPrev := dc.supportedCaps[name]
	changed := !hasPrev || prevValue != value
	dc.supportedCaps[name] = value

	if !dc.caps["cap-notify"] || !changed {
		return
	}

	replyTo := dc.nick
	if !dc.registered {
		replyTo = "*"
	}

	cap := name
	if value != "" && dc.capVersion >= 302 {
		cap = name + "=" + value
	}

	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: "CAP",
		Params:  []string{replyTo, "NEW", cap},
	})
}

func (dc *downstreamConn) unsetSupportedCap(name string) {
	_, hasPrev := dc.supportedCaps[name]
	delete(dc.supportedCaps, name)
	delete(dc.caps, name)

	if !dc.caps["cap-notify"] || !hasPrev {
		return
	}

	replyTo := dc.nick
	if !dc.registered {
		replyTo = "*"
	}

	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: "CAP",
		Params:  []string{replyTo, "DEL", name},
	})
}

func (dc *downstreamConn) updateSupportedCaps() {
	supportedCaps := make(map[string]bool)
	for cap := range needAllDownstreamCaps {
		supportedCaps[cap] = true
	}
	dc.forEachUpstream(func(uc *upstreamConn) {
		for cap, supported := range supportedCaps {
			supportedCaps[cap] = supported && uc.caps[cap]
		}
	})

	for cap, supported := range supportedCaps {
		if supported {
			dc.setSupportedCap(cap, needAllDownstreamCaps[cap])
		} else {
			dc.unsetSupportedCap(cap)
		}
	}
}

func (dc *downstreamConn) updateNick() {
	if uc := dc.upstream(); uc != nil && uc.nick != dc.nick {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.prefix(),
			Command: "NICK",
			Params:  []string{uc.nick},
		})
		dc.nick = uc.nick
	}
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
		dc.logger.Printf("failed authentication for %q: user not found: %v", username, err)
		return errAuthFailed
	}

	// Password auth disabled
	if u.Password == "" {
		return errAuthFailed
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		dc.logger.Printf("failed authentication for %q: wrong password: %v", username, err)
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

		// Some clients only allow specifying the nickname (and use the
		// nickname as a username too). Strip the network name from the
		// nickname when auto-saving networks.
		nick, _, _ := unmarshalUsername(dc.nick)

		dc.logger.Printf("auto-saving network %q", dc.networkName)
		var err error
		network, err = dc.user.createNetwork(&Network{
			Addr: dc.networkName,
			Nick: nick,
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
	// TODO: send CHATHISTORY in RPL_ISUPPORT when implemented
	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.ERR_NOMOTD,
		Params:  []string{dc.nick, "No MOTD"},
	})

	dc.updateNick()
	dc.updateSupportedCaps()

	dc.forEachUpstream(func(uc *upstreamConn) {
		for _, ch := range uc.channels {
			if !ch.complete {
				continue
			}
			if record, ok := uc.network.channels[ch.Name]; ok && record.Detached {
				continue
			}

			dc.SendMessage(&irc.Message{
				Prefix:  dc.prefix(),
				Command: "JOIN",
				Params:  []string{dc.marshalEntity(ch.conn.network, ch.Name)},
			})

			forwardChannel(dc, ch)
		}
	})

	dc.forEachNetwork(func(net *network) {
		// Only send history if we're the first connected client with that name
		// for the network
		if _, ok := net.offlineClients[dc.clientName]; ok {
			dc.sendNetworkHistory(net)
			delete(net.offlineClients, dc.clientName)
		}

		// Fast-forward history to last message
		for target, history := range net.history {
			if ch, ok := net.channels[target]; ok && ch.Detached {
				continue
			}

			lastID, err := dc.user.msgStore.LastMsgID(net, target, time.Now())
			if err != nil {
				dc.logger.Printf("failed to get last message ID: %v", err)
				continue
			}
			history.clients[dc.clientName] = lastID
		}
	})

	return nil
}

// messageSupportsHistory checks whether the provided message can be sent as
// part of an history batch.
func (dc *downstreamConn) messageSupportsHistory(msg *irc.Message) bool {
	// Don't replay all messages, because that would mess up client
	// state. For instance we just sent the list of users, sending
	// PART messages for one of these users would be incorrect.
	// TODO: add support for draft/event-playback
	switch msg.Command {
	case "PRIVMSG", "NOTICE":
		return true
	}
	return false
}

func (dc *downstreamConn) sendNetworkHistory(net *network) {
	if dc.caps["draft/chathistory"] || dc.user.msgStore == nil {
		return
	}
	for target, history := range net.history {
		if ch, ok := net.channels[target]; ok && ch.Detached {
			continue
		}

		lastDelivered, ok := history.clients[dc.clientName]
		if !ok {
			continue
		}

		limit := 4000
		history, err := dc.user.msgStore.LoadLatestID(net, target, lastDelivered, limit)
		if err != nil {
			dc.logger.Printf("failed to send implicit history for %q: %v", target, err)
			continue
		}

		batchRef := "history"
		if dc.caps["batch"] {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BATCH",
				Params:  []string{"+" + batchRef, "chathistory", dc.marshalEntity(net, target)},
			})
		}

		for _, msg := range history {
			if !dc.messageSupportsHistory(msg) {
				continue
			}

			if dc.caps["batch"] {
				msg.Tags["batch"] = irc.TagValue(batchRef)
			}
			dc.SendMessage(dc.marshalMessage(msg, net))
		}

		if dc.caps["batch"] {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BATCH",
				Params:  []string{"-" + batchRef},
			})
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
		var source, destination string
		if err := parseMessageParams(msg, &source); err != nil {
			return err
		}
		if len(msg.Params) > 1 {
			destination = msg.Params[1]
		}
		if destination != "" && destination != dc.srv.Hostname {
			return ircError{&irc.Message{
				Command: irc.ERR_NOSUCHSERVER,
				Params:  []string{dc.nick, destination, "No such server"},
			}}
		}
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "PONG",
			Params:  []string{dc.srv.Hostname, source},
		})
		return nil
	case "PONG":
		if len(msg.Params) == 0 {
			return newNeedMoreParamsError(msg.Command)
		}
		token := msg.Params[len(msg.Params)-1]
		dc.handlePong(token)
	case "USER":
		return ircError{&irc.Message{
			Command: irc.ERR_ALREADYREGISTERED,
			Params:  []string{dc.nick, "You may not reregister"},
		}}
	case "NICK":
		var rawNick string
		if err := parseMessageParams(msg, &rawNick); err != nil {
			return err
		}

		nick := rawNick
		var upstream *upstreamConn
		if dc.upstream() == nil {
			uc, unmarshaledNick, err := dc.unmarshalEntity(nick)
			if err == nil { // NICK nick/network: NICK only on a specific upstream
				upstream = uc
				nick = unmarshaledNick
			}
		}

		if strings.ContainsAny(nick, illegalNickChars) {
			return ircError{&irc.Message{
				Command: irc.ERR_ERRONEUSNICKNAME,
				Params:  []string{dc.nick, rawNick, "contains illegal characters"},
			}}
		}
		if nick == serviceNick {
			return ircError{&irc.Message{
				Command: irc.ERR_NICKNAMEINUSE,
				Params:  []string{dc.nick, rawNick, "Nickname reserved for bouncer service"},
			}}
		}

		var err error
		dc.forEachNetwork(func(n *network) {
			if err != nil || (upstream != nil && upstream.network != n) {
				return
			}
			n.Nick = nick
			err = dc.srv.db.StoreNetwork(dc.user.ID, &n.Network)
		})
		if err != nil {
			return err
		}

		dc.forEachUpstream(func(uc *upstreamConn) {
			if upstream != nil && upstream != uc {
				return
			}
			uc.SendMessageLabeled(dc.id, &irc.Message{
				Command: "NICK",
				Params:  []string{nick},
			})
		})

		if dc.upstream() == nil && dc.nick != nick {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.prefix(),
				Command: "NICK",
				Params:  []string{nick},
			})
			dc.nick = nick
		}
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
			uc.SendMessageLabeled(dc.id, &irc.Message{
				Command: "JOIN",
				Params:  params,
			})

			var ch *Channel
			var ok bool
			if ch, ok = uc.network.channels[upstreamName]; ok {
				// Don't clear the channel key if there's one set
				// TODO: add a way to unset the channel key
				if key != "" {
					ch.Key = key
				}
				uc.network.attach(ch)
			} else {
				ch = &Channel{
					Name: upstreamName,
					Key:  key,
				}
				uc.network.channels[upstreamName] = ch
			}
			if err := dc.srv.db.StoreChannel(uc.network.ID, ch); err != nil {
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

			if strings.EqualFold(reason, "detach") {
				var ch *Channel
				var ok bool
				if ch, ok = uc.network.channels[upstreamName]; ok {
					uc.network.detach(ch)
				} else {
					ch = &Channel{
						Name:     name,
						Detached: true,
					}
					uc.network.channels[upstreamName] = ch
				}
				if err := dc.srv.db.StoreChannel(uc.network.ID, ch); err != nil {
					dc.logger.Printf("failed to create or update channel %q: %v", upstreamName, err)
				}
			} else {
				params := []string{upstreamName}
				if reason != "" {
					params = append(params, reason)
				}
				uc.SendMessageLabeled(dc.id, &irc.Message{
					Command: "PART",
					Params:  params,
				})

				if err := uc.network.deleteChannel(upstreamName); err != nil {
					dc.logger.Printf("failed to delete channel %q: %v", upstreamName, err)
				}
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
					Params:  []string{dc.nick, user, channel, "They are on another network"},
				}}
			}
			uc := ucChannel

			params := []string{upstreamChannel, upstreamUser}
			if reason != "" {
				params = append(params, reason)
			}
			uc.SendMessageLabeled(dc.id, &irc.Message{
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
					uc.SendMessageLabeled(dc.id, &irc.Message{
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
			uc.SendMessageLabeled(dc.id, &irc.Message{
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
			uc.SendMessageLabeled(dc.id, &irc.Message{
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
		var upstream *upstreamConn
		var upstreamChannels map[int64][]string
		if len(msg.Params) > 0 {
			uc, upstreamMask, err := dc.unmarshalEntity(msg.Params[0])
			if err == nil && upstreamMask == "*" { // LIST */network: send LIST only to one network
				upstream = uc
			} else {
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
		}

		dc.user.pendingLISTs = append(dc.user.pendingLISTs, pl)
		dc.forEachUpstream(func(uc *upstreamConn) {
			if upstream != nil && upstream != uc {
				return
			}
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
		if entity == serviceNick {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOREPLY,
				Params:  []string{serviceNick, "*", servicePrefix.User, servicePrefix.Host, dc.srv.Hostname, serviceNick, "H", "0 " + serviceRealname},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{dc.nick, serviceNick, "End of /WHO list"},
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
			if target == mask { // WHOIS nick nick
				params = []string{upstreamNick, upstreamNick}
			} else {
				params = []string{target, upstreamNick}
			}
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
		tags := copyClientTags(msg.Tags)

		for _, name := range strings.Split(targetsStr, ",") {
			if name == serviceNick {
				if dc.caps["echo-message"] {
					echoTags := tags.Copy()
					echoTags["time"] = irc.TagValue(time.Now().UTC().Format(serverTimeLayout))
					dc.SendMessage(&irc.Message{
						Tags:    echoTags,
						Prefix:  dc.prefix(),
						Command: "PRIVMSG",
						Params:  []string{name, text},
					})
				}
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

			unmarshaledText := text
			if uc.isChannel(upstreamName) {
				unmarshaledText = dc.unmarshalText(uc, text)
			}
			uc.SendMessageLabeled(dc.id, &irc.Message{
				Tags:    tags,
				Command: "PRIVMSG",
				Params:  []string{upstreamName, unmarshaledText},
			})

			echoTags := tags.Copy()
			echoTags["time"] = irc.TagValue(time.Now().UTC().Format(serverTimeLayout))
			echoMsg := &irc.Message{
				Tags: echoTags,
				Prefix: &irc.Prefix{
					Name: uc.nick,
					User: uc.username,
				},
				Command: "PRIVMSG",
				Params:  []string{upstreamName, text},
			}
			uc.produce(upstreamName, echoMsg, dc)

			uc.updateChannelAutoDetach(upstreamName)
		}
	case "NOTICE":
		var targetsStr, text string
		if err := parseMessageParams(msg, &targetsStr, &text); err != nil {
			return err
		}
		tags := copyClientTags(msg.Tags)

		for _, name := range strings.Split(targetsStr, ",") {
			uc, upstreamName, err := dc.unmarshalEntity(name)
			if err != nil {
				return err
			}

			unmarshaledText := text
			if uc.isChannel(upstreamName) {
				unmarshaledText = dc.unmarshalText(uc, text)
			}
			uc.SendMessageLabeled(dc.id, &irc.Message{
				Tags:    tags,
				Command: "NOTICE",
				Params:  []string{upstreamName, unmarshaledText},
			})

			uc.updateChannelAutoDetach(upstreamName)
		}
	case "TAGMSG":
		var targetsStr string
		if err := parseMessageParams(msg, &targetsStr); err != nil {
			return err
		}
		tags := copyClientTags(msg.Tags)

		for _, name := range strings.Split(targetsStr, ",") {
			uc, upstreamName, err := dc.unmarshalEntity(name)
			if err != nil {
				return err
			}
			if _, ok := uc.caps["message-tags"]; !ok {
				continue
			}

			uc.SendMessageLabeled(dc.id, &irc.Message{
				Tags:    tags,
				Command: "TAGMSG",
				Params:  []string{upstreamName},
			})

			uc.updateChannelAutoDetach(upstreamName)
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
				Params:  []string{dc.nick, user, channel, "They are on another network"},
			}}
		}
		uc := ucChannel

		uc.SendMessageLabeled(dc.id, &irc.Message{
			Command: "INVITE",
			Params:  []string{upstreamUser, upstreamChannel},
		})
	case "CHATHISTORY":
		var subcommand string
		if err := parseMessageParams(msg, &subcommand); err != nil {
			return err
		}
		var target, criteria, limitStr string
		if err := parseMessageParams(msg, nil, &target, &criteria, &limitStr); err != nil {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "NEED_MORE_PARAMS", subcommand, "Missing parameters"},
			}}
		}

		if dc.user.msgStore == nil {
			return ircError{&irc.Message{
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params:  []string{dc.nick, subcommand, "Unknown command"},
			}}
		}

		uc, entity, err := dc.unmarshalEntity(target)
		if err != nil {
			return err
		}

		// TODO: support msgid criteria
		criteriaParts := strings.SplitN(criteria, "=", 2)
		if len(criteriaParts) != 2 || criteriaParts[0] != "timestamp" {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "UNKNOWN_CRITERIA", criteria, "Unknown criteria"},
			}}
		}

		timestamp, err := time.Parse(serverTimeLayout, criteriaParts[1])
		if err != nil {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "INVALID_CRITERIA", criteria, "Invalid criteria"},
			}}
		}

		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 || limit > dc.srv.HistoryLimit {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "INVALID_LIMIT", limitStr, "Invalid limit"},
			}}
		}

		var history []*irc.Message
		switch subcommand {
		case "BEFORE":
			history, err = dc.user.msgStore.LoadBeforeTime(uc.network, entity, timestamp, limit)
		case "AFTER":
			history, err = dc.user.msgStore.LoadAfterTime(uc.network, entity, timestamp, limit)
		default:
			// TODO: support LATEST, BETWEEN
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "UNKNOWN_COMMAND", subcommand, "Unknown command"},
			}}
		}
		if err != nil {
			dc.logger.Printf("failed parsing log messages for chathistory: %v", err)
			return newChatHistoryError(subcommand, target)
		}

		batchRef := "history"
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "BATCH",
			Params:  []string{"+" + batchRef, "chathistory", target},
		})

		for _, msg := range history {
			msg.Tags["batch"] = irc.TagValue(batchRef)
			dc.SendMessage(dc.marshalMessage(msg, uc.network))
		}

		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "BATCH",
			Params:  []string{"-" + batchRef},
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

	// User may have e.g. EXTERNAL mechanism configured. We do not want to
	// automatically erase the key pair or any other credentials.
	if uc.network.SASL.Mechanism != "" && uc.network.SASL.Mechanism != "PLAIN" {
		return
	}

	dc.logger.Printf("auto-saving NickServ credentials with username %q", username)
	n := uc.network
	n.SASL.Mechanism = "PLAIN"
	n.SASL.Plain.Username = username
	n.SASL.Plain.Password = password
	if err := dc.srv.db.StoreNetwork(dc.user.ID, &n.Network); err != nil {
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
	default:
		return "", "", false
	}
	return username, password, true
}
