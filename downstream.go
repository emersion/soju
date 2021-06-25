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

func parseBouncerNetID(subcommand, s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, ircError{&irc.Message{
			Command: "FAIL",
			Params:  []string{"BOUNCER", "INVALID_NETID", subcommand, s, "Invalid network ID"},
		}}
	}
	return id, nil
}

func getNetworkAttrs(network *network) irc.Tags {
	state := "disconnected"
	if uc := network.conn; uc != nil {
		state = "connected"
	}

	attrs := irc.Tags{
		"name":     irc.TagValue(network.GetName()),
		"state":    irc.TagValue(state),
		"nickname": irc.TagValue(network.Nick),
	}

	if network.Username != "" {
		attrs["username"] = irc.TagValue(network.Username)
	}
	if realname := GetRealname(&network.user.User, &network.Network); realname != "" {
		attrs["realname"] = irc.TagValue(realname)
	}

	if u, err := network.URL(); err == nil {
		hasHostPort := true
		switch u.Scheme {
		case "ircs":
			attrs["tls"] = irc.TagValue("1")
		case "irc+insecure":
			attrs["tls"] = irc.TagValue("0")
		default:
			hasHostPort = false
		}
		if host, port, err := net.SplitHostPort(u.Host); err == nil && hasHostPort {
			attrs["host"] = irc.TagValue(host)
			attrs["port"] = irc.TagValue(port)
		} else if hasHostPort {
			attrs["host"] = irc.TagValue(u.Host)
		}
	}

	return attrs
}

// ' ' and ':' break the IRC message wire format, '@' and '!' break prefixes,
// '*' and '?' break masks, '$' breaks server masks in PRIVMSG/NOTICE
const illegalNickChars = " :@!*?$"

// permanentDownstreamCaps is the list of always-supported downstream
// capabilities.
var permanentDownstreamCaps = map[string]string{
	"batch":         "",
	"cap-notify":    "",
	"echo-message":  "",
	"invite-notify": "",
	"message-tags":  "",
	"sasl":          "PLAIN",
	"server-time":   "",
	"setname":       "",

	"soju.im/bouncer-networks":        "",
	"soju.im/bouncer-networks-notify": "",
}

// needAllDownstreamCaps is the list of downstream capabilities that
// require support from all upstreams to be enabled
var needAllDownstreamCaps = map[string]string{
	"account-tag":   "",
	"away-notify":   "",
	"extended-join": "",
	"multi-prefix":  "",
}

// passthroughIsupport is the set of ISUPPORT tokens that are directly passed
// through from the upstream server to downstream clients.
//
// This is only effective in single-upstream mode.
var passthroughIsupport = map[string]bool{
	"AWAYLEN":    true,
	"BOT":        true,
	"CHANLIMIT":  true,
	"CHANMODES":  true,
	"CHANNELLEN": true,
	"CHANTYPES":  true,
	"EXCEPTS":    true,
	"EXTBAN":     true,
	"HOSTLEN":    true,
	"INVEX":      true,
	"KICKLEN":    true,
	"MAXLIST":    true,
	"MAXTARGETS": true,
	"MODES":      true,
	"NAMELEN":    true,
	"NETWORK":    true,
	"NICKLEN":    true,
	"PREFIX":     true,
	"SAFELIST":   true,
	"TARGMAX":    true,
	"TOPICLEN":   true,
	"USERLEN":    true,
	"UTF8ONLY":   true,
}

type downstreamConn struct {
	conn

	id uint64

	registered  bool
	user        *user
	nick        string
	nickCM      string
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

	lastBatchRef uint64

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
	} else if !dc.caps["soju.im/bouncer-networks"] {
		dc.user.forEachNetwork(f)
	}
}

func (dc *downstreamConn) forEachUpstream(f func(*upstreamConn)) {
	if dc.network == nil && dc.caps["soju.im/bouncer-networks"] {
		return
	}
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
		return net.casemap(nick) == net.conn.nickCM
	}
	// We're not currently connected to the upstream connection, so we don't
	// know whether this name is our nickname. Best-effort: use the network's
	// configured nickname and hope it was the one being used when we were
	// connected.
	return net.casemap(nick) == net.casemap(net.Nick)
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
	name = partialCasemap(net.casemap, name)
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
	prefix.Name = partialCasemap(net.casemap, prefix.Name)
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
	if dc.network != nil {
		return nil, "", ircError{&irc.Message{
			Command: irc.ERR_NOSUCHCHANNEL,
			Params:  []string{name, "Disconnected from upstream network"},
		}}
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
			Params:  []string{name, "Missing network suffix in channel name"},
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
			case "account":
				supported = dc.caps["account"]
			}
			if !supported {
				delete(msg.Tags, name)
			}
		}
	}
	if !dc.caps["batch"] && msg.Tags["batch"] != "" {
		msg = msg.Copy()
		delete(msg.Tags, "batch")
	}
	if msg.Command == "JOIN" && !dc.caps["extended-join"] {
		msg.Params = msg.Params[:1]
	}
	if msg.Command == "SETNAME" && !dc.caps["setname"] {
		return
	}

	dc.conn.SendMessage(msg)
}

func (dc *downstreamConn) SendBatch(typ string, params []string, tags irc.Tags, f func(batchRef irc.TagValue)) {
	dc.lastBatchRef++
	ref := fmt.Sprintf("%v", dc.lastBatchRef)

	if dc.caps["batch"] {
		dc.SendMessage(&irc.Message{
			Tags:    tags,
			Prefix:  dc.srv.prefix(),
			Command: "BATCH",
			Params:  append([]string{"+" + ref, typ}, params...),
		})
	}

	f(irc.TagValue(ref))

	if dc.caps["batch"] {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "BATCH",
			Params:  []string{"-" + ref},
		})
	}
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
	netID, entity, err := parseMsgID(id, nil)
	if err != nil {
		dc.logger.Printf("failed to ACK message ID %q: %v", id, err)
		return
	}

	network := dc.user.getNetworkByID(netID)
	if network == nil {
		return
	}

	network.delivered.StoreID(entity, dc.clientName, id)
}

func (dc *downstreamConn) sendPing(msgID string) {
	token := "soju-msgid-" + msgID
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
	msgID := strings.TrimPrefix(token, "soju-msgid-")
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
	case "QUIT", "SETNAME":
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
		nickCM := casemapASCII(nick)
		if nickCM == serviceNickCM {
			return ircError{&irc.Message{
				Command: irc.ERR_NICKNAMEINUSE,
				Params:  []string{dc.nick, nick, "Nickname reserved for bouncer service"},
			}}
		}
		dc.nick = nick
		dc.nickCM = nickCM
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
	case "BOUNCER":
		var subcommand string
		if err := parseMessageParams(msg, &subcommand); err != nil {
			return err
		}

		switch strings.ToUpper(subcommand) {
		case "BIND":
			var idStr string
			if err := parseMessageParams(msg, nil, &idStr); err != nil {
				return err
			}

			if dc.registered {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "REGISTRATION_IS_COMPLETED", "BIND", "Cannot bind bouncer network after registration"},
				}}
			}
			if dc.user == nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "ACCOUNT_REQUIRED", "BIND", "Authentication needed to bind to bouncer network"},
				}}
			}

			id, err := parseBouncerNetID(subcommand, idStr)
			if err != nil {
				return err
			}

			var match *network
			dc.user.forEachNetwork(func(net *network) {
				if net.ID == id {
					match = net
				}
			})
			if match == nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "INVALID_NETID", idStr, "Unknown network ID"},
				}}
			}

			dc.networkName = match.GetName()
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
		for name, enabled := range dc.caps {
			if enabled {
				caps = append(caps, name)
			}
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
		dc.nickCM = casemapASCII(dc.nick)
	}
}

func (dc *downstreamConn) updateRealname() {
	if uc := dc.upstream(); uc != nil && uc.realname != dc.realname && dc.caps["setname"] {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.prefix(),
			Command: "SETNAME",
			Params:  []string{uc.realname},
		})
		dc.realname = uc.realname
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
			Addr:    dc.networkName,
			Nick:    nick,
			Enabled: true,
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

	isupport := []string{
		fmt.Sprintf("CHATHISTORY=%v", dc.srv.HistoryLimit),
		"CASEMAPPING=ascii",
	}

	if dc.network != nil {
		isupport = append(isupport, fmt.Sprintf("BOUNCER_NETID=%v", dc.network.ID))
	}

	if uc := dc.upstream(); uc != nil {
		for k := range passthroughIsupport {
			v, ok := uc.isupport[k]
			if !ok {
				continue
			}
			if v != nil {
				isupport = append(isupport, fmt.Sprintf("%v=%v", k, *v))
			} else {
				isupport = append(isupport, k)
			}
		}
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
	for _, msg := range generateIsupport(dc.srv.prefix(), dc.nick, isupport) {
		dc.SendMessage(msg)
	}
	motdHint := "No MOTD"
	if uc := dc.upstream(); uc != nil {
		motdHint = "Use /motd to read the message of the day"
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_UMODEIS,
			Params:  []string{dc.nick, string(uc.modes)},
		})
	}
	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.ERR_NOMOTD,
		Params:  []string{dc.nick, motdHint},
	})

	dc.updateNick()
	dc.updateRealname()
	dc.updateSupportedCaps()

	if dc.caps["soju.im/bouncer-networks-notify"] {
		dc.SendBatch("soju.im/bouncer-networks", nil, nil, func(batchRef irc.TagValue) {
			dc.user.forEachNetwork(func(network *network) {
				idStr := fmt.Sprintf("%v", network.ID)
				attrs := getNetworkAttrs(network)
				dc.SendMessage(&irc.Message{
					Tags:    irc.Tags{"batch": batchRef},
					Prefix:  dc.srv.prefix(),
					Command: "BOUNCER",
					Params:  []string{"NETWORK", idStr, attrs.String()},
				})
			})
		})
	}

	dc.forEachUpstream(func(uc *upstreamConn) {
		for _, entry := range uc.channels.innerMap {
			ch := entry.value.(*upstreamChannel)
			if !ch.complete {
				continue
			}
			record := uc.network.channels.Value(ch.Name)
			if record != nil && record.Detached {
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
		if dc.caps["draft/chathistory"] || dc.user.msgStore == nil {
			return
		}

		// Only send history if we're the first connected client with that name
		// for the network
		firstClient := true
		dc.user.forEachDownstream(func(c *downstreamConn) {
			if c != dc && c.clientName == dc.clientName && c.network == dc.network {
				firstClient = false
			}
		})
		if firstClient {
			net.delivered.ForEachTarget(func(target string) {
				lastDelivered := net.delivered.LoadID(target, dc.clientName)
				if lastDelivered == "" {
					return
				}

				dc.sendTargetBacklog(net, target, lastDelivered)

				// Fast-forward history to last message
				targetCM := net.casemap(target)
				lastID, err := dc.user.msgStore.LastMsgID(net, targetCM, time.Now())
				if err != nil {
					dc.logger.Printf("failed to get last message ID: %v", err)
					return
				}
				net.delivered.StoreID(target, dc.clientName, lastID)
			})
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

func (dc *downstreamConn) sendTargetBacklog(net *network, target, msgID string) {
	if dc.caps["draft/chathistory"] || dc.user.msgStore == nil {
		return
	}

	ch := net.channels.Value(target)

	limit := 4000
	targetCM := net.casemap(target)
	history, err := dc.user.msgStore.LoadLatestID(net, targetCM, msgID, limit)
	if err != nil {
		dc.logger.Printf("failed to send backlog for %q: %v", target, err)
		return
	}

	dc.SendBatch("chathistory", []string{dc.marshalEntity(net, target)}, nil, func(batchRef irc.TagValue) {
		for _, msg := range history {
			if !dc.messageSupportsHistory(msg) {
				continue
			}

			if ch != nil && ch.Detached {
				if net.detachedMessageNeedsRelay(ch, msg) {
					dc.relayDetachedMessage(net, msg)
				}
			} else {
				if dc.caps["batch"] {
					msg.Tags["batch"] = irc.TagValue(batchRef)
				}
				dc.SendMessage(dc.marshalMessage(msg, net))
			}
		}
	})
}

func (dc *downstreamConn) relayDetachedMessage(net *network, msg *irc.Message) {
	if msg.Command != "PRIVMSG" && msg.Command != "NOTICE" {
		return
	}

	sender := msg.Prefix.Name
	target, text := msg.Params[0], msg.Params[1]
	if net.isHighlight(msg) {
		sendServiceNOTICE(dc, fmt.Sprintf("highlight in %v: <%v> %v", dc.marshalEntity(net, target), sender, text))
	} else {
		sendServiceNOTICE(dc, fmt.Sprintf("message in %v: <%v> %v", dc.marshalEntity(net, target), sender, text))
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
		if casemapASCII(nick) == serviceNickCM {
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

		if dc.upstream() == nil && upstream == nil && dc.nick != nick {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.prefix(),
				Command: "NICK",
				Params:  []string{nick},
			})
			dc.nick = nick
			dc.nickCM = casemapASCII(dc.nick)
		}
	case "SETNAME":
		var realname string
		if err := parseMessageParams(msg, &realname); err != nil {
			return err
		}

		// If the client just resets to the default, just wipe the per-network
		// preference
		storeRealname := realname
		if realname == dc.user.Realname {
			storeRealname = ""
		}

		var storeErr error
		var needUpdate []Network
		dc.forEachNetwork(func(n *network) {
			// We only need to call updateNetwork for upstreams that don't
			// support setname
			if uc := n.conn; uc != nil && uc.caps["setname"] {
				uc.SendMessageLabeled(dc.id, &irc.Message{
					Command: "SETNAME",
					Params:  []string{realname},
				})

				n.Realname = storeRealname
				if err := dc.srv.db.StoreNetwork(dc.user.ID, &n.Network); err != nil {
					dc.logger.Printf("failed to store network realname: %v", err)
					storeErr = err
				}
				return
			}

			record := n.Network // copy network record because we'll mutate it
			record.Realname = storeRealname
			needUpdate = append(needUpdate, record)
		})

		// Walk the network list as a second step, because updateNetwork
		// mutates the original list
		for _, record := range needUpdate {
			if _, err := dc.user.updateNetwork(&record); err != nil {
				dc.logger.Printf("failed to update network realname: %v", err)
				storeErr = err
			}
		}
		if storeErr != nil {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"SETNAME", "CANNOT_CHANGE_REALNAME", "Failed to update realname"},
			}}
		}

		if dc.upstream() == nil && dc.caps["setname"] {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.prefix(),
				Command: "SETNAME",
				Params:  []string{realname},
			})
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

			if !uc.isChannel(upstreamName) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.ERR_NOSUCHCHANNEL,
					Params:  []string{name, "Not a channel name"},
				})
				continue
			}

			params := []string{upstreamName}
			if key != "" {
				params = append(params, key)
			}
			uc.SendMessageLabeled(dc.id, &irc.Message{
				Command: "JOIN",
				Params:  params,
			})

			ch := uc.network.channels.Value(upstreamName)
			if ch != nil {
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
				uc.network.channels.SetValue(upstreamName, ch)
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
				ch := uc.network.channels.Value(upstreamName)
				if ch != nil {
					uc.network.detach(ch)
				} else {
					ch = &Channel{
						Name:     name,
						Detached: true,
					}
					uc.network.channels.SetValue(upstreamName, ch)
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

		if casemapASCII(name) == dc.nickCM {
			if modeStr != "" {
				if uc := dc.upstream(); uc != nil {
					uc.SendMessageLabeled(dc.id, &irc.Message{
						Command: "MODE",
						Params:  []string{uc.nick, modeStr},
					})
				} else {
					dc.SendMessage(&irc.Message{
						Prefix:  dc.srv.prefix(),
						Command: irc.ERR_UMODEUNKNOWNFLAG,
						Params:  []string{dc.nick, "Cannot change user mode in multi-upstream mode"},
					})
				}
			} else {
				var userMode string
				if uc := dc.upstream(); uc != nil {
					userMode = string(uc.modes)
				}

				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_UMODEIS,
					Params:  []string{dc.nick, userMode},
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
			ch := uc.channels.Value(upstreamName)
			if ch == nil {
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

		uc, upstreamName, err := dc.unmarshalEntity(channel)
		if err != nil {
			return err
		}

		if len(msg.Params) > 1 { // setting topic
			topic := msg.Params[1]
			uc.SendMessageLabeled(dc.id, &irc.Message{
				Command: "TOPIC",
				Params:  []string{upstreamName, topic},
			})
		} else { // getting topic
			ch := uc.channels.Value(upstreamName)
			if ch == nil {
				return ircError{&irc.Message{
					Command: irc.ERR_NOSUCHCHANNEL,
					Params:  []string{dc.nick, upstreamName, "No such channel"},
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
			uc, upstreamName, err := dc.unmarshalEntity(channel)
			if err != nil {
				return err
			}

			ch := uc.channels.Value(upstreamName)
			if ch != nil {
				sendNames(dc, ch)
			} else {
				// NAMES on a channel we have not joined, ask upstream
				uc.SendMessageLabeled(dc.id, &irc.Message{
					Command: "NAMES",
					Params:  []string{upstreamName},
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
		entityCM := casemapASCII(entity)

		if dc.network == nil && entityCM == dc.nickCM {
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
		if entityCM == serviceNickCM {
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

		if dc.network == nil && casemapASCII(mask) == dc.nickCM {
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
	case "PRIVMSG", "NOTICE":
		var targetsStr, text string
		if err := parseMessageParams(msg, &targetsStr, &text); err != nil {
			return err
		}
		tags := copyClientTags(msg.Tags)

		for _, name := range strings.Split(targetsStr, ",") {
			if name == "$"+dc.srv.Hostname || (name == "$*" && dc.network == nil) {
				// "$" means a server mask follows. If it's the bouncer's
				// hostname, broadcast the message to all bouncer users.
				if !dc.user.Admin {
					return ircError{&irc.Message{
						Prefix:  dc.srv.prefix(),
						Command: irc.ERR_BADMASK,
						Params:  []string{dc.nick, name, "Permission denied to broadcast message to all bouncer users"},
					}}
				}

				dc.logger.Printf("broadcasting bouncer-wide %v: %v", msg.Command, text)

				broadcastTags := tags.Copy()
				broadcastTags["time"] = irc.TagValue(time.Now().UTC().Format(serverTimeLayout))
				broadcastMsg := &irc.Message{
					Tags:    broadcastTags,
					Prefix:  servicePrefix,
					Command: msg.Command,
					Params:  []string{name, text},
				}
				dc.srv.forEachUser(func(u *user) {
					u.events <- eventBroadcast{broadcastMsg}
				})
				continue
			}

			if dc.network == nil && casemapASCII(name) == dc.nickCM {
				dc.SendMessage(msg)
				continue
			}

			if msg.Command == "PRIVMSG" && casemapASCII(name) == serviceNickCM {
				if dc.caps["echo-message"] {
					echoTags := tags.Copy()
					echoTags["time"] = irc.TagValue(time.Now().UTC().Format(serverTimeLayout))
					dc.SendMessage(&irc.Message{
						Tags:    echoTags,
						Prefix:  dc.prefix(),
						Command: msg.Command,
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

			if msg.Command == "PRIVMSG" && uc.network.casemap(upstreamName) == "nickserv" {
				dc.handleNickServPRIVMSG(uc, text)
			}

			unmarshaledText := text
			if uc.isChannel(upstreamName) {
				unmarshaledText = dc.unmarshalText(uc, text)
			}
			uc.SendMessageLabeled(dc.id, &irc.Message{
				Tags:    tags,
				Command: msg.Command,
				Params:  []string{upstreamName, unmarshaledText},
			})

			echoTags := tags.Copy()
			echoTags["time"] = irc.TagValue(time.Now().UTC().Format(serverTimeLayout))
			if uc.account != "" {
				echoTags["account"] = irc.TagValue(uc.account)
			}
			echoMsg := &irc.Message{
				Tags: echoTags,
				Prefix: &irc.Prefix{
					Name: uc.nick,
					User: uc.username,
				},
				Command: msg.Command,
				Params:  []string{upstreamName, text},
			}
			uc.produce(upstreamName, echoMsg, dc)

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
		var target, limitStr string
		var boundsStr [2]string
		switch subcommand {
		case "AFTER", "BEFORE":
			if err := parseMessageParams(msg, nil, &target, &boundsStr[0], &limitStr); err != nil {
				return err
			}
		case "BETWEEN":
			if err := parseMessageParams(msg, nil, &target, &boundsStr[0], &boundsStr[1], &limitStr); err != nil {
				return err
			}
		case "TARGETS":
			if err := parseMessageParams(msg, nil, &boundsStr[0], &boundsStr[1], &limitStr); err != nil {
				return err
			}
		default:
			// TODO: support LATEST, AROUND
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "INVALID_PARAMS", subcommand, "Unknown command"},
			}}
		}

		store, ok := dc.user.msgStore.(chatHistoryMessageStore)
		if !ok {
			return ircError{&irc.Message{
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params:  []string{dc.nick, "CHATHISTORY", "Unknown command"},
			}}
		}

		uc, entity, err := dc.unmarshalEntity(target)
		if err != nil {
			return err
		}
		entity = uc.network.casemap(entity)

		// TODO: support msgid criteria
		var bounds [2]time.Time
		bounds[0] = parseChatHistoryBound(boundsStr[0])
		if bounds[0].IsZero() {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "INVALID_PARAMS", subcommand, boundsStr[0], "Invalid first bound"},
			}}
		}

		if boundsStr[1] != "" {
			bounds[1] = parseChatHistoryBound(boundsStr[1])
			if bounds[1].IsZero() {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"CHATHISTORY", "INVALID_PARAMS", subcommand, boundsStr[1], "Invalid second bound"},
				}}
			}
		}

		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 || limit > dc.srv.HistoryLimit {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "INVALID_PARAMS", subcommand, limitStr, "Invalid limit"},
			}}
		}

		var history []*irc.Message
		switch subcommand {
		case "BEFORE":
			history, err = store.LoadBeforeTime(uc.network, entity, bounds[0], time.Time{}, limit)
		case "AFTER":
			history, err = store.LoadAfterTime(uc.network, entity, bounds[0], time.Now(), limit)
		case "BETWEEN":
			if bounds[0].Before(bounds[1]) {
				history, err = store.LoadAfterTime(uc.network, entity, bounds[0], bounds[1], limit)
			} else {
				history, err = store.LoadBeforeTime(uc.network, entity, bounds[0], bounds[1], limit)
			}
		case "TARGETS":
			// TODO: support TARGETS in multi-upstream mode
			targets, err := store.ListTargets(uc.network, bounds[0], bounds[1], limit)
			if err != nil {
				dc.logger.Printf("failed fetching targets for chathistory: %v", target, err)
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"CHATHISTORY", "MESSAGE_ERROR", subcommand, "Failed to retrieve targets"},
				}}
			}

			dc.SendBatch("draft/chathistory-targets", nil, nil, func(batchRef irc.TagValue) {
				for _, target := range targets {
					if ch := uc.network.channels.Value(target.Name); ch != nil && ch.Detached {
						continue
					}

					dc.SendMessage(&irc.Message{
						Tags:    irc.Tags{"batch": batchRef},
						Prefix:  dc.srv.prefix(),
						Command: "CHATHISTORY",
						Params:  []string{"TARGETS", target.Name, target.LatestMessage.UTC().Format(serverTimeLayout)},
					})
				}
			})

			return nil
		}
		if err != nil {
			dc.logger.Printf("failed fetching %q messages for chathistory: %v", target, err)
			return newChatHistoryError(subcommand, target)
		}

		dc.SendBatch("chathistory", []string{target}, nil, func(batchRef irc.TagValue) {
			for _, msg := range history {
				msg.Tags["batch"] = batchRef
				dc.SendMessage(dc.marshalMessage(msg, uc.network))
			}
		})
	case "BOUNCER":
		var subcommand string
		if err := parseMessageParams(msg, &subcommand); err != nil {
			return err
		}

		switch strings.ToUpper(subcommand) {
		case "LISTNETWORKS":
			dc.SendBatch("soju.im/bouncer-networks", nil, nil, func(batchRef irc.TagValue) {
				dc.user.forEachNetwork(func(network *network) {
					idStr := fmt.Sprintf("%v", network.ID)
					attrs := getNetworkAttrs(network)
					dc.SendMessage(&irc.Message{
						Tags:    irc.Tags{"batch": batchRef},
						Prefix:  dc.srv.prefix(),
						Command: "BOUNCER",
						Params:  []string{"NETWORK", idStr, attrs.String()},
					})
				})
			})
		case "ADDNETWORK":
			var attrsStr string
			if err := parseMessageParams(msg, nil, &attrsStr); err != nil {
				return err
			}
			attrs := irc.ParseTags(attrsStr)

			host, ok := attrs.GetTag("host")
			if !ok {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "NEED_ATTRIBUTE", subcommand, "host", "Missing required host attribute"},
				}}
			}

			addr := host
			if port, ok := attrs.GetTag("port"); ok {
				addr += ":" + port
			}

			if tlsStr, ok := attrs.GetTag("tls"); ok && tlsStr == "0" {
				addr = "irc+insecure://" + tlsStr
			}

			nick, ok := attrs.GetTag("nickname")
			if !ok {
				nick = dc.nick
			}

			username, _ := attrs.GetTag("username")
			realname, _ := attrs.GetTag("realname")
			pass, _ := attrs.GetTag("pass")

			if realname == dc.user.Realname {
				realname = ""
			}

			// TODO: reject unknown attributes

			record := &Network{
				Addr:     addr,
				Nick:     nick,
				Username: username,
				Realname: realname,
				Pass:     pass,
				Enabled:  true,
			}
			network, err := dc.user.createNetwork(record)
			if err != nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "UNKNOWN_ERROR", subcommand, fmt.Sprintf("Failed to create network: %v", err)},
				}}
			}

			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BOUNCER",
				Params:  []string{"ADDNETWORK", fmt.Sprintf("%v", network.ID)},
			})
		case "CHANGENETWORK":
			var idStr, attrsStr string
			if err := parseMessageParams(msg, nil, &idStr, &attrsStr); err != nil {
				return err
			}
			id, err := parseBouncerNetID(subcommand, idStr)
			if err != nil {
				return err
			}
			attrs := irc.ParseTags(attrsStr)

			net := dc.user.getNetworkByID(id)
			if net == nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "INVALID_NETID", subcommand, idStr, "Invalid network ID"},
				}}
			}

			record := net.Network // copy network record because we'll mutate it
			for k, v := range attrs {
				s := string(v)
				switch k {
				// TODO: host, port, tls
				case "nickname":
					record.Nick = s
				case "username":
					record.Username = s
				case "realname":
					record.Realname = s
				case "pass":
					record.Pass = s
				default:
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{"BOUNCER", "UNKNOWN_ATTRIBUTE", subcommand, k, "Unknown attribute"},
					}}
				}
			}

			_, err = dc.user.updateNetwork(&record)
			if err != nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "UNKNOWN_ERROR", subcommand, fmt.Sprintf("Failed to update network: %v", err)},
				}}
			}

			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BOUNCER",
				Params:  []string{"CHANGENETWORK", idStr},
			})
		case "DELNETWORK":
			var idStr string
			if err := parseMessageParams(msg, nil, &idStr); err != nil {
				return err
			}
			id, err := parseBouncerNetID(subcommand, idStr)
			if err != nil {
				return err
			}

			net := dc.user.getNetworkByID(id)
			if net == nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "INVALID_NETID", subcommand, idStr, "Invalid network ID"},
				}}
			}

			if err := dc.user.deleteNetwork(net.ID); err != nil {
				return err
			}

			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BOUNCER",
				Params:  []string{"DELNETWORK", idStr},
			})
		default:
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"BOUNCER", "UNKNOWN_COMMAND", subcommand, "Unknown subcommand"},
			}}
		}
	default:
		dc.logger.Printf("unhandled message: %v", msg)

		// Only forward unknown commands in single-upstream mode
		uc := dc.upstream()
		if uc == nil {
			return newUnknownCommandError(msg.Command)
		}

		uc.SendMessageLabeled(dc.id, msg)
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
