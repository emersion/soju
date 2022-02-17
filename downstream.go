package soju

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
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

// authError is an authentication error.
type authError struct {
	// Internal error cause. This will not be revealed to the user.
	err error
	// Error cause which can safely be sent to the user without compromising
	// security.
	reason string
}

func (err *authError) Error() string {
	return err.err.Error()
}

func (err *authError) Unwrap() error {
	return err.err
}

// authErrorReason returns the user-friendly reason of an authentication
// failure.
func authErrorReason(err error) string {
	if authErr, ok := err.(*authError); ok {
		return authErr.reason
	} else {
		return "Authentication failed"
	}
}

func newInvalidUsernameOrPasswordError(err error) error {
	return &authError{
		err:    err,
		reason: "Invalid username or password",
	}
}

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

func fillNetworkAddrAttrs(attrs irc.Tags, network *Network) {
	u, err := network.URL()
	if err != nil {
		return
	}

	hasHostPort := true
	switch u.Scheme {
	case "ircs":
		attrs["tls"] = irc.TagValue("1")
	case "irc+insecure":
		attrs["tls"] = irc.TagValue("0")
	default: // e.g. unix://
		hasHostPort = false
	}
	if host, port, err := net.SplitHostPort(u.Host); err == nil && hasHostPort {
		attrs["host"] = irc.TagValue(host)
		attrs["port"] = irc.TagValue(port)
	} else if hasHostPort {
		attrs["host"] = irc.TagValue(u.Host)
	}
}

func getNetworkAttrs(network *network) irc.Tags {
	state := "disconnected"
	if uc := network.conn; uc != nil {
		state = "connected"
	}

	attrs := irc.Tags{
		"name":     irc.TagValue(network.GetName()),
		"state":    irc.TagValue(state),
		"nickname": irc.TagValue(GetNick(&network.user.User, &network.Network)),
	}

	if network.Username != "" {
		attrs["username"] = irc.TagValue(network.Username)
	}
	if realname := GetRealname(&network.user.User, &network.Network); realname != "" {
		attrs["realname"] = irc.TagValue(realname)
	}

	fillNetworkAddrAttrs(attrs, &network.Network)

	return attrs
}

func networkAddrFromAttrs(attrs irc.Tags) string {
	host, ok := attrs.GetTag("host")
	if !ok {
		return ""
	}

	addr := host
	if port, ok := attrs.GetTag("port"); ok {
		addr += ":" + port
	}

	if tlsStr, ok := attrs.GetTag("tls"); ok && tlsStr == "0" {
		addr = "irc+insecure://" + tlsStr
	}

	return addr
}

func updateNetworkAttrs(record *Network, attrs irc.Tags, subcommand string) error {
	addrAttrs := irc.Tags{}
	fillNetworkAddrAttrs(addrAttrs, record)

	updateAddr := false
	for k, v := range attrs {
		s := string(v)
		switch k {
		case "host", "port", "tls":
			updateAddr = true
			addrAttrs[k] = v
		case "name":
			record.Name = s
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

	if updateAddr {
		record.Addr = networkAddrFromAttrs(addrAttrs)
		if record.Addr == "" {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"BOUNCER", "NEED_ATTRIBUTE", subcommand, "host", "Missing required host attribute"},
			}}
		}
	}

	return nil
}

// ' ' and ':' break the IRC message wire format, '@' and '!' break prefixes,
// '*' and '?' break masks, '$' breaks server masks in PRIVMSG/NOTICE,
// "*" is the reserved nickname for registration, ',' breaks lists
const illegalNickChars = " :@!*?$,"

// permanentDownstreamCaps is the list of always-supported downstream
// capabilities.
var permanentDownstreamCaps = map[string]string{
	"batch":         "",
	"cap-notify":    "",
	"echo-message":  "",
	"invite-notify": "",
	"message-tags":  "",
	"server-time":   "",
	"setname":       "",

	"soju.im/bouncer-networks":        "",
	"soju.im/bouncer-networks-notify": "",
	"soju.im/read":                    "",
}

// needAllDownstreamCaps is the list of downstream capabilities that
// require support from all upstreams to be enabled
var needAllDownstreamCaps = map[string]string{
	"account-notify": "",
	"account-tag":    "",
	"away-notify":    "",
	"extended-join":  "",
	"multi-prefix":   "",

	"draft/extended-monitor": "",
}

// passthroughIsupport is the set of ISUPPORT tokens that are directly passed
// through from the upstream server to downstream clients.
//
// This is only effective in single-upstream mode.
var passthroughIsupport = map[string]bool{
	"AWAYLEN":       true,
	"BOT":           true,
	"CHANLIMIT":     true,
	"CHANMODES":     true,
	"CHANNELLEN":    true,
	"CHANTYPES":     true,
	"CLIENTTAGDENY": true,
	"ELIST":         true,
	"EXCEPTS":       true,
	"EXTBAN":        true,
	"HOSTLEN":       true,
	"INVEX":         true,
	"KICKLEN":       true,
	"MAXLIST":       true,
	"MAXTARGETS":    true,
	"MODES":         true,
	"MONITOR":       true,
	"NAMELEN":       true,
	"NETWORK":       true,
	"NICKLEN":       true,
	"PREFIX":        true,
	"SAFELIST":      true,
	"TARGMAX":       true,
	"TOPICLEN":      true,
	"USERLEN":       true,
	"UTF8ONLY":      true,
	"WHOX":          true,
}

type downstreamSASL struct {
	server                       sasl.Server
	plainUsername, plainPassword string
	pendingResp                  bytes.Buffer
}

type downstreamConn struct {
	conn

	id uint64

	registered      bool
	user            *user
	nick            string
	nickCM          string
	rawUsername     string
	networkName     string
	clientName      string
	realname        string
	hostname        string
	account         string   // RPL_LOGGEDIN/OUT state
	password        string   // empty after authentication
	network         *network // can be nil
	isMultiUpstream bool

	negotiatingCaps bool
	capVersion      int
	supportedCaps   map[string]string
	caps            map[string]bool
	sasl            *downstreamSASL

	lastBatchRef uint64

	monitored casemapMap
}

func newDownstreamConn(srv *Server, ic ircConn, id uint64) *downstreamConn {
	remoteAddr := ic.RemoteAddr().String()
	logger := &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", remoteAddr)}
	options := connOptions{Logger: logger}
	dc := &downstreamConn{
		conn:          *newConn(srv, ic, &options),
		id:            id,
		nick:          "*",
		nickCM:        "*",
		supportedCaps: make(map[string]string),
		caps:          make(map[string]bool),
		monitored:     newCasemapMap(0),
	}
	dc.hostname = remoteAddr
	if host, _, err := net.SplitHostPort(dc.hostname); err == nil {
		dc.hostname = host
	}
	for k, v := range permanentDownstreamCaps {
		dc.supportedCaps[k] = v
	}
	dc.supportedCaps["sasl"] = "PLAIN"
	// TODO: this is racy, we should only enable chathistory after
	// authentication and then check that user.msgStore implements
	// chatHistoryMessageStore
	if srv.Config().LogPath != "" {
		dc.supportedCaps["draft/chathistory"] = ""
	}
	if dc.conn.conn.SupportsCompression() {
		dc.supportedCaps["draft/compression"] = ""
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
	} else if dc.isMultiUpstream {
		for _, network := range dc.user.networks {
			f(network)
		}
	}
}

func (dc *downstreamConn) forEachUpstream(f func(*upstreamConn)) {
	if dc.network == nil && !dc.isMultiUpstream {
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
	return net.casemap(nick) == net.casemap(GetNick(&net.user.User, &net.Network))
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

// unmarshalEntityNetwork converts a downstream entity name (ie. channel or
// nick) into an upstream entity name.
//
// This involves removing the "/<network>" suffix.
func (dc *downstreamConn) unmarshalEntityNetwork(name string) (*network, string, error) {
	if dc.network != nil {
		return dc.network, name, nil
	}
	if !dc.isMultiUpstream {
		return nil, "", ircError{&irc.Message{
			Command: irc.ERR_NOSUCHCHANNEL,
			Params:  []string{dc.nick, name, "Cannot interact with channels and users on the bouncer connection. Did you mean to use a specific network?"},
		}}
	}

	var net *network
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		network := name[i+1:]
		name = name[:i]

		for _, n := range dc.user.networks {
			if network == n.GetName() {
				net = n
				break
			}
		}
	}

	if net == nil {
		return nil, "", ircError{&irc.Message{
			Command: irc.ERR_NOSUCHCHANNEL,
			Params:  []string{dc.nick, name, "Missing network suffix in name"},
		}}
	}

	return net, name, nil
}

// unmarshalEntity is the same as unmarshalEntityNetwork, but returns the
// upstream connection and fails if the upstream is disconnected.
func (dc *downstreamConn) unmarshalEntity(name string) (*upstreamConn, string, error) {
	net, name, err := dc.unmarshalEntityNetwork(name)
	if err != nil {
		return nil, "", err
	}

	if net.conn == nil {
		return nil, "", ircError{&irc.Message{
			Command: irc.ERR_NOSUCHCHANNEL,
			Params:  []string{dc.nick, name, "Disconnected from upstream network"},
		}}
	}

	return net.conn, name, nil
}

func (dc *downstreamConn) unmarshalText(uc *upstreamConn, text string) string {
	if dc.upstream() != nil {
		return text
	}
	// TODO: smarter parsing that ignores URLs
	return strings.ReplaceAll(text, "/"+uc.network.GetName(), "")
}

func (dc *downstreamConn) ReadMessage() (*irc.Message, error) {
	msg, err := dc.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	dc.srv.metrics.downstreamInMessagesTotal.Inc()
	return msg, nil
}

func (dc *downstreamConn) readMessages(ch chan<- event) error {
	for {
		msg, err := dc.ReadMessage()
		if errors.Is(err, io.EOF) {
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
	if msg.Command == "AWAY" && !dc.caps["away-notify"] {
		return
	}
	if msg.Command == "ACCOUNT" && !dc.caps["account-notify"] {
		return
	}
	if msg.Command == "READ" && !dc.caps["soju.im/read"] {
		return
	}

	dc.srv.metrics.downstreamOutMessagesTotal.Inc()
	dc.conn.SendMessage(context.TODO(), msg)
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

	if id == "" || !dc.messageSupportsBacklog(msg) {
		return
	}

	dc.sendPing(id)
}

// advanceMessageWithID advances history to the specified message ID without
// sending a message. This is useful e.g. for self-messages when echo-message
// isn't enabled.
func (dc *downstreamConn) advanceMessageWithID(msg *irc.Message, id string) {
	if id == "" || !dc.messageSupportsBacklog(msg) {
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
// messages that may appear in logs are supported, except MODE messages which
// may only appear in single-upstream mode.
func (dc *downstreamConn) marshalMessage(msg *irc.Message, net *network) *irc.Message {
	msg = msg.Copy()
	msg.Prefix = dc.marshalUserPrefix(net, msg.Prefix)

	if dc.network != nil {
		return msg
	}

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

func (dc *downstreamConn) handleMessage(ctx context.Context, msg *irc.Message) error {
	ctx, cancel := dc.conn.NewContext(ctx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, handleDownstreamMessageTimeout)
	defer cancel()

	switch msg.Command {
	case "QUIT":
		return dc.Close()
	default:
		if dc.registered {
			return dc.handleMessageRegistered(ctx, msg)
		} else {
			return dc.handleMessageUnregistered(ctx, msg)
		}
	}
}

func (dc *downstreamConn) handleMessageUnregistered(ctx context.Context, msg *irc.Message) error {
	switch msg.Command {
	case "NICK":
		var nick string
		if err := parseMessageParams(msg, &nick); err != nil {
			return err
		}
		if nick == "" || strings.ContainsAny(nick, illegalNickChars) {
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
		credentials, err := dc.handleAuthenticateCommand(msg)
		if err != nil {
			return err
		} else if credentials == nil {
			break
		}

		if err := dc.authenticate(ctx, credentials.plainUsername, credentials.plainPassword); err != nil {
			dc.logger.Printf("SASL authentication error for user %q: %v", credentials.plainUsername, err)
			dc.endSASL(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, authErrorReason(err)},
			})
			break
		}

		// Technically we should send RPL_LOGGEDIN here. However we use
		// RPL_LOGGEDIN to mirror the upstream connection status. Let's
		// see how many clients that breaks. See:
		// https://github.com/ircv3/ircv3-specifications/pull/476
		dc.endSASL(nil)
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
			for _, net := range dc.user.networks {
				if net.ID == id {
					match = net
					break
				}
			}
			if match == nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "INVALID_NETID", idStr, "Unknown network ID"},
				}}
			}

			dc.networkName = match.GetName()
		}
	case "COMPRESS":
		// handled in dc.conn.ReadMessage() if supported
		if !dc.conn.conn.SupportsCompression() {
			return newUnknownCommandError(msg.Command)
		}
	default:
		dc.logger.Printf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	if dc.rawUsername != "" && dc.nick != "*" && !dc.negotiatingCaps {
		if dc.caps["draft/compression"] {
			// triggers compression at dc.conn level
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "COMPRESS",
			})
		}
		return dc.register(ctx)
	}
	return nil
}

func (dc *downstreamConn) handleCapCommand(cmd string, args []string) error {
	cmd = strings.ToUpper(cmd)

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
			Params:  []string{dc.nick, "LS", strings.Join(caps, " ")},
		})

		if dc.capVersion >= 302 {
			// CAP version 302 implicitly enables cap-notify
			dc.caps["cap-notify"] = true
		}

		if !dc.registered {
			dc.negotiatingCaps = true
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
			Params:  []string{dc.nick, "LIST", strings.Join(caps, " ")},
		})
	case "REQ":
		if len(args) == 0 {
			return ircError{&irc.Message{
				Command: err_invalidcapcmd,
				Params:  []string{dc.nick, cmd, "Missing argument in CAP REQ command"},
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
			Params:  []string{dc.nick, reply, args[0]},
		})

		if !dc.registered {
			dc.negotiatingCaps = true
		}
	case "END":
		dc.negotiatingCaps = false
	default:
		return ircError{&irc.Message{
			Command: err_invalidcapcmd,
			Params:  []string{dc.nick, cmd, "Unknown CAP command"},
		}}
	}
	return nil
}

func (dc *downstreamConn) handleAuthenticateCommand(msg *irc.Message) (result *downstreamSASL, err error) {
	defer func() {
		if err != nil {
			dc.sasl = nil
		}
	}()

	if !dc.caps["sasl"] {
		return nil, ircError{&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.ERR_SASLFAIL,
			Params:  []string{dc.nick, "AUTHENTICATE requires the \"sasl\" capability to be enabled"},
		}}
	}
	if len(msg.Params) == 0 {
		return nil, ircError{&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.ERR_SASLFAIL,
			Params:  []string{dc.nick, "Missing AUTHENTICATE argument"},
		}}
	}
	if msg.Params[0] == "*" {
		return nil, ircError{&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.ERR_SASLABORTED,
			Params:  []string{dc.nick, "SASL authentication aborted"},
		}}
	}

	var resp []byte
	if dc.sasl == nil {
		mech := strings.ToUpper(msg.Params[0])
		var server sasl.Server
		switch mech {
		case "PLAIN":
			server = sasl.NewPlainServer(sasl.PlainAuthenticator(func(identity, username, password string) error {
				dc.sasl.plainUsername = username
				dc.sasl.plainPassword = password
				return nil
			}))
		default:
			return nil, ircError{&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, fmt.Sprintf("Unsupported SASL mechanism %q", mech)},
			}}
		}

		dc.sasl = &downstreamSASL{server: server}
	} else {
		chunk := msg.Params[0]
		if chunk == "+" {
			chunk = ""
		}

		if dc.sasl.pendingResp.Len()+len(chunk) > 10*1024 {
			return nil, ircError{&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, "Response too long"},
			}}
		}

		dc.sasl.pendingResp.WriteString(chunk)

		if len(chunk) == maxSASLLength {
			return nil, nil // Multi-line response, wait for the next command
		}

		resp, err = base64.StdEncoding.DecodeString(dc.sasl.pendingResp.String())
		if err != nil {
			return nil, ircError{&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, "Invalid base64-encoded response"},
			}}
		}

		dc.sasl.pendingResp.Reset()
	}

	challenge, done, err := dc.sasl.server.Next(resp)
	if err != nil {
		return nil, err
	} else if done {
		return dc.sasl, nil
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
		return nil, nil
	}
}

func (dc *downstreamConn) endSASL(msg *irc.Message) {
	if dc.sasl == nil {
		return
	}

	dc.sasl = nil

	if msg != nil {
		dc.SendMessage(msg)
	} else {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_SASLSUCCESS,
			Params:  []string{dc.nick, "SASL authentication successful"},
		})
	}
}

func (dc *downstreamConn) setSupportedCap(name, value string) {
	prevValue, hasPrev := dc.supportedCaps[name]
	changed := !hasPrev || prevValue != value
	dc.supportedCaps[name] = value

	if !dc.caps["cap-notify"] || !changed {
		return
	}

	cap := name
	if value != "" && dc.capVersion >= 302 {
		cap = name + "=" + value
	}

	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: "CAP",
		Params:  []string{dc.nick, "NEW", cap},
	})
}

func (dc *downstreamConn) unsetSupportedCap(name string) {
	_, hasPrev := dc.supportedCaps[name]
	delete(dc.supportedCaps, name)
	delete(dc.caps, name)

	if !dc.caps["cap-notify"] || !hasPrev {
		return
	}

	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: "CAP",
		Params:  []string{dc.nick, "DEL", name},
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

	if uc := dc.upstream(); uc != nil && uc.supportsSASL("PLAIN") {
		dc.setSupportedCap("sasl", "PLAIN")
	} else if dc.network != nil {
		dc.unsetSupportedCap("sasl")
	}

	if uc := dc.upstream(); uc != nil && uc.caps["draft/account-registration"] {
		// Strip "before-connect", because we require downstreams to be fully
		// connected before attempting account registration.
		values := strings.Split(uc.supportedCaps["draft/account-registration"], ",")
		for i, v := range values {
			if v == "before-connect" {
				values = append(values[:i], values[i+1:]...)
				break
			}
		}
		dc.setSupportedCap("draft/account-registration", strings.Join(values, ","))
	} else {
		dc.unsetSupportedCap("draft/account-registration")
	}

	if _, ok := dc.user.msgStore.(chatHistoryMessageStore); ok && dc.network != nil {
		dc.setSupportedCap("draft/event-playback", "")
	} else {
		dc.unsetSupportedCap("draft/event-playback")
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

func (dc *downstreamConn) updateAccount() {
	var account string
	if dc.network == nil {
		account = dc.user.Username
	} else if uc := dc.upstream(); uc != nil {
		account = uc.account
	} else {
		return
	}

	if dc.account == account || !dc.caps["sasl"] {
		return
	}

	if account != "" {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_LOGGEDIN,
			Params:  []string{dc.nick, dc.prefix().String(), account, "You are logged in as " + account},
		})
	} else {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_LOGGEDOUT,
			Params:  []string{dc.nick, dc.prefix().String(), "You are logged out"},
		})
	}

	dc.account = account
}

func sanityCheckServer(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	conn, err := new(tls.Dialer).DialContext(ctx, "tcp", addr)
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

func (dc *downstreamConn) authenticate(ctx context.Context, username, password string) error {
	username, clientName, networkName := unmarshalUsername(username)

	u, err := dc.srv.db.GetUser(ctx, username)
	if err != nil {
		return newInvalidUsernameOrPasswordError(fmt.Errorf("user not found: %w", err))
	}

	// Password auth disabled
	if u.Password == "" {
		return newInvalidUsernameOrPasswordError(fmt.Errorf("password auth disabled"))
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		return newInvalidUsernameOrPasswordError(fmt.Errorf("wrong password"))
	}

	dc.user = dc.srv.getUser(username)
	if dc.user == nil {
		return fmt.Errorf("user not active")
	}
	dc.clientName = clientName
	dc.networkName = networkName
	return nil
}

func (dc *downstreamConn) register(ctx context.Context) error {
	if dc.registered {
		return fmt.Errorf("tried to register twice")
	}

	if dc.sasl != nil {
		dc.endSASL(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.ERR_SASLABORTED,
			Params:  []string{dc.nick, "SASL authentication aborted"},
		})
	}

	password := dc.password
	dc.password = ""
	if dc.user == nil {
		if password == "" {
			if dc.caps["sasl"] {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"*", "ACCOUNT_REQUIRED", "Authentication required"},
				}}
			} else {
				return ircError{&irc.Message{
					Command: irc.ERR_PASSWDMISMATCH,
					Params:  []string{dc.nick, "Authentication required"},
				}}
			}
		}

		if err := dc.authenticate(ctx, dc.rawUsername, password); err != nil {
			dc.logger.Printf("PASS authentication error for user %q: %v", dc.rawUsername, err)
			return ircError{&irc.Message{
				Command: irc.ERR_PASSWDMISMATCH,
				Params:  []string{dc.nick, authErrorReason(err)},
			}}
		}
	}

	if dc.clientName == "" && dc.networkName == "" {
		_, dc.clientName, dc.networkName = unmarshalUsername(dc.rawUsername)
	}

	dc.registered = true
	dc.logger.Printf("registration complete for user %q", dc.user.Username)
	return nil
}

func (dc *downstreamConn) loadNetwork(ctx context.Context) error {
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
		if err := sanityCheckServer(ctx, addr); err != nil {
			dc.logger.Printf("failed to connect to %q: %v", addr, err)
			return ircError{&irc.Message{
				Command: irc.ERR_PASSWDMISMATCH,
				Params:  []string{dc.nick, fmt.Sprintf("Failed to connect to %q", dc.networkName)},
			}}
		}

		// Some clients only allow specifying the nickname (and use the
		// nickname as a username too). Strip the network name from the
		// nickname when auto-saving networks.
		nick, _, _ := unmarshalUsername(dc.nick)

		dc.logger.Printf("auto-saving network %q", dc.networkName)
		var err error
		network, err = dc.user.createNetwork(ctx, &Network{
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

func (dc *downstreamConn) welcome(ctx context.Context) error {
	if dc.user == nil || !dc.registered {
		panic("tried to welcome an unregistered connection")
	}

	remoteAddr := dc.conn.RemoteAddr().String()
	dc.logger = &prefixLogger{dc.srv.Logger, fmt.Sprintf("user %q: downstream %q: ", dc.user.Username, remoteAddr)}

	// TODO: doing this might take some time. We should do it in dc.register
	// instead, but we'll potentially be adding a new network and this must be
	// done in the user goroutine.
	if err := dc.loadNetwork(ctx); err != nil {
		return err
	}

	if dc.network == nil && !dc.caps["soju.im/bouncer-networks"] && dc.srv.Config().MultiUpstream {
		dc.isMultiUpstream = true
	}

	dc.updateSupportedCaps()

	isupport := []string{
		fmt.Sprintf("CHATHISTORY=%v", chatHistoryLimit),
		"CASEMAPPING=ascii",
	}

	if dc.network != nil {
		isupport = append(isupport, fmt.Sprintf("BOUNCER_NETID=%v", dc.network.ID))
	}
	if title := dc.srv.Config().Title; dc.network == nil && title != "" {
		isupport = append(isupport, "NETWORK="+encodeISUPPORT(title))
	}
	if dc.network == nil && !dc.isMultiUpstream {
		isupport = append(isupport, "WHOX")
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
		Params:  []string{dc.nick, "Your host is " + dc.srv.Config().Hostname},
	})
	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_MYINFO,
		Params:  []string{dc.nick, dc.srv.Config().Hostname, "soju", "aiwroO", "OovaimnqpsrtklbeI"},
	})
	for _, msg := range generateIsupport(dc.srv.prefix(), dc.nick, isupport) {
		dc.SendMessage(msg)
	}
	if uc := dc.upstream(); uc != nil {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_UMODEIS,
			Params:  []string{dc.nick, "+" + string(uc.modes)},
		})
	}
	if dc.network == nil && !dc.isMultiUpstream && dc.user.Admin {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_UMODEIS,
			Params:  []string{dc.nick, "+o"},
		})
	}

	dc.updateNick()
	dc.updateRealname()
	dc.updateAccount()

	if motd := dc.user.srv.Config().MOTD; motd != "" && dc.network == nil {
		for _, msg := range generateMOTD(dc.srv.prefix(), dc.nick, motd) {
			dc.SendMessage(msg)
		}
	} else {
		motdHint := "No MOTD"
		if dc.network != nil {
			motdHint = "Use /motd to read the message of the day"
		}
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.ERR_NOMOTD,
			Params:  []string{dc.nick, motdHint},
		})
	}

	if dc.caps["soju.im/bouncer-networks-notify"] {
		dc.SendBatch("soju.im/bouncer-networks", nil, nil, func(batchRef irc.TagValue) {
			for _, network := range dc.user.networks {
				idStr := fmt.Sprintf("%v", network.ID)
				attrs := getNetworkAttrs(network)
				dc.SendMessage(&irc.Message{
					Tags:    irc.Tags{"batch": batchRef},
					Prefix:  dc.srv.prefix(),
					Command: "BOUNCER",
					Params:  []string{"NETWORK", idStr, attrs.String()},
				})
			}
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

			forwardChannel(ctx, dc, ch)
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

				dc.sendTargetBacklog(ctx, net, target, lastDelivered)

				// Fast-forward history to last message
				targetCM := net.casemap(target)
				lastID, err := dc.user.msgStore.LastMsgID(&net.Network, targetCM, time.Now())
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

// messageSupportsBacklog checks whether the provided message can be sent as
// part of an history batch.
func (dc *downstreamConn) messageSupportsBacklog(msg *irc.Message) bool {
	// Don't replay all messages, because that would mess up client
	// state. For instance we just sent the list of users, sending
	// PART messages for one of these users would be incorrect.
	switch msg.Command {
	case "PRIVMSG", "NOTICE":
		return true
	}
	return false
}

func (dc *downstreamConn) sendTargetBacklog(ctx context.Context, net *network, target, msgID string) {
	if dc.caps["draft/chathistory"] || dc.user.msgStore == nil {
		return
	}

	ch := net.channels.Value(target)

	ctx, cancel := context.WithTimeout(ctx, backlogTimeout)
	defer cancel()

	targetCM := net.casemap(target)
	history, err := dc.user.msgStore.LoadLatestID(ctx, &net.Network, targetCM, msgID, backlogLimit)
	if err != nil {
		dc.logger.Printf("failed to send backlog for %q: %v", target, err)
		return
	}

	dc.SendBatch("chathistory", []string{dc.marshalEntity(net, target)}, nil, func(batchRef irc.TagValue) {
		for _, msg := range history {
			if ch != nil && ch.Detached {
				if net.detachedMessageNeedsRelay(ch, msg) {
					dc.relayDetachedMessage(net, msg)
				}
			} else {
				msg.Tags["batch"] = batchRef
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
	ctx, cancel := context.WithTimeout(context.TODO(), downstreamRegisterTimeout)
	defer cancel()

	// Close the connection with an error if the deadline is exceeded
	go func() {
		<-ctx.Done()
		if err := ctx.Err(); err == context.DeadlineExceeded {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "ERROR",
				Params:  []string{"Connection registration timed out"},
			})
			dc.Close()
		}
	}()

	for !dc.registered {
		msg, err := dc.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to read IRC command: %w", err)
		}

		err = dc.handleMessage(ctx, msg)
		if ircErr, ok := err.(ircError); ok {
			ircErr.Message.Prefix = dc.srv.prefix()
			dc.SendMessage(ircErr.Message)
		} else if err != nil {
			return fmt.Errorf("failed to handle IRC command %q: %v", msg, err)
		}
	}

	return nil
}

func (dc *downstreamConn) handleMessageRegistered(ctx context.Context, msg *irc.Message) error {
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
		hostname := dc.srv.Config().Hostname
		if destination != "" && destination != hostname {
			return ircError{&irc.Message{
				Command: irc.ERR_NOSUCHSERVER,
				Params:  []string{dc.nick, destination, "No such server"},
			}}
		}
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "PONG",
			Params:  []string{hostname, source},
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

		if nick == "" || strings.ContainsAny(nick, illegalNickChars) {
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
			err = dc.srv.db.StoreNetwork(ctx, dc.user.ID, &n.Network)
		})
		if err != nil {
			return err
		}

		dc.forEachUpstream(func(uc *upstreamConn) {
			if upstream != nil && upstream != uc {
				return
			}
			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
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
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "SETNAME",
					Params:  []string{realname},
				})

				n.Realname = storeRealname
				if err := dc.srv.db.StoreNetwork(ctx, dc.user.ID, &n.Network); err != nil {
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
			if _, err := dc.user.updateNetwork(ctx, &record); err != nil {
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

		if dc.upstream() == nil {
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

			// Most servers ignore duplicate JOIN messages. We ignore them here
			// because some clients automatically send JOIN messages in bulk
			// when reconnecting to the bouncer. We don't want to flood the
			// upstream connection with these.
			if !uc.channels.Has(upstreamName) {
				params := []string{upstreamName}
				if key != "" {
					params = append(params, key)
				}
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "JOIN",
					Params:  params,
				})
			}

			ch := uc.network.channels.Value(upstreamName)
			if ch != nil {
				// Don't clear the channel key if there's one set
				// TODO: add a way to unset the channel key
				if key != "" {
					ch.Key = key
				}
				uc.network.attach(ctx, ch)
			} else {
				ch = &Channel{
					Name: upstreamName,
					Key:  key,
				}
				uc.network.channels.SetValue(upstreamName, ch)
			}
			if err := dc.srv.db.StoreChannel(ctx, uc.network.ID, ch); err != nil {
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
				if err := dc.srv.db.StoreChannel(ctx, uc.network.ID, ch); err != nil {
					dc.logger.Printf("failed to create or update channel %q: %v", upstreamName, err)
				}
			} else {
				params := []string{upstreamName}
				if reason != "" {
					params = append(params, reason)
				}
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "PART",
					Params:  params,
				})

				if err := uc.network.deleteChannel(ctx, upstreamName); err != nil {
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
			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
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
					uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
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
					Params:  []string{dc.nick, "+" + userMode},
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
			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
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
			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
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
		network := dc.network
		if network == nil && len(msg.Params) > 0 {
			var err error
			network, msg.Params[0], err = dc.unmarshalEntityNetwork(msg.Params[0])
			if err != nil {
				return err
			}
		}
		if network == nil {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_LISTEND,
				Params:  []string{dc.nick, "LIST without a network suffix is not supported in multi-upstream mode"},
			})
			return nil
		}

		uc := network.conn
		if uc == nil {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_LISTEND,
				Params:  []string{dc.nick, "Disconnected from upstream server"},
			})
			return nil
		}

		uc.enqueueCommand(dc, msg)
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
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "NAMES",
					Params:  []string{upstreamName},
				})
			}
		}
	// For WHOX docs, see:
	// - http://faerion.sourceforge.net/doc/irc/whox.var
	// - https://github.com/quakenet/snircd/blob/master/doc/readme.who
	// Note, many features aren't widely implemented, such as flags and mask2
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

		// Clients will use the first mask to match RPL_ENDOFWHO
		endOfWhoToken := msg.Params[0]

		// TODO: add support for WHOX mask2
		mask := msg.Params[0]
		var options string
		if len(msg.Params) > 1 {
			options = msg.Params[1]
		}

		optionsParts := strings.SplitN(options, "%", 2)
		// TODO: add support for WHOX flags in optionsParts[0]
		var fields, whoxToken string
		if len(optionsParts) == 2 {
			optionsParts := strings.SplitN(optionsParts[1], ",", 2)
			fields = strings.ToLower(optionsParts[0])
			if len(optionsParts) == 2 && strings.Contains(fields, "t") {
				whoxToken = optionsParts[1]
			}
		}

		// TODO: support mixed bouncer/upstream WHO queries
		maskCM := casemapASCII(mask)
		if dc.network == nil && maskCM == dc.nickCM {
			// TODO: support AWAY (H/G) in self WHO reply
			flags := "H"
			if dc.user.Admin {
				flags += "*"
			}
			info := whoxInfo{
				Token:    whoxToken,
				Username: dc.user.Username,
				Hostname: dc.hostname,
				Server:   dc.srv.Config().Hostname,
				Nickname: dc.nick,
				Flags:    flags,
				Account:  dc.user.Username,
				Realname: dc.realname,
			}
			dc.SendMessage(generateWHOXReply(dc.srv.prefix(), dc.nick, fields, &info))
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{dc.nick, endOfWhoToken, "End of /WHO list"},
			})
			return nil
		}
		if maskCM == serviceNickCM {
			info := whoxInfo{
				Token:    whoxToken,
				Username: servicePrefix.User,
				Hostname: servicePrefix.Host,
				Server:   dc.srv.Config().Hostname,
				Nickname: serviceNick,
				Flags:    "H*",
				Account:  serviceNick,
				Realname: serviceRealname,
			}
			dc.SendMessage(generateWHOXReply(dc.srv.prefix(), dc.nick, fields, &info))
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{dc.nick, endOfWhoToken, "End of /WHO list"},
			})
			return nil
		}

		// TODO: properly support WHO masks
		uc, upstreamMask, err := dc.unmarshalEntity(mask)
		if err != nil {
			return err
		}

		params := []string{upstreamMask}
		if options != "" {
			params = append(params, options)
		}

		uc.enqueueCommand(dc, &irc.Message{
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
				Params:  []string{dc.nick, dc.nick, dc.srv.Config().Hostname, "soju"},
			})
			if dc.user.Admin {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_WHOISOPERATOR,
					Params:  []string{dc.nick, dc.nick, "is a bouncer administrator"},
				})
			}
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: rpl_whoisaccount,
				Params:  []string{dc.nick, dc.nick, dc.user.Username, "is logged in as"},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHOIS,
				Params:  []string{dc.nick, dc.nick, "End of /WHOIS list"},
			})
			return nil
		}
		if casemapASCII(mask) == serviceNickCM {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISUSER,
				Params:  []string{dc.nick, serviceNick, servicePrefix.User, servicePrefix.Host, "*", serviceRealname},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISSERVER,
				Params:  []string{dc.nick, serviceNick, dc.srv.Config().Hostname, "soju"},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISOPERATOR,
				Params:  []string{dc.nick, serviceNick, "is the bouncer service"},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: rpl_whoisaccount,
				Params:  []string{dc.nick, serviceNick, serviceNick, "is logged in as"},
			})
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHOIS,
				Params:  []string{dc.nick, serviceNick, "End of /WHOIS list"},
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

		uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
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
			if name == "$"+dc.srv.Config().Hostname || (name == "$*" && dc.network == nil) {
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
				broadcastTags["time"] = irc.TagValue(formatServerTime(time.Now()))
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
				dc.SendMessage(&irc.Message{
					Tags:    msg.Tags.Copy(),
					Prefix:  dc.prefix(),
					Command: msg.Command,
					Params:  []string{name, text},
				})
				continue
			}

			if msg.Command == "PRIVMSG" && casemapASCII(name) == serviceNickCM {
				if dc.caps["echo-message"] {
					echoTags := tags.Copy()
					echoTags["time"] = irc.TagValue(formatServerTime(time.Now()))
					dc.SendMessage(&irc.Message{
						Tags:    echoTags,
						Prefix:  dc.prefix(),
						Command: msg.Command,
						Params:  []string{name, text},
					})
				}
				handleServicePRIVMSG(ctx, dc, text)
				continue
			}

			uc, upstreamName, err := dc.unmarshalEntity(name)
			if err != nil {
				return err
			}

			if msg.Command == "PRIVMSG" && uc.network.casemap(upstreamName) == "nickserv" {
				dc.handleNickServPRIVMSG(ctx, uc, text)
			}

			unmarshaledText := text
			if uc.isChannel(upstreamName) {
				unmarshaledText = dc.unmarshalText(uc, text)
			}
			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
				Tags:    tags,
				Command: msg.Command,
				Params:  []string{upstreamName, unmarshaledText},
			})

			echoTags := tags.Copy()
			echoTags["time"] = irc.TagValue(formatServerTime(time.Now()))
			if uc.account != "" {
				echoTags["account"] = irc.TagValue(uc.account)
			}
			echoMsg := &irc.Message{
				Tags:    echoTags,
				Prefix:  &irc.Prefix{Name: uc.nick},
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
			if dc.network == nil && casemapASCII(name) == dc.nickCM {
				dc.SendMessage(&irc.Message{
					Tags:    msg.Tags.Copy(),
					Prefix:  dc.prefix(),
					Command: "TAGMSG",
					Params:  []string{name},
				})
				continue
			}

			if casemapASCII(name) == serviceNickCM {
				continue
			}

			uc, upstreamName, err := dc.unmarshalEntity(name)
			if err != nil {
				return err
			}
			if _, ok := uc.caps["message-tags"]; !ok {
				continue
			}

			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
				Tags:    tags,
				Command: "TAGMSG",
				Params:  []string{upstreamName},
			})

			echoTags := tags.Copy()
			echoTags["time"] = irc.TagValue(formatServerTime(time.Now()))
			if uc.account != "" {
				echoTags["account"] = irc.TagValue(uc.account)
			}
			echoMsg := &irc.Message{
				Tags:    echoTags,
				Prefix:  &irc.Prefix{Name: uc.nick},
				Command: "TAGMSG",
				Params:  []string{upstreamName},
			}
			uc.produce(upstreamName, echoMsg, dc)

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

		uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
			Command: "INVITE",
			Params:  []string{upstreamUser, upstreamChannel},
		})
	case "AUTHENTICATE":
		// Post-connection-registration AUTHENTICATE is unsupported in
		// multi-upstream mode, or if the upstream doesn't support SASL
		uc := dc.upstream()
		if uc == nil || !uc.caps["sasl"] {
			return ircError{&irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, "Upstream network authentication not supported"},
			}}
		}

		credentials, err := dc.handleAuthenticateCommand(msg)
		if err != nil {
			return err
		}

		if credentials != nil {
			if uc.saslClient != nil {
				dc.endSASL(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.ERR_SASLFAIL,
					Params:  []string{dc.nick, "Another authentication attempt is already in progress"},
				})
				return nil
			}

			uc.logger.Printf("starting post-registration SASL PLAIN authentication with username %q", credentials.plainUsername)
			uc.saslClient = sasl.NewPlainClient("", credentials.plainUsername, credentials.plainPassword)
			uc.enqueueCommand(dc, &irc.Message{
				Command: "AUTHENTICATE",
				Params:  []string{"PLAIN"},
			})
		}
	case "REGISTER", "VERIFY":
		// Check number of params here, since we'll use that to save the
		// credentials on command success
		if (msg.Command == "REGISTER" && len(msg.Params) < 3) || (msg.Command == "VERIFY" && len(msg.Params) < 2) {
			return newNeedMoreParamsError(msg.Command)
		}

		uc := dc.upstream()
		if uc == nil || !uc.caps["draft/account-registration"] {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{msg.Command, "TEMPORARILY_UNAVAILABLE", "*", "Upstream network account registration not supported"},
			}}
		}

		uc.logger.Printf("starting %v with account name %v", msg.Command, msg.Params[0])
		uc.enqueueCommand(dc, msg)
	case "MONITOR":
		// MONITOR is unsupported in multi-upstream mode
		uc := dc.upstream()
		if uc == nil {
			return newUnknownCommandError(msg.Command)
		}
		if _, ok := uc.isupport["MONITOR"]; !ok {
			return newUnknownCommandError(msg.Command)
		}

		var subcommand string
		if err := parseMessageParams(msg, &subcommand); err != nil {
			return err
		}

		switch strings.ToUpper(subcommand) {
		case "+", "-":
			var targets string
			if err := parseMessageParams(msg, nil, &targets); err != nil {
				return err
			}
			for _, target := range strings.Split(targets, ",") {
				if subcommand == "+" {
					// Hard limit, just to avoid having downstreams fill our map
					if len(dc.monitored.innerMap) >= 1000 {
						dc.SendMessage(&irc.Message{
							Prefix:  dc.srv.prefix(),
							Command: irc.ERR_MONLISTFULL,
							Params:  []string{dc.nick, "1000", target, "Bouncer monitor list is full"},
						})
						continue
					}

					dc.monitored.SetValue(target, nil)

					if uc.monitored.Has(target) {
						cmd := irc.RPL_MONOFFLINE
						if online := uc.monitored.Value(target); online {
							cmd = irc.RPL_MONONLINE
						}

						dc.SendMessage(&irc.Message{
							Prefix:  dc.srv.prefix(),
							Command: cmd,
							Params:  []string{dc.nick, target},
						})
					}
				} else {
					dc.monitored.Delete(target)
				}
			}
			uc.updateMonitor()
		case "C": // clear
			dc.monitored = newCasemapMap(0)
			uc.updateMonitor()
		case "L": // list
			// TODO: be less lazy and pack the list
			for _, entry := range dc.monitored.innerMap {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_MONLIST,
					Params:  []string{dc.nick, entry.originalKey},
				})
			}
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFMONLIST,
				Params:  []string{dc.nick, "End of MONITOR list"},
			})
		case "S": // status
			// TODO: be less lazy and pack the lists
			for _, entry := range dc.monitored.innerMap {
				target := entry.originalKey

				cmd := irc.RPL_MONOFFLINE
				if online := uc.monitored.Value(target); online {
					cmd = irc.RPL_MONONLINE
				}

				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: cmd,
					Params:  []string{dc.nick, target},
				})
			}
		}
	case "CHATHISTORY":
		var subcommand string
		if err := parseMessageParams(msg, &subcommand); err != nil {
			return err
		}
		var target, limitStr string
		var boundsStr [2]string
		switch subcommand {
		case "AFTER", "BEFORE", "LATEST":
			if err := parseMessageParams(msg, nil, &target, &boundsStr[0], &limitStr); err != nil {
				return err
			}
		case "BETWEEN":
			if err := parseMessageParams(msg, nil, &target, &boundsStr[0], &boundsStr[1], &limitStr); err != nil {
				return err
			}
		case "TARGETS":
			if dc.network == nil {
				// Either an unbound bouncer network, in which case we should return no targets,
				// or a multi-upstream downstream, but we don't support CHATHISTORY TARGETS for those yet.
				dc.SendBatch("draft/chathistory-targets", nil, nil, func(batchRef irc.TagValue) {})
				return nil
			}
			if err := parseMessageParams(msg, nil, &boundsStr[0], &boundsStr[1], &limitStr); err != nil {
				return err
			}
		default:
			// TODO: support AROUND
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "INVALID_PARAMS", subcommand, "Unknown command"},
			}}
		}

		// We don't save history for our service
		if casemapASCII(target) == serviceNickCM {
			dc.SendBatch("chathistory", []string{target}, nil, func(batchRef irc.TagValue) {})
			return nil
		}

		store, ok := dc.user.msgStore.(chatHistoryMessageStore)
		if !ok {
			return ircError{&irc.Message{
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params:  []string{dc.nick, "CHATHISTORY", "Unknown command"},
			}}
		}

		network, entity, err := dc.unmarshalEntityNetwork(target)
		if err != nil {
			return err
		}
		entity = network.casemap(entity)

		// TODO: support msgid criteria
		var bounds [2]time.Time
		bounds[0] = parseChatHistoryBound(boundsStr[0])
		if subcommand == "LATEST" && boundsStr[0] == "*" {
			bounds[0] = time.Now()
		} else if bounds[0].IsZero() {
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
		if err != nil || limit < 0 || limit > chatHistoryLimit {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"CHATHISTORY", "INVALID_PARAMS", subcommand, limitStr, "Invalid limit"},
			}}
		}

		eventPlayback := dc.caps["draft/event-playback"]

		var history []*irc.Message
		switch subcommand {
		case "BEFORE", "LATEST":
			history, err = store.LoadBeforeTime(ctx, &network.Network, entity, bounds[0], time.Time{}, limit, eventPlayback)
		case "AFTER":
			history, err = store.LoadAfterTime(ctx, &network.Network, entity, bounds[0], time.Now(), limit, eventPlayback)
		case "BETWEEN":
			if bounds[0].Before(bounds[1]) {
				history, err = store.LoadAfterTime(ctx, &network.Network, entity, bounds[0], bounds[1], limit, eventPlayback)
			} else {
				history, err = store.LoadBeforeTime(ctx, &network.Network, entity, bounds[0], bounds[1], limit, eventPlayback)
			}
		case "TARGETS":
			// TODO: support TARGETS in multi-upstream mode
			targets, err := store.ListTargets(ctx, &network.Network, bounds[0], bounds[1], limit, eventPlayback)
			if err != nil {
				dc.logger.Printf("failed fetching targets for chathistory: %v", err)
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"CHATHISTORY", "MESSAGE_ERROR", subcommand, "Failed to retrieve targets"},
				}}
			}

			dc.SendBatch("draft/chathistory-targets", nil, nil, func(batchRef irc.TagValue) {
				for _, target := range targets {
					if ch := network.channels.Value(target.Name); ch != nil && ch.Detached {
						continue
					}

					dc.SendMessage(&irc.Message{
						Tags:    irc.Tags{"batch": batchRef},
						Prefix:  dc.srv.prefix(),
						Command: "CHATHISTORY",
						Params:  []string{"TARGETS", target.Name, formatServerTime(target.LatestMessage)},
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
				dc.SendMessage(dc.marshalMessage(msg, network))
			}
		})
	case "READ":
		var target, criteria string
		if err := parseMessageParams(msg, &target); err != nil {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"READ", "NEED_MORE_PARAMS", "Missing parameters"},
			}}
		}
		if len(msg.Params) > 1 {
			criteria = msg.Params[1]
		}

		// We don't save read receipts for our service
		if casemapASCII(target) == serviceNickCM {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.prefix(),
				Command: "READ",
				Params:  []string{target, "*"},
			})
			return nil
		}

		uc, entity, err := dc.unmarshalEntity(target)
		if err != nil {
			return err
		}
		entityCM := uc.network.casemap(entity)

		r, err := dc.srv.db.GetReadReceipt(ctx, uc.network.ID, entityCM)
		if err != nil {
			dc.logger.Printf("failed to get the read receipt for %q: %v", entity, err)
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"READ", "INTERNAL_ERROR", target, "Internal error"},
			}}
		} else if r == nil {
			r = &ReadReceipt{
				Target: entityCM,
			}
		}

		broadcast := false
		if len(criteria) > 0 {
			// TODO: support msgid criteria
			criteriaParts := strings.SplitN(criteria, "=", 2)
			if len(criteriaParts) != 2 || criteriaParts[0] != "timestamp" {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"READ", "INVALID_PARAMS", criteria, "Unknown criteria"},
				}}
			}

			timestamp, err := time.Parse(serverTimeLayout, criteriaParts[1])
			if err != nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"READ", "INVALID_PARAMS", criteria, "Invalid criteria"},
				}}
			}
			now := time.Now()
			if timestamp.After(now) {
				timestamp = now
			}
			if r.Timestamp.Before(timestamp) {
				r.Timestamp = timestamp
				if err := dc.srv.db.StoreReadReceipt(ctx, uc.network.ID, r); err != nil {
					dc.logger.Printf("failed to store receipt for %q: %v", entity, err)
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{"READ", "INTERNAL_ERROR", target, "Internal error"},
					}}
				}
				broadcast = true
			}
		}

		timestampStr := "*"
		if !r.Timestamp.IsZero() {
			timestampStr = fmt.Sprintf("timestamp=%s", formatServerTime(r.Timestamp))
		}
		uc.forEachDownstream(func(d *downstreamConn) {
			if broadcast || dc.id == d.id {
				d.SendMessage(&irc.Message{
					Prefix:  d.prefix(),
					Command: "READ",
					Params:  []string{d.marshalEntity(uc.network, entity), timestampStr},
				})
			}
		})
	case "COMPRESS":
		// handled in dc.conn.ReadMessage() if supported
		if !dc.conn.conn.SupportsCompression() {
			return newUnknownCommandError(msg.Command)
		}
	case "BOUNCER":
		var subcommand string
		if err := parseMessageParams(msg, &subcommand); err != nil {
			return err
		}

		switch strings.ToUpper(subcommand) {
		case "BIND":
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"BOUNCER", "REGISTRATION_IS_COMPLETED", "BIND", "Cannot bind to a network after registration"},
			}}
		case "LISTNETWORKS":
			dc.SendBatch("soju.im/bouncer-networks", nil, nil, func(batchRef irc.TagValue) {
				for _, network := range dc.user.networks {
					idStr := fmt.Sprintf("%v", network.ID)
					attrs := getNetworkAttrs(network)
					dc.SendMessage(&irc.Message{
						Tags:    irc.Tags{"batch": batchRef},
						Prefix:  dc.srv.prefix(),
						Command: "BOUNCER",
						Params:  []string{"NETWORK", idStr, attrs.String()},
					})
				}
			})
		case "ADDNETWORK":
			var attrsStr string
			if err := parseMessageParams(msg, nil, &attrsStr); err != nil {
				return err
			}
			attrs := irc.ParseTags(attrsStr)

			record := &Network{Nick: dc.nick, Enabled: true}
			if err := updateNetworkAttrs(record, attrs, subcommand); err != nil {
				return err
			}

			if record.Nick == dc.user.Username {
				record.Nick = ""
			}
			if record.Realname == dc.user.Realname {
				record.Realname = ""
			}

			network, err := dc.user.createNetwork(ctx, record)
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
			if err := updateNetworkAttrs(&record, attrs, subcommand); err != nil {
				return err
			}

			if record.Nick == dc.user.Username {
				record.Nick = ""
			}
			if record.Realname == dc.user.Realname {
				record.Realname = ""
			}

			_, err = dc.user.updateNetwork(ctx, &record)
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

			if err := dc.user.deleteNetwork(ctx, net.ID); err != nil {
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

		uc.SendMessageLabeled(ctx, dc.id, msg)
	}
	return nil
}

func (dc *downstreamConn) handleNickServPRIVMSG(ctx context.Context, uc *upstreamConn, text string) {
	username, password, ok := parseNickServCredentials(text, uc.nick)
	if ok {
		uc.network.autoSaveSASLPlain(ctx, username, password)
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
