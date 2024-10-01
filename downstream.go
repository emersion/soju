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
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/emersion/go-sasl"
	"gopkg.in/irc.v4"

	"codeberg.org/emersion/soju/auth"
	"codeberg.org/emersion/soju/database"
	"codeberg.org/emersion/soju/msgstore"
	"codeberg.org/emersion/soju/xirc"
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

func newUnknownIRCError(cmd, text string) ircError {
	return ircError{&irc.Message{
		Command: xirc.ERR_UNKNOWNERROR,
		Params:  []string{"*", cmd, text},
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

// authErrorReason returns the user-friendly reason of an authentication
// failure.
func authErrorReason(err error) string {
	if authErr, ok := err.(*auth.Error); ok {
		return authErr.ExternalMsg
	} else {
		return "Authentication failed"
	}
}

func parseBouncerNetID(subcommand, s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return 0, ircError{&irc.Message{
			Command: "FAIL",
			Params:  []string{"BOUNCER", "INVALID_NETID", subcommand, s, "Invalid network ID"},
		}}
	}
	return id, nil
}

func fillNetworkAddrAttrs(attrs irc.Tags, network *database.Network) {
	u, err := network.URL()
	if err != nil {
		return
	}

	hasHostPort := true
	switch u.Scheme {
	case "ircs":
		attrs["tls"] = "1"
	case "irc+insecure":
		attrs["tls"] = "0"
	default: // e.g. unix://
		hasHostPort = false
	}
	if host, port, err := net.SplitHostPort(u.Host); err == nil && hasHostPort {
		attrs["host"] = host
		attrs["port"] = port
	} else if hasHostPort {
		attrs["host"] = u.Host
	}
}

func getNetworkAttrs(network *network) irc.Tags {
	state := "disconnected"
	if uc := network.conn; uc != nil {
		state = "connected"
	}

	attrs := irc.Tags{
		"name":     network.GetName(),
		"state":    state,
		"nickname": database.GetNick(&network.user.User, &network.Network),
	}

	if network.Username != "" {
		attrs["username"] = network.Username
	}
	if realname := database.GetRealname(&network.user.User, &network.Network); realname != "" {
		attrs["realname"] = realname
	}

	if network.lastError != nil {
		attrs["error"] = network.lastError.Error()
	}

	fillNetworkAddrAttrs(attrs, &network.Network)

	return attrs
}

func networkAddrFromAttrs(attrs irc.Tags) string {
	host := string(attrs["host"])
	if host == "" {
		return ""
	}

	addr := host
	if port := string(attrs["port"]); port != "" {
		addr += ":" + port
	}

	if tlsStr := string(attrs["tls"]); tlsStr == "0" {
		addr = "irc+insecure://" + addr
	}

	return addr
}

func updateNetworkAttrs(record *database.Network, attrs irc.Tags, subcommand string) error {
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

// illegalNickChars is the list of characters forbidden in a nickname.
//
//   - ' ' and ':' break the IRC message wire format
//   - '@' and '!' break prefixes
//   - '*' breaks masks and is the reserved nickname for registration
//   - '?' breaks masks
//   - '$' breaks server masks in PRIVMSG/NOTICE
//   - ',' breaks lists
//   - '.' is reserved for server names
//
// See https://modern.ircdocs.horse/#clients
const illegalNickChars = " :@!*?$,."

// illegalChanChars is the list of characters forbidden in a channel name.
//
// See https://modern.ircdocs.horse/#channels
const illegalChanChars = " ,\x07"

// permanentDownstreamCaps is the list of always-supported downstream
// capabilities.
var permanentDownstreamCaps = map[string]string{
	"batch":         "",
	"cap-notify":    "",
	"echo-message":  "",
	"invite-notify": "",
	"server-time":   "",
	"setname":       "",

	"draft/pre-away":          "",
	"draft/read-marker":       "",
	"draft/no-implicit-names": "",

	"soju.im/account-required":        "",
	"soju.im/bouncer-networks":        "",
	"soju.im/bouncer-networks-notify": "",
	"soju.im/no-implicit-names":       "",
	"soju.im/read":                    "",
	"soju.im/webpush":                 "",
}

// needAllDownstreamCaps is the list of downstream capabilities that
// require support from all upstreams to be enabled.
var needAllDownstreamCaps = map[string]string{
	"account-notify":   "",
	"account-tag":      "",
	"away-notify":      "",
	"chghost":          "",
	"extended-join":    "",
	"extended-monitor": "",
	"message-tags":     "",
	"multi-prefix":     "",

	"draft/extended-monitor": "",
}

// passthroughIsupport is the set of ISUPPORT tokens that are directly passed
// through from the upstream server to downstream clients.
var passthroughIsupport = map[string]bool{
	"ACCOUNTEXTBAN": true,
	"AWAYLEN":       true,
	"BOT":           true,
	"CASEMAPPING":   true,
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
	"LINELEN":       true,
	"MAXLIST":       true,
	"MAXTARGETS":    true,
	"MODES":         true,
	"MONITOR":       true,
	"NAMELEN":       true,
	"NETWORK":       true,
	"NICKLEN":       true,
	"PREFIX":        true,
	"SAFELIST":      true,
	"STATUSMSG":     true,
	"TARGMAX":       true,
	"TOPICLEN":      true,
	"USERLEN":       true,
	"UTF8ONLY":      true,
	"WHOX":          true,
}

type saslPlain struct {
	Identity, Username, Password string
}

type downstreamSASL struct {
	server      sasl.Server
	mechanism   string
	plain       *saslPlain
	oauthBearer *sasl.OAuthBearerOptions
	pendingResp bytes.Buffer
}

type downstreamRegistration struct {
	nick     string
	username string
	pass     string

	networkName string
	networkID   int64

	negotiatingCaps bool

	authUsername string
}

func serverSASLMechanisms(srv *Server) []string {
	var l []string
	if _, ok := srv.Config().Auth.(auth.PlainAuthenticator); ok {
		l = append(l, "PLAIN")
	}
	if _, ok := srv.Config().Auth.(auth.OAuthBearerAuthenticator); ok {
		l = append(l, "OAUTHBEARER")
	}
	return l
}

type downstreamConn struct {
	*conn

	id uint64

	// These don't change after connection registration
	registered    bool
	user          *user
	network       *network // can be nil
	clientName    string
	impersonating bool

	nick     string
	nickCM   string
	realname string
	username string
	hostname string
	account  string // RPL_LOGGEDIN/OUT state
	away     *string

	capVersion   int
	caps         xirc.CapRegistry
	sasl         *downstreamSASL         // nil unless SASL is underway
	registration *downstreamRegistration // nil after RPL_WELCOME

	lastBatchRef uint64

	casemap   xirc.CaseMapping
	monitored xirc.CaseMappingMap[struct{}]
}

func newDownstreamConn(srv *Server, ic ircConn, id uint64) *downstreamConn {
	remoteAddr := ic.RemoteAddr().String()
	logger := &prefixLogger{srv.Logger, fmt.Sprintf("downstream %q: ", remoteAddr)}
	options := connOptions{Logger: logger}
	cm := xirc.CaseMappingASCII
	dc := &downstreamConn{
		conn:         newConn(srv, ic, &options),
		id:           id,
		nick:         "*",
		nickCM:       "*",
		username:     "~u",
		caps:         xirc.NewCapRegistry(),
		casemap:      cm,
		monitored:    xirc.NewCaseMappingMap[struct{}](cm),
		registration: new(downstreamRegistration),
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		dc.hostname = host
	} else {
		dc.hostname = remoteAddr
	}
	for k, v := range permanentDownstreamCaps {
		dc.caps.Available[k] = v
	}
	dc.caps.Available["sasl"] = strings.Join(serverSASLMechanisms(dc.srv), ",")
	// TODO: this is racy, we should only enable chathistory after
	// authentication and then check that user.msgStore implements
	// chatHistoryMessageStore
	switch srv.Config().MsgStoreDriver {
	case "fs", "db":
		dc.caps.Available["draft/chathistory"] = ""
		dc.caps.Available["soju.im/search"] = ""
	}
	return dc
}

func (dc *downstreamConn) prefix() *irc.Prefix {
	return &irc.Prefix{
		Name: dc.nick,
		User: dc.username,
		Host: dc.hostname,
	}
}

func (dc *downstreamConn) forEachNetwork(f func(*network)) {
	if dc.network != nil {
		f(dc.network)
	}
}

func (dc *downstreamConn) forEachUpstream(f func(*upstreamConn)) {
	if dc.network == nil {
		return
	}
	dc.user.forEachUpstream(func(uc *upstreamConn) {
		if dc.network != nil && uc.network != dc.network {
			return
		}
		f(uc)
	})
}

// upstream returns the upstream connection, if any. If there are zero upstream
// connections, it returns nil.
func (dc *downstreamConn) upstream() *upstreamConn {
	if dc.network == nil {
		return nil
	}
	return dc.network.conn
}

func (dc *downstreamConn) upstreamForCommand(cmd string) (*upstreamConn, error) {
	if dc.network == nil {
		return nil, newUnknownIRCError(cmd, "Cannot interact with channels and users on the bouncer connection. Did you mean to use a specific network?")
	}
	if dc.network.conn == nil {
		return nil, newUnknownIRCError(cmd, "Disconnected from upstream network")
	}
	return dc.network.conn, nil
}

func isOurNick(net *network, nick string) bool {
	// TODO: this doesn't account for nick changes
	if net.conn != nil {
		return net.conn.isOurNick(nick)
	}
	// We're not currently connected to the upstream connection, so we don't
	// know whether this name is our nickname. Best-effort: use the network's
	// configured nickname and hope it was the one being used when we were
	// connected.
	return net.casemap(nick) == net.casemap(database.GetNick(&net.user.User, &net.Network))
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
func (dc *downstreamConn) SendMessage(ctx context.Context, msg *irc.Message) {
	if !dc.caps.IsEnabled("message-tags") {
		if msg.Command == "TAGMSG" {
			return
		}
		msg = msg.Copy()
		for name := range msg.Tags {
			supported := false
			switch name {
			case "time":
				supported = dc.caps.IsEnabled("server-time")
			case "account":
				supported = dc.caps.IsEnabled("account-tag")
			case "batch":
				supported = dc.caps.IsEnabled("batch")
			}
			if !supported {
				delete(msg.Tags, name)
			}
		}
	}
	if !dc.caps.IsEnabled("batch") && msg.Tags["batch"] != "" {
		msg = msg.Copy()
		delete(msg.Tags, "batch")
	}
	if msg.Command == "JOIN" && !dc.caps.IsEnabled("extended-join") {
		msg = msg.Copy()
		msg.Params = msg.Params[:1]
	}
	if msg.Command == "SETNAME" && !dc.caps.IsEnabled("setname") {
		return
	}
	if msg.Command == "CHGHOST" && !dc.caps.IsEnabled("chghost") {
		return
	}
	if msg.Command == "AWAY" && !dc.caps.IsEnabled("away-notify") {
		return
	}
	if msg.Command == "ACCOUNT" && !dc.caps.IsEnabled("account-notify") {
		return
	}
	if msg.Command == "MARKREAD" && !dc.caps.IsEnabled("draft/read-marker") {
		return
	}
	if msg.Command == "READ" && !dc.caps.IsEnabled("soju.im/read") {
		return
	}
	if msg.Prefix != nil && msg.Prefix.Name == "*" {
		// We use "*" as a sentinel value to simplify upstream message handling
		msgCopy := *msg
		msg = &msgCopy
		msg.Prefix = nil
	}
	if msg.Prefix == nil && isNumeric(msg.Command) {
		// Numerics must always carry a source
		msgCopy := *msg
		msg = &msgCopy
		msg.Prefix = dc.srv.prefix()
	}

	dc.srv.metrics.downstreamOutMessagesTotal.Inc()
	dc.conn.SendMessage(ctx, msg)
}

func (dc *downstreamConn) SendBatch(ctx context.Context, typ string, params []string, tags irc.Tags, f func(batchRef string)) {
	dc.lastBatchRef++
	ref := fmt.Sprintf("%v", dc.lastBatchRef)

	if dc.caps.IsEnabled("batch") {
		dc.SendMessage(ctx, &irc.Message{
			Tags:    tags,
			Command: "BATCH",
			Params:  append([]string{"+" + ref, typ}, params...),
		})
	}

	f(ref)

	if dc.caps.IsEnabled("batch") {
		dc.SendMessage(ctx, &irc.Message{
			Command: "BATCH",
			Params:  []string{"-" + ref},
		})
	}
}

// sendMessageWithID sends an outgoing message with the specified internal ID.
func (dc *downstreamConn) sendMessageWithID(ctx context.Context, msg *irc.Message, id string) {
	dc.SendMessage(ctx, msg)

	if id == "" || !dc.messageSupportsBacklog(msg) || dc.caps.IsEnabled("draft/chathistory") {
		return
	}

	dc.sendPing(ctx, id)
}

// advanceMessageWithID advances history to the specified message ID without
// sending a message. This is useful e.g. for self-messages when echo-message
// isn't enabled.
func (dc *downstreamConn) advanceMessageWithID(ctx context.Context, msg *irc.Message, id string) {
	if id == "" || !dc.messageSupportsBacklog(msg) || dc.caps.IsEnabled("draft/chathistory") {
		return
	}

	dc.sendPing(ctx, id)
}

// ackMsgID acknowledges that a message has been received.
func (dc *downstreamConn) ackMsgID(id string) {
	netID, entity, err := msgstore.ParseMsgID(id, nil)
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

func (dc *downstreamConn) sendPing(ctx context.Context, msgID string) {
	token := "soju-msgid-" + msgID
	dc.SendMessage(ctx, &irc.Message{
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

func (dc *downstreamConn) handleMessage(ctx context.Context, msg *irc.Message) error {
	ctx, cancel := dc.conn.NewContext(ctx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, handleDownstreamMessageTimeout)
	defer cancel()

	switch msg.Command {
	case "QUIT":
		dc.conn.Shutdown(ctx)
		return nil // TODO: stop handling commands
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
		if err := parseMessageParams(msg, &dc.registration.nick); err != nil {
			return err
		}
	case "USER":
		if err := parseMessageParams(msg, &dc.registration.username, nil, nil, nil); err != nil {
			return err
		}
	case "PASS":
		if err := parseMessageParams(msg, &dc.registration.pass); err != nil {
			return err
		}
	case "CAP":
		return dc.handleCap(ctx, msg)
	case "AUTHENTICATE":
		credentials, err := dc.handleAuthenticate(ctx, msg)
		if err != nil {
			return err
		} else if credentials == nil {
			break
		}

		var username, clientName, networkName string
		var impersonating bool
		switch credentials.mechanism {
		case "PLAIN":
			username, clientName, networkName = unmarshalUsername(credentials.plain.Username)
			password := credentials.plain.Password

			auth, ok := dc.srv.Config().Auth.(auth.PlainAuthenticator)
			if !ok {
				err = fmt.Errorf("SASL PLAIN not supported")
				break
			}

			if err = auth.AuthPlain(ctx, dc.srv.db, username, password); err != nil {
				err = fmt.Errorf("%v (username %q)", err, username)
				break
			}

			if credentials.plain.Identity != "" && credentials.plain.Identity != username {
				var u *database.User
				u, err = dc.srv.db.GetUser(ctx, username)
				if err != nil {
					err = fmt.Errorf("%v (username %q)", err, username)
					break
				}
				if !u.Admin {
					err = fmt.Errorf("SASL impersonation only allowed for admin users")
					break
				}
				username, clientName, networkName = unmarshalUsername(credentials.plain.Identity)
				if _, err = dc.srv.db.GetUser(ctx, username); err != nil {
					err = fmt.Errorf("%v (username %q)", err, username)
					break
				}
				impersonating = true
			}
		case "OAUTHBEARER":
			auth, ok := dc.srv.Config().Auth.(auth.OAuthBearerAuthenticator)
			if !ok {
				err = fmt.Errorf("SASL OAUTHBEARER not supported")
				break
			}

			username, err = auth.AuthOAuthBearer(ctx, dc.srv.db, credentials.oauthBearer.Token)
			if err != nil {
				break
			}

			if credentials.oauthBearer.Username != "" && credentials.oauthBearer.Username != username {
				err = fmt.Errorf("username mismatch (client provided %q, but server returned %q)", credentials.oauthBearer.Username, username)
				break
			}
		default:
			err = fmt.Errorf("unsupported SASL mechanism")
		}

		if err != nil {
			dc.logger.Printf("SASL %v authentication error for nick %q: %v", credentials.mechanism, dc.registration.nick, err)
			dc.endSASL(ctx, &irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, authErrorReason(err)},
			})
			break
		}

		if username == "" {
			panic(fmt.Errorf("username unset after SASL authentication"))
		}
		dc.setAuthUsername(username, clientName, networkName)
		dc.impersonating = impersonating

		// Technically we should send RPL_LOGGEDIN here. However we use
		// RPL_LOGGEDIN to mirror the upstream connection status. Let's
		// see how many clients that breaks. See:
		// https://github.com/ircv3/ircv3-specifications/pull/476
		dc.endSASL(ctx, nil)
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

			if dc.registration.authUsername == "" {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "ACCOUNT_REQUIRED", "BIND", "Authentication needed to bind to bouncer network"},
				}}
			}

			id, err := parseBouncerNetID(subcommand, idStr)
			if err != nil {
				return err
			}

			dc.registration.networkID = id
		default:
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"BOUNCER", "UNKNOWN_COMMAND", subcommand, "Unknown subcommand"},
			}}
		}
	case "AWAY":
		if len(msg.Params) > 0 {
			dc.away = &msg.Params[0]
		} else {
			dc.away = nil
		}

		dc.SendMessage(ctx, generateAwayReply(dc.away != nil))
	default:
		dc.logger.Debugf("unhandled message: %v", msg)
		return newUnknownCommandError(msg.Command)
	}
	return nil
}

func (dc *downstreamConn) handleCap(ctx context.Context, msg *irc.Message) error {
	var cmd string
	if err := parseMessageParams(msg, &cmd); err != nil {
		return err
	}
	args := msg.Params[1:]

	switch cmd = strings.ToUpper(cmd); cmd {
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
				dc.caps.Available[k] = v
			}
		}

		caps := make([]string, 0, len(dc.caps.Available))
		for k, v := range dc.caps.Available {
			if dc.capVersion >= 302 && v != "" {
				caps = append(caps, k+"="+v)
			} else {
				caps = append(caps, k)
			}
		}

		// TODO: multi-line replies
		dc.SendMessage(ctx, &irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "CAP",
			Params:  []string{dc.nick, "LS", strings.Join(caps, " ")},
		})

		if dc.capVersion >= 302 {
			// CAP version 302 implicitly enables cap-notify
			dc.caps.SetEnabled("cap-notify", true)
		}

		if !dc.registered {
			dc.registration.negotiatingCaps = true
		}
	case "LIST":
		var caps []string
		for name := range dc.caps.Enabled {
			caps = append(caps, name)
		}

		// TODO: multi-line replies
		dc.SendMessage(ctx, &irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "CAP",
			Params:  []string{dc.nick, "LIST", strings.Join(caps, " ")},
		})
	case "REQ":
		if len(args) == 0 {
			return ircError{&irc.Message{
				Command: xirc.ERR_INVALIDCAPCMD,
				Params:  []string{dc.nick, cmd, "Missing argument in CAP REQ command"},
			}}
		}

		caps := strings.Fields(args[0])
		ack := true
		m := make(map[string]bool, len(caps))
		for _, name := range caps {
			name = strings.ToLower(name)
			enable := !strings.HasPrefix(name, "-")
			if !enable {
				name = strings.TrimPrefix(name, "-")
			}

			if enable == dc.caps.IsEnabled(name) {
				continue
			}

			if !dc.caps.IsAvailable(name) {
				ack = false
				break
			}

			if name == "cap-notify" && dc.capVersion >= 302 && !enable {
				// cap-notify cannot be disabled with CAP version 302
				ack = false
				break
			}

			if name == "soju.im/account-required" {
				// account-required is an informational cap
				ack = false
				break
			}

			m[name] = enable
		}

		// Atomically ack the whole capability set
		if ack {
			for name, enable := range m {
				dc.caps.SetEnabled(name, enable)
			}
		}

		reply := "NAK"
		if ack {
			reply = "ACK"
		}
		dc.SendMessage(ctx, &irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: "CAP",
			Params:  []string{dc.nick, reply, args[0]},
		})

		if !dc.registered {
			dc.registration.negotiatingCaps = true
		}
	case "END":
		if !dc.registered {
			dc.registration.negotiatingCaps = false
		}
	default:
		return ircError{&irc.Message{
			Command: xirc.ERR_INVALIDCAPCMD,
			Params:  []string{dc.nick, cmd, "Unknown CAP command"},
		}}
	}
	return nil
}

func (dc *downstreamConn) handleAuthenticate(ctx context.Context, msg *irc.Message) (result *downstreamSASL, err error) {
	defer func() {
		if err != nil {
			dc.sasl = nil
		}
	}()

	if !dc.caps.IsEnabled("sasl") {
		return nil, ircError{&irc.Message{
			Command: irc.ERR_SASLFAIL,
			Params:  []string{dc.nick, "AUTHENTICATE requires the \"sasl\" capability to be enabled"},
		}}
	}
	if len(msg.Params) == 0 {
		return nil, ircError{&irc.Message{
			Command: irc.ERR_SASLFAIL,
			Params:  []string{dc.nick, "Missing AUTHENTICATE argument"},
		}}
	}
	if msg.Params[0] == "*" {
		return nil, ircError{&irc.Message{
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
				dc.sasl.plain = &saslPlain{
					Identity: identity,
					Username: username,
					Password: password,
				}
				return nil
			}))
		case "OAUTHBEARER":
			server = sasl.NewOAuthBearerServer(sasl.OAuthBearerAuthenticator(func(options sasl.OAuthBearerOptions) *sasl.OAuthBearerError {
				dc.sasl.oauthBearer = &options
				return nil
			}))
		case "ANONYMOUS":
			server = sasl.NewAnonymousServer(func(trace string) error {
				return nil
			})
		default:
			return nil, ircError{&irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, "Unsupported SASL mechanism"},
			}}
		}

		dc.sasl = &downstreamSASL{server: server, mechanism: mech}
	} else {
		chunk := msg.Params[0]
		if chunk == "+" {
			chunk = ""
		}

		if dc.sasl.pendingResp.Len()+len(chunk) > 10*1024 {
			return nil, ircError{&irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, "Response too long"},
			}}
		}

		dc.sasl.pendingResp.WriteString(chunk)

		if len(chunk) == xirc.MaxSASLLength {
			return nil, nil // Multi-line response, wait for the next command
		}

		resp, err = base64.StdEncoding.DecodeString(dc.sasl.pendingResp.String())
		if err != nil {
			return nil, ircError{&irc.Message{
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
		dc.SendMessage(ctx, &irc.Message{
			Command: "AUTHENTICATE",
			Params:  []string{challengeStr},
		})
		return nil, nil
	}
}

func (dc *downstreamConn) endSASL(ctx context.Context, msg *irc.Message) {
	if dc.sasl == nil {
		return
	}

	dc.sasl = nil

	if msg != nil {
		dc.SendMessage(ctx, msg)
	} else {
		dc.SendMessage(ctx, &irc.Message{
			Command: irc.RPL_SASLSUCCESS,
			Params:  []string{dc.nick, "SASL authentication successful"},
		})
	}
}

func (dc *downstreamConn) setSupportedCap(ctx context.Context, name, value string) {
	prevValue, hasPrev := dc.caps.Available[name]
	changed := !hasPrev || prevValue != value
	dc.caps.Available[name] = value

	if !dc.caps.IsEnabled("cap-notify") || !changed {
		return
	}

	cap := name
	if value != "" && dc.capVersion >= 302 {
		cap = name + "=" + value
	}

	dc.SendMessage(ctx, &irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: "CAP",
		Params:  []string{dc.nick, "NEW", cap},
	})
}

func (dc *downstreamConn) unsetSupportedCap(ctx context.Context, name string) {
	hasPrev := dc.caps.IsAvailable(name)
	dc.caps.Del(name)

	if !dc.caps.IsEnabled("cap-notify") || !hasPrev {
		return
	}

	dc.SendMessage(ctx, &irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: "CAP",
		Params:  []string{dc.nick, "DEL", name},
	})
}

func (dc *downstreamConn) updateSupportedCaps(ctx context.Context) {
	supportedCaps := make(map[string]bool)
	for cap := range needAllDownstreamCaps {
		supportedCaps[cap] = true
	}
	dc.forEachUpstream(func(uc *upstreamConn) {
		for cap, supported := range supportedCaps {
			supportedCaps[cap] = supported && uc.caps.IsEnabled(cap)
		}
	})

	for cap, supported := range supportedCaps {
		if supported {
			dc.setSupportedCap(ctx, cap, needAllDownstreamCaps[cap])
		} else {
			dc.unsetSupportedCap(ctx, cap)
		}
	}

	if uc := dc.upstream(); uc != nil && uc.supportsSASL("PLAIN") {
		dc.setSupportedCap(ctx, "sasl", "PLAIN,ANONYMOUS")
	} else if dc.network != nil {
		dc.unsetSupportedCap(ctx, "sasl")
	}

	if uc := dc.upstream(); uc != nil && uc.caps.IsEnabled("draft/account-registration") {
		// Strip "before-connect", because we require downstreams to be fully
		// connected before attempting account registration.
		values := strings.Split(uc.caps.Available["draft/account-registration"], ",")
		for i, v := range values {
			if v == "before-connect" {
				values = append(values[:i], values[i+1:]...)
				break
			}
		}
		dc.setSupportedCap(ctx, "draft/account-registration", strings.Join(values, ","))
	} else {
		dc.unsetSupportedCap(ctx, "draft/account-registration")
	}

	if _, ok := dc.user.msgStore.(msgstore.ChatHistoryStore); ok && dc.network != nil {
		dc.setSupportedCap(ctx, "draft/event-playback", "")
	} else {
		dc.unsetSupportedCap(ctx, "draft/event-playback")
	}
}

func (dc *downstreamConn) updateNick(ctx context.Context) {
	var nick string
	if uc := dc.upstream(); uc != nil {
		nick = uc.nick
	} else if dc.network != nil {
		nick = database.GetNick(&dc.user.User, &dc.network.Network)
	} else {
		nick = database.GetNick(&dc.user.User, nil)
	}

	if nick == dc.nick {
		return
	}

	dc.SendMessage(ctx, &irc.Message{
		Prefix:  dc.prefix(),
		Command: "NICK",
		Params:  []string{nick},
	})
	dc.nick = nick
	dc.nickCM = dc.casemap(dc.nick)
}

func (dc *downstreamConn) updateHost(ctx context.Context) {
	uc := dc.upstream()
	if uc == nil || uc.hostname == "" {
		return
	}

	if uc.hostname == dc.hostname && uc.username == dc.username {
		return
	}

	if dc.caps.IsEnabled("chghost") {
		dc.SendMessage(ctx, &irc.Message{
			Prefix:  dc.prefix(),
			Command: "CHGHOST",
			Params:  []string{uc.username, uc.hostname},
		})
	} else if uc.hostname != dc.hostname {
		dc.SendMessage(ctx, &irc.Message{
			Prefix:  dc.prefix(),
			Command: xirc.RPL_VISIBLEHOST,
			Params:  []string{dc.nick, uc.hostname, "is now your visible host"},
		})
	}

	dc.hostname = uc.hostname
	dc.username = uc.username
}

func (dc *downstreamConn) updateRealname(ctx context.Context) {
	if !dc.caps.IsEnabled("setname") {
		return
	}

	var realname string
	if uc := dc.upstream(); uc != nil {
		realname = uc.realname
	} else if dc.network != nil {
		realname = database.GetRealname(&dc.user.User, &dc.network.Network)
	} else {
		realname = database.GetRealname(&dc.user.User, nil)
	}

	if realname != dc.realname {
		dc.SendMessage(ctx, &irc.Message{
			Prefix:  dc.prefix(),
			Command: "SETNAME",
			Params:  []string{realname},
		})
		dc.realname = realname
	}
}

func (dc *downstreamConn) updateAccount(ctx context.Context) {
	var account string
	if dc.network == nil {
		account = dc.user.Username
	} else if uc := dc.upstream(); uc != nil {
		account = uc.account
	} else {
		return
	}

	if dc.account == account || !dc.caps.IsEnabled("sasl") {
		return
	}

	if account != "" {
		dc.SendMessage(ctx, &irc.Message{
			Command: irc.RPL_LOGGEDIN,
			Params:  []string{dc.nick, dc.prefix().String(), account, "You are logged in as " + account},
		})
	} else {
		dc.SendMessage(ctx, &irc.Message{
			Command: irc.RPL_LOGGEDOUT,
			Params:  []string{dc.nick, dc.prefix().String(), "You are logged out"},
		})
	}

	dc.account = account
}

func (dc *downstreamConn) updateCasemapping() {
	cm := xirc.CaseMappingASCII
	if dc.network != nil {
		cm = dc.network.casemap
	}

	dc.casemap = cm
	dc.nickCM = cm(dc.nick)
	dc.monitored.SetCaseMapping(cm)
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

func (dc *downstreamConn) setAuthUsername(username, clientName, networkName string) {
	dc.clientName = clientName
	dc.registration.authUsername = username
	dc.registration.networkName = networkName
}

func (dc *downstreamConn) register(ctx context.Context) error {
	if dc.registered {
		panic("tried to register twice")
	}

	if dc.sasl != nil {
		dc.endSASL(ctx, &irc.Message{
			Command: irc.ERR_SASLABORTED,
			Params:  []string{dc.nick, "SASL authentication aborted"},
		})
	}

	password := dc.registration.pass
	dc.registration.pass = ""
	if dc.registration.authUsername == "" {
		if password == "" {
			if dc.caps.IsEnabled("sasl") {
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

		plainAuth, ok := dc.srv.Config().Auth.(auth.PlainAuthenticator)
		if !ok {
			return ircError{&irc.Message{
				Command: irc.ERR_PASSWDMISMATCH,
				Params:  []string{dc.nick, "PASS authentication disabled"},
			}}
		}

		username, clientName, networkName := unmarshalUsername(dc.registration.username)
		if err := plainAuth.AuthPlain(ctx, dc.srv.db, username, password); err != nil {
			dc.logger.Printf("PASS authentication error for user %q: %v", dc.registration.username, err)
			return ircError{&irc.Message{
				Command: irc.ERR_PASSWDMISMATCH,
				Params:  []string{dc.nick, authErrorReason(err)},
			}}
		}

		dc.setAuthUsername(username, clientName, networkName)
	}

	_, fallbackClientName, fallbackNetworkName := unmarshalUsername(dc.registration.username)
	if dc.clientName == "" {
		dc.clientName = fallbackClientName
	} else if fallbackClientName != "" && dc.clientName != fallbackClientName {
		return ircError{&irc.Message{
			Command: irc.ERR_ERRONEUSNICKNAME,
			Params:  []string{dc.nick, "Client name mismatch in usernames"},
		}}
	}

	if dc.registration.networkName == "" {
		dc.registration.networkName = fallbackNetworkName
	} else if fallbackNetworkName != "" && dc.registration.networkName != fallbackNetworkName {
		return ircError{&irc.Message{
			Command: irc.ERR_ERRONEUSNICKNAME,
			Params:  []string{dc.nick, "Network name mismatch in usernames"},
		}}
	}

	dc.registered = true
	dc.username = dc.registration.authUsername
	dc.logger.Printf("registration complete for user %q", dc.username)
	return nil
}

func (dc *downstreamConn) loadNetwork(ctx context.Context) error {
	if id := dc.registration.networkID; id != 0 {
		network := dc.user.getNetworkByID(id)
		if network == nil {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"BOUNCER", "INVALID_NETID", fmt.Sprintf("%v", id), "Unknown network ID"},
			}}
		}
		dc.network = network
		return nil
	}

	if dc.registration.networkName == "*" {
		return ircError{&irc.Message{
			Command: irc.ERR_PASSWDMISMATCH,
			Params:  []string{dc.nick, fmt.Sprintf("Multi-upstream mode is no longer supported")},
		}}
	}

	if dc.registration.networkName == "" {
		return nil
	}

	network := dc.user.getNetwork(dc.registration.networkName)
	if network == nil {
		addr := dc.registration.networkName
		if !strings.ContainsRune(addr, ':') {
			addr = addr + ":6697"
		}

		dc.logger.Printf("trying to connect to new network %q", addr)
		if err := sanityCheckServer(ctx, addr); err != nil {
			dc.logger.Printf("failed to connect to %q: %v", addr, err)
			return ircError{&irc.Message{
				Command: irc.ERR_PASSWDMISMATCH,
				Params:  []string{dc.nick, fmt.Sprintf("Failed to connect to %q", dc.registration.networkName)},
			}}
		}

		// Some clients only allow specifying the nickname (and use the
		// nickname as a username too). Strip the network name from the
		// nickname when auto-saving networks.
		nick, _, _ := unmarshalUsername(dc.registration.nick)
		if nick == "" || strings.ContainsAny(nick, illegalNickChars) {
			return ircError{&irc.Message{
				Command: irc.ERR_ERRONEUSNICKNAME,
				Params:  []string{dc.nick, dc.registration.nick, "Nickname contains illegal characters"},
			}}
		}
		if xirc.CaseMappingASCII(nick) == serviceNickCM {
			return ircError{&irc.Message{
				Command: irc.ERR_NICKNAMEINUSE,
				Params:  []string{dc.nick, dc.registration.nick, "Nickname reserved for bouncer service"},
			}}
		}

		record := database.NewNetwork(dc.registration.networkName)
		record.Nick = nick

		dc.logger.Printf("auto-saving network %q", dc.registration.networkName)
		var err error
		network, err = dc.user.createNetwork(ctx, record, true)
		if err != nil {
			return err
		}
	}

	dc.network = network
	return nil
}

func (dc *downstreamConn) welcome(ctx context.Context, user *user) error {
	if !dc.registered {
		panic("tried to welcome an unregistered connection")
	}
	if dc.user != nil {
		panic("tried to welcome the same connection twice")
	}

	dc.user = user

	remoteAddr := dc.conn.RemoteAddr().String()
	dc.logger = &prefixLogger{dc.srv.Logger, fmt.Sprintf("user %q: downstream %q: ", dc.user.Username, remoteAddr)}

	// TODO: doing this might take some time. We should do it in dc.register
	// instead, but we'll potentially be adding a new network and this must be
	// done in the user goroutine.
	if err := dc.loadNetwork(ctx); err != nil {
		return err
	}

	dc.registration = nil

	dc.updateSupportedCaps(ctx)

	if uc := dc.upstream(); uc != nil {
		dc.nick = uc.nick
	} else if dc.network != nil {
		dc.nick = database.GetNick(&dc.user.User, &dc.network.Network)
	} else {
		dc.nick = dc.user.Username
	}
	dc.nickCM = dc.casemap(dc.nick)

	var isupport []string
	if dc.network != nil {
		isupport = append(isupport, fmt.Sprintf("BOUNCER_NETID=%v", dc.network.ID))
	} else {
		isupport = append(isupport, "BOT=B", "CASEMAPPING=ascii")
	}
	if title := dc.srv.Config().Title; dc.network == nil && title != "" {
		isupport = append(isupport, "NETWORK="+title)
	}
	if dc.network == nil {
		isupport = append(isupport, "WHOX")
		isupport = append(isupport, "CHANTYPES=") // channels are not supported
	}
	if _, ok := dc.user.msgStore.(msgstore.ChatHistoryStore); ok && dc.network != nil {
		isupport = append(isupport, fmt.Sprintf("CHATHISTORY=%v", chatHistoryLimit))
		isupport = append(isupport, "MSGREFTYPES=timestamp")
	}
	if dc.caps.IsEnabled("soju.im/webpush") {
		isupport = append(isupport, "VAPID="+dc.srv.webPush.VAPIDKeys.Public)
	}
	if dc.srv.Config().FileUploader != nil {
		isupport = append(isupport, "soju.im/FILEHOST="+dc.srv.Config().HTTPIngress+"/uploads")
	}

	if uc := dc.upstream(); uc != nil {
		// If upstream doesn't support message-tags, indicate that we'll drop
		// all of them
		if _, ok := uc.isupport["CLIENTTAGDENY"]; !ok && !uc.caps.IsEnabled("message-tags") {
			isupport = append(isupport, "CLIENTTAGDENY=*")
		}

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

	dc.SendMessage(ctx, &irc.Message{
		Command: irc.RPL_WELCOME,
		Params:  []string{dc.nick, "Welcome to soju, " + dc.nick},
	})
	dc.SendMessage(ctx, &irc.Message{
		Command: irc.RPL_YOURHOST,
		Params:  []string{dc.nick, "Your host is " + dc.srv.Config().Hostname},
	})
	dc.SendMessage(ctx, &irc.Message{
		Command: irc.RPL_MYINFO,
		Params:  []string{dc.nick, dc.srv.Config().Hostname, "soju", "aiwroO", "OovaimnqpsrtklbeI"},
	})
	for _, msg := range xirc.GenerateIsupport(isupport) {
		dc.SendMessage(ctx, msg)
	}
	if uc := dc.upstream(); uc != nil {
		dc.SendMessage(ctx, &irc.Message{
			Command: irc.RPL_UMODEIS,
			Params:  []string{dc.nick, "+" + string(uc.modes)},
		})
	}
	if dc.network == nil && dc.user.Admin {
		dc.SendMessage(ctx, &irc.Message{
			Command: irc.RPL_UMODEIS,
			Params:  []string{dc.nick, "+o"},
		})
	}

	dc.updateHost(ctx)
	dc.updateRealname(ctx)
	dc.updateAccount(ctx)
	dc.updateCasemapping()

	if motd := dc.user.srv.Config().MOTD; motd != "" && dc.network == nil {
		for _, msg := range xirc.GenerateMOTD(motd) {
			dc.SendMessage(ctx, msg)
		}
	} else {
		motdHint := "No MOTD"
		if dc.network != nil {
			motdHint = "Use /motd to read the message of the day"
		}
		dc.SendMessage(ctx, &irc.Message{
			Command: irc.ERR_NOMOTD,
			Params:  []string{dc.nick, motdHint},
		})
	}

	if dc.caps.IsEnabled("soju.im/bouncer-networks-notify") {
		dc.SendBatch(ctx, "soju.im/bouncer-networks", nil, nil, func(batchRef string) {
			for _, network := range dc.user.networks {
				idStr := fmt.Sprintf("%v", network.ID)
				attrs := getNetworkAttrs(network)
				dc.SendMessage(ctx, &irc.Message{
					Tags:    irc.Tags{"batch": batchRef},
					Command: "BOUNCER",
					Params:  []string{"NETWORK", idStr, attrs.String()},
				})
			}
		})
	}

	dc.forEachUpstream(func(uc *upstreamConn) {
		uc.channels.ForEach(func(_ string, ch *upstreamChannel) {
			if !ch.complete {
				return
			}
			record := uc.network.channels.Get(ch.Name)
			if record != nil && record.Detached {
				return
			}

			dc.SendMessage(ctx, &irc.Message{
				Prefix:  dc.prefix(),
				Command: "JOIN",
				Params:  []string{ch.Name},
			})

			forwardChannel(ctx, dc, ch)
		})
	})

	dc.forEachNetwork(func(net *network) {
		if dc.caps.IsEnabled("draft/chathistory") || dc.user.msgStore == nil {
			return
		}

		// Only send history if we're the first connected client with that name
		// for the network
		firstClient := true
		for _, c := range dc.user.downstreamConns {
			if c != dc && c.clientName == dc.clientName && c.network == dc.network {
				firstClient = false
			}
		}
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
	if dc.caps.IsEnabled("draft/chathistory") || dc.user.msgStore == nil {
		return
	}

	ch := net.channels.Get(target)

	ctx, cancel := context.WithTimeout(ctx, backlogTimeout)
	defer cancel()

	targetCM := net.casemap(target)
	loadOptions := msgstore.LoadMessageOptions{
		Network: &net.Network,
		Entity:  targetCM,
		Limit:   backlogLimit,
	}
	history, err := dc.user.msgStore.LoadLatestID(ctx, msgID, &loadOptions)
	if err != nil {
		dc.logger.Printf("failed to send backlog for %q: %v", target, err)
		return
	}

	dc.SendBatch(ctx, "chathistory", []string{target}, nil, func(batchRef string) {
		for _, msg := range history {
			if ch != nil && ch.Detached {
				if net.detachedMessageNeedsRelay(ch, msg) {
					dc.relayDetachedMessage(net, msg)
				}
			} else {
				msg.Tags["batch"] = batchRef
				dc.SendMessage(ctx, msg)
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
		sendServiceNOTICE(dc, fmt.Sprintf("highlight in %v: <%v> %v", target, sender, text))
	} else {
		sendServiceNOTICE(dc, fmt.Sprintf("message in %v: <%v> %v", target, sender, text))
	}
}

func (dc *downstreamConn) runUntilRegistered() error {
	ctx, cancel := context.WithTimeout(context.TODO(), downstreamRegisterTimeout)
	defer cancel()

	// Close the connection with an error if the deadline is exceeded
	go func() {
		<-ctx.Done()
		if err := ctx.Err(); err == context.DeadlineExceeded {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			dc.SendMessage(ctx, &irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "ERROR",
				Params:  []string{"Connection registration timed out"},
			})
			dc.Shutdown(ctx)
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
			dc.SendMessage(ctx, ircErr.Message)
		} else if err != nil {
			return fmt.Errorf("failed to handle IRC command %q: %v", msg, err)
		}

		if dc.registration.nick != "" && dc.registration.username != "" && !dc.registration.negotiatingCaps {
			return dc.register(ctx)
		}
	}

	return nil
}

func (dc *downstreamConn) handleMessageRegistered(ctx context.Context, msg *irc.Message) error {
	switch msg.Command {
	case "CAP":
		return dc.handleCap(ctx, msg)
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
		dc.SendMessage(ctx, &irc.Message{
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
		var nick string
		if err := parseMessageParams(msg, &nick); err != nil {
			return err
		}

		if nick == "" || strings.ContainsAny(nick, illegalNickChars) {
			return ircError{&irc.Message{
				Command: irc.ERR_ERRONEUSNICKNAME,
				Params:  []string{dc.nick, nick, "Nickname contains illegal characters"},
			}}
		}
		if dc.casemap(nick) == serviceNickCM {
			return ircError{&irc.Message{
				Command: irc.ERR_NICKNAMEINUSE,
				Params:  []string{dc.nick, nick, "Nickname reserved for bouncer service"},
			}}
		}

		var err error
		if dc.network != nil {
			record := dc.network.Network
			record.Nick = nick
			err = dc.srv.db.StoreNetwork(ctx, dc.user.ID, &record)
		} else {
			err = dc.user.updateUser(ctx, func(record *database.User) error {
				record.Nick = nick
				return nil
			})
		}
		if err != nil {
			dc.logger.Printf("failed to update nick: %v", err)
			return ircError{&irc.Message{
				Command: xirc.ERR_UNKNOWNERROR,
				Params:  []string{dc.nick, "NICK", "Failed to update nick"},
			}}
		}

		if dc.network != nil {
			dc.network.Network.Nick = nick
			if uc := dc.upstream(); uc != nil {
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "NICK",
					Params:  []string{nick},
				})
			} else {
				dc.updateNick(ctx)
			}
		} else {
			for _, c := range dc.user.downstreamConns {
				if c.network == nil {
					c.updateNick(ctx)
				}
			}
		}
	case "SETNAME":
		var realname string
		if err := parseMessageParams(msg, &realname); err != nil {
			return err
		}

		if dc.realname == realname {
			dc.SendMessage(ctx, &irc.Message{
				Prefix:  dc.prefix(),
				Command: "SETNAME",
				Params:  []string{realname},
			})
			return nil
		}

		var err error
		if dc.network != nil {
			// If the client just resets to the default, just wipe the per-network
			// preference
			record := dc.network.Network
			record.Realname = realname
			if realname == dc.user.Realname {
				record.Realname = ""
			}

			if uc := dc.upstream(); uc != nil && uc.caps.IsEnabled("setname") {
				// Upstream will reply with a SETNAME message on success
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "SETNAME",
					Params:  []string{realname},
				})

				err = dc.srv.db.StoreNetwork(ctx, dc.user.ID, &record)
			} else {
				// This will disconnect then re-connect the upstream connection
				_, err = dc.user.updateNetwork(ctx, &record, false)
			}
		} else {
			err = dc.user.updateUser(ctx, func(record *database.User) error {
				record.Realname = realname
				return nil
			})
		}

		if err != nil {
			dc.logger.Printf("failed to update realname: %v", err)
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"SETNAME", "CANNOT_CHANGE_REALNAME", "Failed to update realname"},
			}}
		}

		if dc.network == nil {
			for _, c := range dc.user.downstreamConns {
				if c.network == nil {
					c.updateRealname(ctx)
				}
			}
		}
	case "JOIN":
		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		var namesStr string
		if err := parseMessageParams(msg, &namesStr); err != nil {
			return err
		}

		var keys []string
		if len(msg.Params) > 1 {
			keys = strings.Split(msg.Params[1], ",")
		}

		for i, name := range strings.Split(namesStr, ",") {
			var key string
			if len(keys) > i {
				key = keys[i]
			}

			if name == "" || strings.ContainsAny(name, illegalChanChars) {
				dc.SendMessage(ctx, &irc.Message{
					Command: irc.ERR_BADCHANMASK,
					Params:  []string{name, "Invalid channel name"},
				})
				continue
			}
			if !uc.isChannel(name) {
				dc.SendMessage(ctx, &irc.Message{
					Command: irc.ERR_NOSUCHCHANNEL,
					Params:  []string{name, "Not a channel name"},
				})
				continue
			}

			// Most servers ignore duplicate JOIN messages. We ignore them here
			// because some clients automatically send JOIN messages in bulk
			// when reconnecting to the bouncer. We don't want to flood the
			// upstream connection with these.
			if !uc.channels.Has(name) {
				params := []string{name}
				if key != "" {
					params = append(params, key)
				}
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "JOIN",
					Params:  params,
				})
			}

			ch := uc.network.channels.Get(name)
			if ch != nil {
				// Don't clear the channel key if there's one set
				// TODO: add a way to unset the channel key
				if key != "" {
					ch.Key = key
				}
				uc.network.attach(ctx, ch)
			} else {
				ch = &database.Channel{
					Name: name,
					Key:  key,
				}
				uc.network.channels.Set(ch.Name, ch)
			}
			if err := dc.srv.db.StoreChannel(ctx, uc.network.ID, ch); err != nil {
				dc.logger.Printf("failed to create or update channel %q: %v", name, err)
			}
		}
	case "PART":
		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		var namesStr string
		if err := parseMessageParams(msg, &namesStr); err != nil {
			return err
		}

		var reason string
		if len(msg.Params) > 1 {
			reason = msg.Params[1]
		}

		for _, name := range strings.Split(namesStr, ",") {
			if strings.EqualFold(reason, "detach") {
				ch := uc.network.channels.Get(name)
				if ch != nil {
					uc.network.detach(ch)
				} else {
					ch = &database.Channel{
						Name:     name,
						Detached: true,
					}
					uc.network.channels.Set(ch.Name, ch)
				}
				if err := dc.srv.db.StoreChannel(ctx, uc.network.ID, ch); err != nil {
					dc.logger.Printf("failed to create or update channel %q: %v", name, err)
				}
			} else {
				params := []string{name}
				if reason != "" {
					params = append(params, reason)
				}
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "PART",
					Params:  params,
				})

				if err := uc.network.deleteChannel(ctx, name); err != nil {
					dc.logger.Printf("failed to delete channel %q: %v", name, err)
				}

				uc.network.pushTargets.Del(name)
			}
		}
	case "KICK":
		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		uc.SendMessageLabeled(ctx, dc.id, msg)
	case "MODE":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		var modeStr string
		if len(msg.Params) > 1 {
			modeStr = msg.Params[1]
		}

		if dc.casemap(name) == dc.nickCM {
			if modeStr != "" {
				uc, err := dc.upstreamForCommand(msg.Command)
				if err != nil {
					return err
				}
				uc.SendMessageLabeled(ctx, dc.id, msg)
			} else {
				var userMode string
				if uc := dc.upstream(); uc != nil {
					userMode = string(uc.modes)
				}

				dc.SendMessage(ctx, &irc.Message{
					Command: irc.RPL_UMODEIS,
					Params:  []string{dc.nick, "+" + userMode},
				})
			}
			return nil
		}

		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		if !uc.isChannel(name) {
			return ircError{&irc.Message{
				Command: irc.ERR_USERSDONTMATCH,
				Params:  []string{dc.nick, "Cannot change mode for other users"},
			}}
		}

		if modeStr != "" {
			params := []string{name, modeStr}
			params = append(params, msg.Params[2:]...)
			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
				Command: "MODE",
				Params:  params,
			})
		} else {
			ch := uc.channels.Get(name)
			if ch == nil {
				// we're not on that channel, pass command to upstream
				uc.SendMessageLabeled(ctx, dc.id, msg)
				return nil
			}

			if ch.modes == nil {
				// we haven't received the initial RPL_CHANNELMODEIS yet
				// ignore the request, we will broadcast the modes later when we receive RPL_CHANNELMODEIS
				return nil
			}

			modeStr, modeParams := ch.modes.Format()
			params := []string{dc.nick, name, modeStr}
			params = append(params, modeParams...)

			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_CHANNELMODEIS,
				Params:  params,
			})
			if ch.creationTime != "" {
				dc.SendMessage(ctx, &irc.Message{
					Command: xirc.RPL_CREATIONTIME,
					Params:  []string{dc.nick, name, ch.creationTime},
				})
			}
		}
	case "TOPIC":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}

		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		if len(msg.Params) > 1 { // setting topic
			topic := msg.Params[1]
			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
				Command: "TOPIC",
				Params:  []string{name, topic},
			})
		} else { // getting topic
			ch := uc.channels.Get(name)
			if ch == nil {
				// we're not on that channel, pass command to upstream
				uc.SendMessageLabeled(ctx, dc.id, msg)
			} else {
				sendTopic(ctx, dc, ch)
			}
		}
	case "LIST":
		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		uc.enqueueCommand(dc, msg)
	case "NAMES":
		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		if len(msg.Params) == 0 {
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFNAMES,
				Params:  []string{dc.nick, "*", "End of /NAMES list"},
			})
			return nil
		}

		channels := strings.Split(msg.Params[0], ",")
		for _, name := range channels {
			ch := uc.channels.Get(name)
			if ch != nil {
				sendNames(ctx, dc, ch)
			} else {
				// NAMES on a channel we have not joined, ask upstream
				uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
					Command: "NAMES",
					Params:  []string{name},
				})
			}
		}
	case "WHO":
		if len(msg.Params) == 0 {
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{"*", "*", "End of /WHO list"},
			})
			return nil
		}

		// Clients will use the first mask to match RPL_ENDOFWHO
		endOfWhoToken := msg.Params[0]

		mask := msg.Params[0]
		var options string
		if len(msg.Params) > 1 {
			options = msg.Params[1]
		}

		fields, whoxToken := xirc.ParseWHOXOptions(options)

		// TODO: support mixed bouncer/upstream WHO queries
		maskCM := dc.casemap(mask)
		if dc.network == nil && maskCM == dc.nickCM {
			flags := "H"
			if dc.away != nil {
				flags = "G"
			}
			if dc.user.Admin {
				flags += "*"
			}
			info := xirc.WHOXInfo{
				Token:    whoxToken,
				Username: dc.user.Username,
				Hostname: dc.hostname,
				Server:   dc.srv.Config().Hostname,
				Nickname: dc.nick,
				Flags:    flags,
				Account:  dc.user.Username,
				Realname: dc.realname,
			}
			dc.SendMessage(ctx, xirc.GenerateWHOXReply(fields, &info))
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{"*", endOfWhoToken, "End of /WHO list"},
			})
			return nil
		}
		if maskCM == serviceNickCM {
			flags := "H*"
			if dc.network == nil {
				flags += "B"
			} else if uc := dc.upstream(); uc != nil {
				if v := uc.isupport["BOT"]; v != nil && len(*v) == 1 {
					flags += *v
				}
			}
			info := xirc.WHOXInfo{
				Token:    whoxToken,
				Username: servicePrefix.User,
				Hostname: servicePrefix.Host,
				Server:   dc.srv.Config().Hostname,
				Nickname: serviceNick,
				Flags:    flags,
				Account:  serviceNick,
				Realname: serviceRealname,
			}
			dc.SendMessage(ctx, xirc.GenerateWHOXReply(fields, &info))
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{"*", endOfWhoToken, "End of /WHO list"},
			})
			return nil
		}
		if dc.network == nil {
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{"*", endOfWhoToken, "End of /WHO list"},
			})
			return nil
		}

		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		// Check if we have the reply cached
		if l, ok := uc.getCachedWHO(mask, fields); ok {
			for _, uu := range l {
				info := xirc.WHOXInfo{
					Token:    whoxToken,
					Username: uu.Username,
					Hostname: uu.Hostname,
					Server:   uu.Server,
					Nickname: uu.Nickname,
					Flags:    uu.Flags,
					Account:  uu.Account,
					Realname: uu.Realname,
				}
				if uc.isChannel(mask) {
					info.Channel = mask

					// Set channel membership prefixes from cached NAMES reply
					ch := uc.channels.Get(info.Channel)
					memberships := ch.Members.Get(info.Nickname)
					prefixes := formatMemberPrefix(*memberships, dc)

					// Channel membership prefixes are listed after away status ('G'/'H')
					// and optional server operator indicator ('*')
					i := strings.IndexFunc(info.Flags, func(f rune) bool {
						return f != 'G' && f != 'H' && f != '*'
					})

					if i == -1 {
						info.Flags += prefixes
					} else {
						info.Flags = info.Flags[:i] + prefixes + info.Flags[i:]
					}
				}
				dc.SendMessage(ctx, xirc.GenerateWHOXReply(fields, &info))
			}
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{"*", endOfWhoToken, "End of /WHO list"},
			})
			return nil
		}

		uc.enqueueCommand(dc, msg)
	case "WHOIS":
		if len(msg.Params) == 0 {
			return ircError{&irc.Message{
				Command: irc.ERR_NONICKNAMEGIVEN,
				Params:  []string{dc.nick, "No nickname given"},
			}}
		}

		var mask string
		if len(msg.Params) == 1 {
			mask = msg.Params[0]
		} else {
			mask = msg.Params[1]
		}
		// TODO: support multiple WHOIS users
		if i := strings.IndexByte(mask, ','); i >= 0 {
			mask = mask[:i]
		}

		if dc.network == nil && dc.casemap(mask) == dc.nickCM {
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_WHOISUSER,
				Params:  []string{dc.nick, dc.nick, dc.user.Username, dc.hostname, "*", dc.realname},
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_WHOISSERVER,
				Params:  []string{dc.nick, dc.nick, dc.srv.Config().Hostname, "soju"},
			})
			if dc.user.Admin {
				dc.SendMessage(ctx, &irc.Message{
					Command: irc.RPL_WHOISOPERATOR,
					Params:  []string{dc.nick, dc.nick, "is a bouncer administrator"},
				})
			}
			dc.SendMessage(ctx, &irc.Message{
				Command: xirc.RPL_WHOISACCOUNT,
				Params:  []string{dc.nick, dc.nick, dc.user.Username, "is logged in as"},
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFWHOIS,
				Params:  []string{dc.nick, dc.nick, "End of /WHOIS list"},
			})
			return nil
		}
		if dc.casemap(mask) == serviceNickCM {
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_WHOISUSER,
				Params:  []string{dc.nick, serviceNick, servicePrefix.User, servicePrefix.Host, "*", serviceRealname},
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_WHOISSERVER,
				Params:  []string{dc.nick, serviceNick, dc.srv.Config().Hostname, "soju"},
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_WHOISOPERATOR,
				Params:  []string{dc.nick, serviceNick, "is the bouncer service"},
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: xirc.RPL_WHOISACCOUNT,
				Params:  []string{dc.nick, serviceNick, serviceNick, "is logged in as"},
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: xirc.RPL_WHOISBOT,
				Params:  []string{dc.nick, serviceNick, "is a bot"},
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFWHOIS,
				Params:  []string{dc.nick, serviceNick, "End of /WHOIS list"},
			})
			return nil
		}

		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		uc.enqueueCommand(dc, msg)
	case "PRIVMSG", "NOTICE", "TAGMSG":
		var targetsStr, text string
		if msg.Command != "TAGMSG" {
			if err := parseMessageParams(msg, &targetsStr, &text); err != nil {
				return err
			}
		} else {
			if err := parseMessageParams(msg, &targetsStr); err != nil {
				return err
			}
		}

		tags := copyClientTags(msg.Tags)

		for _, name := range strings.Split(targetsStr, ",") {
			params := []string{name}
			if msg.Command != "TAGMSG" {
				params = append(params, text)
			}

			if name == "$"+dc.srv.Config().Hostname || (name == "$*" && dc.network == nil) {
				// "$" means a server mask follows. If it's the bouncer's
				// hostname, broadcast the message to all bouncer users.
				if !dc.user.Admin {
					return ircError{&irc.Message{
						Command: irc.ERR_BADMASK,
						Params:  []string{dc.nick, name, "Permission denied to broadcast message to all bouncer users"},
					}}
				}

				dc.logger.Printf("broadcasting bouncer-wide %v: %v", msg.Command, text)

				broadcastTags := tags.Copy()
				broadcastTags["time"] = dc.user.FormatServerTime(time.Now())
				broadcastMsg := &irc.Message{
					Tags:    broadcastTags,
					Prefix:  servicePrefix,
					Command: msg.Command,
					Params:  params,
				}
				dc.srv.forEachUser(func(u *user) {
					u.events <- eventBroadcast{broadcastMsg}
				})
				continue
			}

			if dc.network == nil && dc.casemap(name) == dc.nickCM {
				dc.SendMessage(ctx, &irc.Message{
					Tags:    msg.Tags.Copy(),
					Prefix:  dc.prefix(),
					Command: msg.Command,
					Params:  params,
				})
				continue
			}

			if dc.casemap(name) == serviceNickCM {
				if dc.caps.IsEnabled("echo-message") {
					echoTags := tags.Copy()
					echoTags["time"] = dc.user.FormatServerTime(time.Now())
					dc.SendMessage(ctx, &irc.Message{
						Tags:    echoTags,
						Prefix:  dc.prefix(),
						Command: msg.Command,
						Params:  params,
					})
				}
				if msg.Command == "PRIVMSG" {
					if err := handleServicePRIVMSG(&serviceContext{
						Context: ctx,
						nick:    dc.nick,
						network: dc.network,
						user:    dc.user,
						srv:     dc.user.srv,
						admin:   dc.user.Admin,
						print: func(text string) {
							sendServicePRIVMSG(dc, text)
						},
					}, text); err != nil {
						sendServicePRIVMSG(dc, fmt.Sprintf("error: %v", err))
					}
				}
				continue
			}

			uc, err := dc.upstreamForCommand(msg.Command)
			if err != nil {
				return err
			}

			if msg.Command == "PRIVMSG" && uc.network.casemap(name) == "nickserv" {
				dc.handleNickServPRIVMSG(ctx, uc, text)
			}

			upstreamParams := []string{name}
			if msg.Command != "TAGMSG" {
				upstreamParams = append(upstreamParams, text)
			}

			uc.SendMessageLabeled(ctx, dc.id, &irc.Message{
				Tags:    tags,
				Command: msg.Command,
				Params:  upstreamParams,
			})

			// If the upstream supports echo message, we'll produce the message
			// when it is echoed from the upstream.
			// Otherwise, produce/log it here because it's the last time we'll see it.
			if !uc.caps.IsEnabled("echo-message") {
				echoParams := []string{name}
				if msg.Command != "TAGMSG" {
					echoParams = append(echoParams, text)
				}

				echoTags := tags.Copy()
				echoTags["time"] = dc.user.FormatServerTime(time.Now())
				if uc.account != "" {
					echoTags["account"] = uc.account
				}
				echoMsg := &irc.Message{
					Tags: echoTags,
					Prefix: &irc.Prefix{
						Name: uc.nick,
						User: uc.username,
						Host: uc.hostname,
					},
					Command: msg.Command,
					Params:  echoParams,
				}
				uc.produce(name, echoMsg, dc.id)
			}

			uc.updateChannelAutoDetach(name)
		}
	case "INVITE":
		uc, err := dc.upstreamForCommand(msg.Command)
		if err != nil {
			return err
		}

		uc.SendMessageLabeled(ctx, dc.id, msg)
	case "AUTHENTICATE":
		// Post-connection-registration AUTHENTICATE is only supported if an
		// upstream is bound and supports SASL
		uc := dc.upstream()
		if uc == nil || !uc.caps.IsEnabled("sasl") {
			return ircError{&irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, "Upstream network authentication not supported"},
			}}
		}

		credentials, err := dc.handleAuthenticate(ctx, msg)
		if err != nil {
			return err
		} else if credentials == nil {
			break
		}

		if uc.saslClient != nil {
			dc.endSASL(ctx, &irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, "Another authentication attempt is already in progress"},
			})
			break
		}

		switch credentials.mechanism {
		case "PLAIN":
			if credentials.plain.Identity != "" && credentials.plain.Identity != credentials.plain.Username {
				return ircError{&irc.Message{
					Command: irc.ERR_SASLFAIL,
					Params:  []string{dc.nick, "SASL PLAIN identity not supported"},
				}}
			}

			uc.logger.Printf("starting post-registration SASL PLAIN authentication with username %q", credentials.plain.Username)
			uc.saslClient = sasl.NewPlainClient("", credentials.plain.Username, credentials.plain.Password)
			uc.enqueueCommand(dc, &irc.Message{
				Command: "AUTHENTICATE",
				Params:  []string{"PLAIN"},
			})
		case "ANONYMOUS":
			if uc.network.SASL.Mechanism != "" {
				record := uc.network.Network // copy network record because we'll mutate it
				record.SASL.Plain.Username = ""
				record.SASL.Plain.Password = ""
				record.SASL.External.CertBlob = nil
				record.SASL.External.PrivKeyBlob = nil
				record.SASL.Mechanism = ""
				_, err := dc.user.updateNetwork(ctx, &record, false)
				if err != nil {
					dc.logger.Printf("failed to clear SASL credentials")
					dc.endSASL(ctx, &irc.Message{
						Command: irc.ERR_SASLFAIL,
						Params:  []string{dc.nick, "Internal server error"},
					})
					break
				}
			}
			dc.endSASL(ctx, nil)
		default:
			dc.endSASL(ctx, &irc.Message{
				Command: irc.ERR_SASLFAIL,
				Params:  []string{dc.nick, "Unsupported SASL authentication mechanism"},
			})
		}
	case "REGISTER", "VERIFY":
		// Check number of params here, since we'll use that to save the
		// credentials on command success
		if (msg.Command == "REGISTER" && len(msg.Params) < 3) || (msg.Command == "VERIFY" && len(msg.Params) < 2) {
			return newNeedMoreParamsError(msg.Command)
		}

		uc := dc.upstream()
		if uc == nil || !uc.caps.IsEnabled("draft/account-registration") {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{msg.Command, "TEMPORARILY_UNAVAILABLE", "*", "Upstream network account registration not supported"},
			}}
		}

		uc.logger.Printf("starting %v with account name %v", msg.Command, msg.Params[0])
		uc.enqueueCommand(dc, msg)
	case "AWAY":
		if len(msg.Params) > 0 {
			dc.away = &msg.Params[0]
		} else {
			dc.away = nil
		}

		dc.SendMessage(ctx, generateAwayReply(dc.away != nil))

		uc := dc.upstream()
		if uc != nil {
			uc.updateAway()
		}
	case "INFO":
		if dc.network == nil {
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_INFO,
				Params:  []string{dc.nick, "soju <https://soju.im>"},
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFINFO,
				Params:  []string{dc.nick, "End of INFO"},
			})
			break
		}

		if uc := dc.upstream(); uc == nil {
			return ircError{&irc.Message{
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params:  []string{dc.nick, msg.Command, "Disconnected from upstream network"},
			}}
		} else {
			uc.SendMessageLabeled(ctx, dc.id, msg)
		}
	case "MONITOR":
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
					if dc.monitored.Len() >= 1000 {
						dc.SendMessage(ctx, &irc.Message{
							Command: irc.ERR_MONLISTFULL,
							Params:  []string{dc.nick, "1000", target, "Bouncer monitor list is full"},
						})
						continue
					}

					dc.monitored.Set(target, struct{}{})

					if uc.network.casemap(target) == serviceNickCM {
						// BouncerServ is never tired
						dc.SendMessage(ctx, &irc.Message{
							Command: irc.RPL_MONONLINE,
							Params:  []string{dc.nick, target},
						})
						continue
					}

					if uc.monitored.Has(target) {
						cmd := irc.RPL_MONOFFLINE
						if online := uc.monitored.Get(target); online {
							cmd = irc.RPL_MONONLINE
						}

						dc.SendMessage(ctx, &irc.Message{
							Command: cmd,
							Params:  []string{dc.nick, target},
						})
					}
				} else {
					dc.monitored.Del(target)
				}
			}
			uc.updateMonitor()
		case "C": // clear
			dc.monitored = xirc.NewCaseMappingMap[struct{}](uc.network.casemap)
			uc.updateMonitor()
		case "L": // list
			// TODO: be less lazy and pack the list
			dc.monitored.ForEach(func(name string, _ struct{}) {
				dc.SendMessage(ctx, &irc.Message{
					Command: irc.RPL_MONLIST,
					Params:  []string{dc.nick, name},
				})
			})
			dc.SendMessage(ctx, &irc.Message{
				Command: irc.RPL_ENDOFMONLIST,
				Params:  []string{dc.nick, "End of MONITOR list"},
			})
		case "S": // status
			// TODO: be less lazy and pack the lists
			dc.monitored.ForEach(func(target string, _ struct{}) {
				cmd := irc.RPL_MONOFFLINE
				if online := uc.monitored.Get(target); online {
					cmd = irc.RPL_MONONLINE
				}

				if uc.network.casemap(target) == serviceNickCM {
					cmd = irc.RPL_MONONLINE
				}

				dc.SendMessage(ctx, &irc.Message{
					Command: cmd,
					Params:  []string{dc.nick, target},
				})
			})
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
				dc.SendBatch(ctx, "draft/chathistory-targets", nil, nil, func(batchRef string) {})
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
		if dc.casemap(target) == serviceNickCM {
			dc.SendBatch(ctx, "chathistory", []string{target}, nil, func(batchRef string) {})
			return nil
		}

		store, ok := dc.user.msgStore.(msgstore.ChatHistoryStore)
		if !ok {
			return ircError{&irc.Message{
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params:  []string{dc.nick, "CHATHISTORY", "Chat history disabled"},
			}}
		}

		network := dc.network
		if network == nil {
			return newChatHistoryError(subcommand, "Cannot fetch chat history on bouncer connection")
		}

		target = network.casemap(target)

		// TODO: support msgid criteria
		var bounds [2]time.Time
		bounds[0] = parseChatHistoryBound(boundsStr[0])
		if subcommand == "LATEST" && boundsStr[0] == "*" {
			bounds[0] = time.Time{}
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

		eventPlayback := dc.caps.IsEnabled("draft/event-playback")

		options := msgstore.LoadMessageOptions{
			Network: &network.Network,
			Entity:  target,
			Limit:   limit,
			Events:  eventPlayback,
		}

		var history []*irc.Message
		switch subcommand {
		case "BEFORE":
			history, err = store.LoadBeforeTime(ctx, bounds[0], time.Time{}, &options)
		case "LATEST":
			history, err = store.LoadBeforeTime(ctx, time.Now(), bounds[0], &options)
		case "AFTER":
			history, err = store.LoadAfterTime(ctx, bounds[0], time.Now(), &options)
		case "BETWEEN":
			if bounds[0].Before(bounds[1]) {
				history, err = store.LoadAfterTime(ctx, bounds[0], bounds[1], &options)
			} else {
				history, err = store.LoadBeforeTime(ctx, bounds[0], bounds[1], &options)
			}
		case "TARGETS":
			targets, err := store.ListTargets(ctx, &network.Network, bounds[0], bounds[1], limit, eventPlayback)
			if err != nil {
				dc.logger.Printf("failed fetching targets for chathistory: %v", err)
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"CHATHISTORY", "MESSAGE_ERROR", subcommand, "Failed to retrieve targets"},
				}}
			}

			dc.SendBatch(ctx, "draft/chathistory-targets", nil, nil, func(batchRef string) {
				for _, target := range targets {
					if ch := network.channels.Get(target.Name); ch != nil && ch.Detached {
						continue
					}

					dc.SendMessage(ctx, &irc.Message{
						Tags:    irc.Tags{"batch": batchRef},
						Command: "CHATHISTORY",
						Params:  []string{"TARGETS", target.Name, xirc.FormatServerTime(target.LatestMessage)},
					})
				}
			})

			return nil
		}
		if err != nil {
			dc.logger.Printf("failed fetching %q messages for chathistory: %v", target, err)
			return newChatHistoryError(subcommand, target)
		}

		dc.SendBatch(ctx, "chathistory", []string{target}, nil, func(batchRef string) {
			for _, msg := range history {
				msg.Tags["batch"] = batchRef
				dc.SendMessage(ctx, msg)
			}
		})
	case "READ", "MARKREAD":
		var target, criteria string
		if err := parseMessageParams(msg, &target); err != nil {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{msg.Command, "NEED_MORE_PARAMS", "Missing parameters"},
			}}
		}
		if len(msg.Params) > 1 {
			criteria = msg.Params[1]
		}

		// We don't save read receipts for our service
		if dc.casemap(target) == serviceNickCM {
			dc.SendMessage(ctx, &irc.Message{
				Prefix:  dc.prefix(),
				Command: msg.Command,
				Params:  []string{target, "*"},
			})
			return nil
		}

		network := dc.network
		if network == nil {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{msg.Command, "INTERNAL_ERROR", target, "Cannot set read markers on bouncer connection"},
			}}
		}

		targetCM := network.casemap(target)

		r, err := dc.srv.db.GetReadReceipt(ctx, network.ID, targetCM)
		if err != nil {
			dc.logger.Printf("failed to get the read receipt for %q: %v", target, err)
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{msg.Command, "INTERNAL_ERROR", target, "Internal error"},
			}}
		} else if r == nil {
			r = &database.ReadReceipt{
				Target: targetCM,
			}
		}

		broadcast := false
		if len(criteria) > 0 {
			// TODO: support msgid criteria
			criteriaParts := strings.SplitN(criteria, "=", 2)
			if len(criteriaParts) != 2 || criteriaParts[0] != "timestamp" {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{msg.Command, "INVALID_PARAMS", criteria, "Unknown criteria"},
				}}
			}

			timestamp, err := time.Parse(xirc.ServerTimeLayout, criteriaParts[1])
			if err != nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{msg.Command, "INVALID_PARAMS", criteria, "Invalid criteria"},
				}}
			}
			now := time.Now()
			if timestamp.After(now) {
				timestamp = now
			}
			if r.Timestamp.Before(timestamp) {
				r.Timestamp = timestamp
				if err := dc.srv.db.StoreReadReceipt(ctx, network.ID, r); err != nil {
					dc.logger.Printf("failed to store receipt for %q: %v", target, err)
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{msg.Command, "INTERNAL_ERROR", target, "Internal error"},
					}}
				}
				broadcast = true
			}
		}

		timestampStr := "*"
		if !r.Timestamp.IsZero() {
			timestampStr = fmt.Sprintf("timestamp=%s", xirc.FormatServerTime(r.Timestamp))
		}
		network.forEachDownstream(func(d *downstreamConn) {
			if broadcast || dc.id == d.id {
				cmd := "MARKREAD"
				if !d.caps.IsEnabled("draft/read-marker") {
					cmd = "READ"
				}
				d.SendMessage(ctx, &irc.Message{
					Prefix:  d.prefix(),
					Command: cmd,
					Params:  []string{target, timestampStr},
				})
			}
		})

		if broadcast && network.pushTargets.Has(target) {
			// TODO: only broadcast if draft/read-marker has been negotiated
			if !r.Timestamp.Before(network.pushTargets.Get(target)) {
				network.pushTargets.Del(target)
			}
			go network.broadcastWebPush(&irc.Message{
				Command: "MARKREAD",
				Params:  []string{target, timestampStr},
			})
		}
	case "SEARCH":
		store, ok := dc.user.msgStore.(msgstore.SearchStore)
		if !ok {
			return ircError{&irc.Message{
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params:  []string{dc.nick, "SEARCH", "Unknown command"},
			}}
		}
		var attrsStr string
		if err := parseMessageParams(msg, &attrsStr); err != nil {
			return err
		}
		attrs := irc.ParseTags(attrsStr)

		var network *network
		const searchMaxLimit = 100
		opts := msgstore.SearchMessageOptions{
			Limit: searchMaxLimit,
		}
		for name, v := range attrs {
			value := string(v)
			switch name {
			case "before", "after":
				timestamp, err := time.Parse(xirc.ServerTimeLayout, value)
				if err != nil {
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{"SEARCH", "INVALID_PARAMS", name, "Invalid criteria"},
					}}
				}
				switch name {
				case "after":
					opts.Start = timestamp
				case "before":
					opts.End = timestamp
				}
			case "from":
				opts.From = value
			case "in":
				network = dc.network
				if network == nil {
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{"SEARCH", "INVALID_PARAMS", name, "Cannot search on bouncer connection"},
					}}
				}
				opts.In = network.casemap(value)
			case "text":
				opts.Text = value
			case "limit":
				limit, err := strconv.Atoi(value)
				if err != nil || limit <= 0 {
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{"SEARCH", "INVALID_PARAMS", name, "Invalid limit"},
					}}
				}
				opts.Limit = limit
			}
		}
		if network == nil {
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"SEARCH", "INVALID_PARAMS", "in", "The in parameter is mandatory"},
			}}
		}
		if opts.Limit > searchMaxLimit {
			opts.Limit = searchMaxLimit
		}

		messages, err := store.Search(ctx, &network.Network, &opts)
		if err != nil {
			dc.logger.Printf("failed fetching messages for search: %v", err)
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"SEARCH", "INTERNAL_ERROR", "Messages could not be retrieved"},
			}}
		}

		dc.SendBatch(ctx, "soju.im/search", nil, nil, func(batchRef string) {
			for _, msg := range messages {
				msg.Tags["batch"] = batchRef
				dc.SendMessage(ctx, msg)
			}
		})
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
			dc.SendBatch(ctx, "soju.im/bouncer-networks", nil, nil, func(batchRef string) {
				for _, network := range dc.user.networks {
					idStr := fmt.Sprintf("%v", network.ID)
					attrs := getNetworkAttrs(network)
					dc.SendMessage(ctx, &irc.Message{
						Tags:    irc.Tags{"batch": batchRef},
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

			record := database.NewNetwork("")
			record.Nick = dc.nick
			if err := updateNetworkAttrs(record, attrs, subcommand); err != nil {
				return err
			}

			if record.Nick == dc.user.Username {
				record.Nick = ""
			}
			if record.Realname == dc.user.Realname {
				record.Realname = ""
			}

			network, err := dc.user.createNetwork(ctx, record, true)
			if err != nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "UNKNOWN_ERROR", subcommand, fmt.Sprintf("Failed to create network: %v", err)},
				}}
			}

			dc.SendMessage(ctx, &irc.Message{
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
			wasEnabled := record.Enabled
			if err := updateNetworkAttrs(&record, attrs, subcommand); err != nil {
				return err
			}

			if record.Nick == dc.user.Username {
				record.Nick = ""
			}
			if record.Realname == dc.user.Realname {
				record.Realname = ""
			}

			_, err = dc.user.updateNetwork(ctx, &record, !wasEnabled)
			if err != nil {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"BOUNCER", "UNKNOWN_ERROR", subcommand, fmt.Sprintf("Failed to update network: %v", err)},
				}}
			}

			dc.SendMessage(ctx, &irc.Message{
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

			dc.SendMessage(ctx, &irc.Message{
				Command: "BOUNCER",
				Params:  []string{"DELNETWORK", idStr},
			})
		default:
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"BOUNCER", "UNKNOWN_COMMAND", subcommand, "Unknown subcommand"},
			}}
		}
	case "WEBPUSH":
		if !dc.caps.IsEnabled("soju.im/webpush") {
			return newUnknownCommandError(msg.Command)
		}

		var subcommand string
		if err := parseMessageParams(msg, &subcommand); err != nil {
			return err
		}

		switch subcommand {
		case "REGISTER":
			var endpoint, keysStr string
			if err := parseMessageParams(msg, nil, &endpoint, &keysStr); err != nil {
				return err
			}

			rawKeys := irc.ParseTags(keysStr)
			authKey, hasAuthKey := rawKeys["auth"]
			p256dhKey, hasP256dh := rawKeys["p256dh"]
			if !hasAuthKey || !hasP256dh {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"WEBPUSH", "INVALID_PARAMS", subcommand, "Missing auth or p256dh key"},
				}}
			}

			newSub := database.WebPushSubscription{
				Endpoint: endpoint,
			}
			newSub.Keys.VAPID = dc.srv.webPush.VAPIDKeys.Public
			newSub.Keys.Auth = string(authKey)
			newSub.Keys.P256DH = string(p256dhKey)

			subs, err := dc.listWebPushSubscriptions(ctx)
			if err != nil {
				dc.logger.Printf("failed to fetch Web push subscription: %v", err)
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"WEBPUSH", "INTERNAL_ERROR", subcommand, "Internal error"},
				}}
			}

			if len(subs) > 25 {
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"WEBPUSH", "INTERNAL_ERROR", subcommand, "Too many subscriptions"},
				}}
			}

			updateSub := true
			oldSub := findWebPushSubscription(subs, endpoint)
			if oldSub != nil {
				// Update the old subscription instead of creating a new one
				newSub.ID = oldSub.ID
				// Rate-limit subscription checks
				updateSub = time.Since(oldSub.UpdatedAt) > webpushCheckSubscriptionDelay || oldSub.Keys != newSub.Keys
			}

			var networkID int64
			if dc.network != nil {
				networkID = dc.network.ID
			}

			// Send a test Web Push message, to make sure the endpoint is valid
			if updateSub {
				if err := sanityCheckWebPushEndpoint(ctx, newSub.Endpoint); err != nil {
					dc.logger.Printf("failed to sanity check Web push endpoint %q: %v", newSub.Endpoint, err)
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{"WEBPUSH", "INVALID_PARAMS", subcommand, "Invalid endpoint"},
					}}
				}

				err = dc.srv.sendWebPush(ctx, &webpush.Subscription{
					Endpoint: newSub.Endpoint,
					Keys: webpush.Keys{
						Auth:   newSub.Keys.Auth,
						P256dh: newSub.Keys.P256DH,
					},
				}, newSub.Keys.VAPID, &irc.Message{
					Command: "NOTE",
					Params:  []string{"WEBPUSH", "REGISTERED", "Push notifications enabled"},
				})
				if err != nil {
					dc.logger.Printf("failed to send Web push notification to endpoint %q: %v", newSub.Endpoint, err)
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{"WEBPUSH", "INVALID_PARAMS", subcommand, "Invalid endpoint"},
					}}
				}

				if err := dc.user.srv.db.StoreWebPushSubscription(ctx, dc.user.ID, networkID, &newSub); err != nil {
					dc.logger.Printf("failed to store Web push subscription: %v", err)
					return ircError{&irc.Message{
						Command: "FAIL",
						Params:  []string{"WEBPUSH", "INTERNAL_ERROR", subcommand, "Internal error"},
					}}
				}
			}

			dc.SendMessage(ctx, &irc.Message{
				Command: "WEBPUSH",
				Params:  []string{"REGISTER", endpoint},
			})
		case "UNREGISTER":
			var endpoint string
			if err := parseMessageParams(msg, nil, &endpoint); err != nil {
				return err
			}

			subs, err := dc.listWebPushSubscriptions(ctx)
			if err != nil {
				dc.logger.Printf("failed to fetch Web push subscription: %v", err)
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"WEBPUSH", "INTERNAL_ERROR", subcommand, "Internal error"},
				}}
			}

			oldSub := findWebPushSubscription(subs, endpoint)
			if oldSub == nil {
				dc.SendMessage(ctx, &irc.Message{
					Command: "WEBPUSH",
					Params:  []string{"UNREGISTER", endpoint},
				})
				return nil
			}

			if err := dc.srv.db.DeleteWebPushSubscription(ctx, oldSub.ID); err != nil {
				dc.logger.Printf("failed to delete Web push subscription: %v", err)
				return ircError{&irc.Message{
					Command: "FAIL",
					Params:  []string{"WEBPUSH", "INTERNAL_ERROR", subcommand, "Internal error"},
				}}
			}

			dc.SendMessage(ctx, &irc.Message{
				Command: "WEBPUSH",
				Params:  []string{"UNREGISTER", endpoint},
			})
		default:
			return ircError{&irc.Message{
				Command: "FAIL",
				Params:  []string{"WEBPUSH", "INVALID_PARAMS", subcommand, "Unknown command"},
			}}
		}
	default:
		dc.logger.Debugf("unhandled message: %v", msg)

		if dc.network == nil {
			return newUnknownCommandError(msg.Command)
		}

		uc := dc.upstream()
		if uc == nil {
			return ircError{&irc.Message{
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params:  []string{"*", msg.Command, "Disconnected from upstream network"},
			}}
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

func (dc *downstreamConn) listWebPushSubscriptions(ctx context.Context) ([]database.WebPushSubscription, error) {
	var networkID int64
	if dc.network != nil {
		networkID = dc.network.ID
	}

	return dc.user.srv.db.ListWebPushSubscriptions(ctx, dc.user.ID, networkID)
}

func findWebPushSubscription(subs []database.WebPushSubscription, endpoint string) *database.WebPushSubscription {
	for i, sub := range subs {
		if sub.Endpoint == endpoint {
			return &subs[i]
		}
	}
	return nil
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

func forwardChannel(ctx context.Context, dc *downstreamConn, ch *upstreamChannel) {
	if !ch.complete {
		panic("Tried to forward a partial channel")
	}

	// RPL_NOTOPIC shouldn't be sent on JOIN
	if ch.Topic != "" {
		sendTopic(ctx, dc, ch)
	}

	var markReadCmd string
	if dc.caps.IsEnabled("draft/read-marker") {
		markReadCmd = "MARKREAD"
	} else if dc.caps.IsEnabled("soju.im/read") {
		markReadCmd = "READ"
	}
	if markReadCmd != "" {
		channelCM := ch.conn.network.casemap(ch.Name)
		r, err := dc.srv.db.GetReadReceipt(ctx, ch.conn.network.ID, channelCM)
		if err != nil {
			dc.logger.Printf("failed to get the read receipt for %q: %v", ch.Name, err)
		} else {
			timestampStr := "*"
			if r != nil {
				timestampStr = fmt.Sprintf("timestamp=%s", xirc.FormatServerTime(r.Timestamp))
			}
			dc.SendMessage(ctx, &irc.Message{
				Prefix:  dc.prefix(),
				Command: markReadCmd,
				Params:  []string{ch.Name, timestampStr},
			})
		}
	}

	if !dc.caps.IsEnabled("soju.im/no-implicit-names") && !dc.caps.IsEnabled("draft/no-implicit-names") {
		sendNames(ctx, dc, ch)
	}
}

func sendTopic(ctx context.Context, dc *downstreamConn, ch *upstreamChannel) {
	if ch.Topic != "" {
		dc.SendMessage(ctx, &irc.Message{
			Command: irc.RPL_TOPIC,
			Params:  []string{dc.nick, ch.Name, ch.Topic},
		})
		if ch.TopicWho != nil {
			topicTime := strconv.FormatInt(ch.TopicTime.Unix(), 10)
			dc.SendMessage(ctx, &irc.Message{
				Command: xirc.RPL_TOPICWHOTIME,
				Params:  []string{dc.nick, ch.Name, ch.TopicWho.String(), topicTime},
			})
		}
	} else {
		dc.SendMessage(ctx, &irc.Message{
			Command: irc.RPL_NOTOPIC,
			Params:  []string{dc.nick, ch.Name, "No topic is set"},
		})
	}
}

func sendNames(ctx context.Context, dc *downstreamConn, ch *upstreamChannel) {
	var members []string
	ch.Members.ForEach(func(nick string, memberships *xirc.MembershipSet) {
		s := formatMemberPrefix(*memberships, dc) + nick
		members = append(members, s)
	})

	msgs := xirc.GenerateNamesReply(ch.Name, ch.Status, members)
	for _, msg := range msgs {
		dc.SendMessage(ctx, msg)
	}
}

func sanityCheckWebPushEndpoint(ctx context.Context, endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be HTTPS")
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", u.Host)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %v", err)
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsMulticast() || ip.IsPrivate() {
			return fmt.Errorf("invalid IP %v", ip)
		}
	}

	return nil
}
