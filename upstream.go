package soju

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"gopkg.in/irc.v4"

	"codeberg.org/emersion/soju/database"
	"codeberg.org/emersion/soju/xirc"
)

// permanentUpstreamCaps is the static list of upstream capabilities always
// requested when supported.
var permanentUpstreamCaps = map[string]bool{
	"account-notify":   true,
	"account-tag":      true,
	"away-notify":      true,
	"batch":            true,
	"chghost":          true,
	"extended-join":    true,
	"extended-monitor": true,
	"invite-notify":    true,
	"labeled-response": true,
	"message-tags":     true,
	"multi-prefix":     true,
	"sasl":             true,
	"server-time":      true,
	"setname":          true,

	"draft/account-registration": true,
	"draft/extended-monitor":     true,
	"draft/message-redaction":    true,
}

// storableMessageTags is the static list of message tags that will cause
// a TAGMSG to be stored.
var storableMessageTags = map[string]bool{
	"+draft/react": true,
	"+react":       true,
}

type registrationError struct {
	*irc.Message
}

func (err registrationError) Error() string {
	return fmt.Sprintf("registration error (%v): %v", err.Command, err.Reason())
}

func (err registrationError) Reason() string {
	if len(err.Params) > 0 {
		return err.Params[len(err.Params)-1]
	}
	return err.Command
}

func (err registrationError) Temporary() bool {
	// Only return false if we're 100% sure that fixing the error requires a
	// network configuration change
	switch err.Command {
	case irc.ERR_PASSWDMISMATCH, irc.ERR_ERRONEUSNICKNAME:
		return false
	case "FAIL":
		return err.Params[1] != "ACCOUNT_REQUIRED"
	default:
		return true
	}
}

type upstreamChannel struct {
	Name         string
	conn         *upstreamConn
	Topic        string
	TopicWho     *irc.Prefix
	TopicTime    time.Time
	Status       xirc.ChannelStatus
	modes        channelModes
	creationTime string
	Members      xirc.CaseMappingMap[*xirc.MembershipSet]
	complete     bool
	detachTimer  *time.Timer
}

func (uc *upstreamChannel) updateAutoDetach(dur time.Duration) {
	if uc.detachTimer != nil {
		uc.detachTimer.Stop()
		uc.detachTimer = nil
	}

	if dur == 0 {
		return
	}

	uc.detachTimer = time.AfterFunc(dur, func() {
		uc.conn.network.user.events <- eventChannelDetach{
			uc:   uc.conn,
			name: uc.Name,
		}
	})
}

type upstreamBatch struct {
	Type   string
	Params []string
	Outer  *upstreamBatch // if not-nil, this batch is nested in Outer
	Label  string
}

type upstreamUser struct {
	Nickname string
	Username string
	Hostname string
	Server   string
	Flags    string
	Account  string
	Realname string
}

func (uu *upstreamUser) hasWHOXFields(fields string) bool {
	for i := 0; i < len(fields); i++ {
		ok := false
		switch fields[i] {
		case 'n':
			ok = uu.Nickname != ""
		case 'u':
			ok = uu.Username != ""
		case 'h':
			ok = uu.Hostname != ""
		case 's':
			ok = uu.Server != ""
		case 'f':
			ok = uu.Flags != ""
		case 'a':
			ok = uu.Account != ""
		case 'r':
			ok = uu.Realname != ""
		case 't', 'c', 'i', 'd', 'l', 'o':
			// we return static values for those fields, so they are always available
			ok = true
		}
		if !ok {
			return false
		}
	}
	return true
}

func (uu *upstreamUser) updateFrom(update *upstreamUser) {
	if update.Nickname != "" {
		uu.Nickname = update.Nickname
	}
	if update.Username != "" {
		uu.Username = update.Username
	}
	if update.Hostname != "" {
		uu.Hostname = update.Hostname
	}
	if update.Server != "" {
		uu.Server = update.Server
	}
	if update.Flags != "" {
		uu.Flags = update.Flags
	}
	if update.Account != "" {
		uu.Account = update.Account
	}
	if update.Realname != "" {
		uu.Realname = update.Realname
	}
}

type pendingUpstreamCommand struct {
	downstreamID uint64
	msg          *irc.Message
	sentAt       time.Time
}

type upstreamConn struct {
	*conn

	network *network
	user    *user

	serverPrefix          *irc.Prefix
	serverName            string
	availableUserModes    string
	availableChannelModes map[byte]channelModeType
	availableChannelTypes string
	availableStatusMsg    string
	availableMemberships  []xirc.Membership
	isupport              map[string]*string

	registered  bool
	nick        string
	username    string
	realname    string
	hostname    string
	modes       userModes
	channels    xirc.CaseMappingMap[*upstreamChannel]
	users       xirc.CaseMappingMap[*upstreamUser]
	caps        xirc.CapRegistry
	batches     map[string]upstreamBatch
	away        bool
	account     string
	nextLabelID uint64
	monitored   xirc.CaseMappingMap[bool]

	saslClient  sasl.Client
	saslStarted bool

	// Queue of commands in progress, indexed by type. The first entry has been
	// sent to the server and is awaiting reply. The following entries have not
	// been sent yet.
	pendingCmds map[string][]pendingUpstreamCommand

	pendingRegainNick string
	regainNickTimer   *time.Timer
	regainNickBackoff *backoffer

	gotMotd bool

	hasDesiredNick bool
}

func connectToUpstream(ctx context.Context, network *network) (*upstreamConn, error) {
	logger := &prefixLogger{network.user.logger, fmt.Sprintf("upstream %q: ", network.GetName())}

	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	u, err := network.URL()
	if err != nil {
		return nil, err
	}

	var netConn net.Conn
	switch u.Scheme {
	case "ircs":
		addr := u.Host
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			host = u.Host
			addr = u.Host + ":6697"
		}

		tlsConfig := &tls.Config{ServerName: host, NextProtos: []string{"irc"}}
		if network.SASL.Mechanism == "EXTERNAL" {
			if network.SASL.External.CertBlob == nil {
				return nil, fmt.Errorf("missing certificate for authentication")
			}
			if network.SASL.External.PrivKeyBlob == nil {
				return nil, fmt.Errorf("missing private key for authentication")
			}
			key, err := x509.ParsePKCS8PrivateKey(network.SASL.External.PrivKeyBlob)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
			tlsConfig.Certificates = []tls.Certificate{
				{
					Certificate: [][]byte{network.SASL.External.CertBlob},
					PrivateKey:  key.(crypto.PrivateKey),
				},
			}
			logger.Printf("using TLS client certificate %x", sha256.Sum256(network.SASL.External.CertBlob))
		}

		if network.CertFP != "" {
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("the server didn't present any TLS certificate")
				}

				parts := strings.SplitN(network.CertFP, ":", 2)
				algo, localCertFP := parts[0], parts[1]

				for _, rawCert := range rawCerts {
					var remoteCertFP string
					switch algo {
					case "sha-512":
						sum := sha512.Sum512(rawCert)
						remoteCertFP = hex.EncodeToString(sum[:])
					case "sha-256":
						sum := sha256.Sum256(rawCert)
						remoteCertFP = hex.EncodeToString(sum[:])
					}

					if remoteCertFP == localCertFP {
						return nil // fingerprints match
					}
				}

				// Fingerprints don't match, let's give the user a fingerprint
				// they can use to connect
				sum := sha512.Sum512(rawCerts[0])
				remoteCertFP := hex.EncodeToString(sum[:])
				return fmt.Errorf("the configured TLS certificate fingerprint doesn't match the server's - %s", remoteCertFP)
			}
		}

		logger.Printf("connecting to TLS server at address %q", addr)
		netConn, err = dialTCP(ctx, network.user, addr)
		if err != nil {
			return nil, err
		}

		// Don't do the TLS handshake immediately, because we need to register
		// the new connection with identd ASAP. See:
		// https://todo.sr.ht/~emersion/soju/69#event-41859
		netConn = tls.Client(netConn, tlsConfig)
	case "irc+insecure":
		addr := u.Host
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = u.Host + ":6667"
		}

		logger.Printf("connecting to plain-text server at address %q", addr)
		netConn, err = dialTCP(ctx, network.user, addr)
		if err != nil {
			return nil, err
		}
	case "irc+unix", "unix":
		var dialer net.Dialer
		logger.Printf("connecting to Unix socket at path %q", u.Path)
		netConn, err = dialer.DialContext(ctx, "unix", u.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Unix socket %q: %v", u.Path, err)
		}
	default:
		return nil, fmt.Errorf("failed to dial %q: unknown scheme: %v", network.Addr, u.Scheme)
	}

	options := connOptions{
		Logger:         logger,
		RateLimitDelay: upstreamMessageDelay,
		RateLimitBurst: upstreamMessageBurst,
	}

	cm := stdCaseMapping
	uc := &upstreamConn{
		conn:                  newConn(network.user.srv, newNetIRCConn(netConn), &options),
		network:               network,
		user:                  network.user,
		channels:              xirc.NewCaseMappingMap[*upstreamChannel](cm),
		users:                 xirc.NewCaseMappingMap[*upstreamUser](cm),
		caps:                  xirc.NewCapRegistry(),
		batches:               make(map[string]upstreamBatch),
		serverPrefix:          &irc.Prefix{Name: "*"},
		availableChannelTypes: stdChannelTypes,
		availableStatusMsg:    "",
		availableChannelModes: stdChannelModes,
		availableMemberships:  stdMemberships,
		isupport:              make(map[string]*string),
		pendingCmds:           make(map[string][]pendingUpstreamCommand),
		monitored:             xirc.NewCaseMappingMap[bool](cm),
		hasDesiredNick:        true,
	}
	return uc, nil
}

func dialTCP(ctx context.Context, user *user, addr string) (net.Conn, error) {
	var dialer net.Dialer
	upstreamUserIPs := user.srv.Config().UpstreamUserIPs
	if len(upstreamUserIPs) > 0 {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		ipAddr, err := resolveIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve host %q: %v", host, err)
		}

		localAddr, err := user.localTCPAddr(ipAddr.IP)
		if err != nil {
			return nil, fmt.Errorf("failed to pick local IP for remote host %q: %v", host, err)
		}

		addr = net.JoinHostPort(ipAddr.String(), port)
		dialer.LocalAddr = localAddr
	}

	return dialer.DialContext(ctx, "tcp", addr)
}

func (uc *upstreamConn) forEachDownstream(f func(*downstreamConn)) {
	uc.network.forEachDownstream(f)
}

func (uc *upstreamConn) forEachDownstreamByID(id uint64, f func(*downstreamConn)) {
	uc.forEachDownstream(func(dc *downstreamConn) {
		if id != 0 && id != dc.id {
			return
		}
		f(dc)
	})
}

func (uc *upstreamConn) downstreamByID(id uint64) *downstreamConn {
	for _, dc := range uc.user.downstreamConns {
		if dc.id == id {
			return dc
		}
	}
	return nil
}

func (uc *upstreamConn) getChannel(name string) (*upstreamChannel, error) {
	ch := uc.channels.Get(name)
	if ch == nil {
		return nil, fmt.Errorf("unknown channel %q", name)
	}
	return ch, nil
}

func (uc *upstreamConn) isChannel(entity string) bool {
	return len(entity) > 0 && strings.ContainsRune(uc.availableChannelTypes, rune(entity[0]))
}

func (uc *upstreamConn) isOurNick(nick string) bool {
	return uc.network.equalCasemap(uc.nick, nick)
}

func (uc *upstreamConn) forwardMessage(ctx context.Context, msg *irc.Message) {
	uc.forEachDownstream(func(dc *downstreamConn) {
		dc.SendMessage(ctx, msg)
	})
}

func (uc *upstreamConn) forwardMsgByID(ctx context.Context, id uint64, msg *irc.Message) {
	uc.forEachDownstreamByID(id, func(dc *downstreamConn) {
		dc.SendMessage(ctx, msg)
	})
}

func (uc *upstreamConn) abortPendingCommands() {
	ctx := context.TODO()
	for _, l := range uc.pendingCmds {
		for _, pendingCmd := range l {
			dc := uc.downstreamByID(pendingCmd.downstreamID)
			if dc == nil {
				continue
			}

			switch pendingCmd.msg.Command {
			case "LIST":
				dc.SendMessage(ctx, &irc.Message{
					Command: irc.RPL_LISTEND,
					Params:  []string{dc.nick, "Command aborted"},
				})
			case "WHO":
				mask := "*"
				if len(pendingCmd.msg.Params) > 0 {
					mask = pendingCmd.msg.Params[0]
				}
				dc.SendMessage(ctx, &irc.Message{
					Command: irc.RPL_ENDOFWHO,
					Params:  []string{dc.nick, mask, "Command aborted"},
				})
			case "WHOIS":
				nick := pendingCmd.msg.Params[len(pendingCmd.msg.Params)-1]
				dc.SendMessage(ctx, &irc.Message{
					Command: irc.RPL_ENDOFWHOIS,
					Params:  []string{dc.nick, nick, "Command aborted"},
				})
			case "AUTHENTICATE":
				dc.endSASL(ctx, &irc.Message{
					Command: irc.ERR_SASLABORTED,
					Params:  []string{dc.nick, "SASL authentication aborted"},
				})
			case "REGISTER", "VERIFY":
				dc.SendMessage(ctx, &irc.Message{
					Command: "FAIL",
					Params:  []string{pendingCmd.msg.Command, "TEMPORARILY_UNAVAILABLE", pendingCmd.msg.Params[0], "Command aborted"},
				})
			default:
				panic(fmt.Errorf("Unsupported pending command %q", pendingCmd.msg.Command))
			}
		}
	}

	uc.pendingCmds = make(map[string][]pendingUpstreamCommand)
}

func (uc *upstreamConn) sendNextPendingCommand(cmd string) {
	if len(uc.pendingCmds[cmd]) == 0 {
		return
	}
	pendingCmd := &uc.pendingCmds[cmd][0]
	uc.SendMessageLabeled(context.TODO(), pendingCmd.downstreamID, pendingCmd.msg)
	pendingCmd.sentAt = time.Now()
}

func (uc *upstreamConn) enqueueCommand(dc *downstreamConn, msg *irc.Message) {
	switch msg.Command {
	case "LIST", "WHO", "WHOIS", "AUTHENTICATE", "REGISTER", "VERIFY":
		// Supported
	default:
		panic(fmt.Errorf("Unsupported pending command %q", msg.Command))
	}

	uc.pendingCmds[msg.Command] = append(uc.pendingCmds[msg.Command], pendingUpstreamCommand{
		downstreamID: dc.id,
		msg:          msg,
	})

	// If we didn't get a reply after a while, just give up
	// TODO: consider sending an abort reply to downstream
	if t := uc.pendingCmds[msg.Command][0].sentAt; !t.IsZero() && time.Since(t) > 30*time.Second {
		copy(uc.pendingCmds[msg.Command], uc.pendingCmds[msg.Command][1:])
	}

	if len(uc.pendingCmds[msg.Command]) == 1 {
		uc.sendNextPendingCommand(msg.Command)
	}
}

func (uc *upstreamConn) currentPendingCommand(cmd string) (*downstreamConn, *irc.Message) {
	if len(uc.pendingCmds[cmd]) == 0 {
		return nil, nil
	}

	pendingCmd := uc.pendingCmds[cmd][0]
	return uc.downstreamByID(pendingCmd.downstreamID), pendingCmd.msg
}

func (uc *upstreamConn) dequeueCommand(cmd string) (*downstreamConn, *irc.Message) {
	dc, msg := uc.currentPendingCommand(cmd)

	if len(uc.pendingCmds[cmd]) > 0 {
		copy(uc.pendingCmds[cmd], uc.pendingCmds[cmd][1:])
		uc.pendingCmds[cmd] = uc.pendingCmds[cmd][:len(uc.pendingCmds[cmd])-1]
	}

	uc.sendNextPendingCommand(cmd)

	return dc, msg
}

func (uc *upstreamConn) cancelPendingCommandsByDownstreamID(downstreamID uint64) {
	for cmd := range uc.pendingCmds {
		// We can't cancel the currently running command stored in
		// uc.pendingCmds[cmd][0]
		for i := len(uc.pendingCmds[cmd]) - 1; i >= 1; i-- {
			if uc.pendingCmds[cmd][i].downstreamID == downstreamID {
				uc.pendingCmds[cmd] = append(uc.pendingCmds[cmd][:i], uc.pendingCmds[cmd][i+1:]...)
			}
		}
	}
}

func (uc *upstreamConn) parseMembershipPrefix(s string) (ms xirc.MembershipSet, nick string) {
	var memberships xirc.MembershipSet
	i := 0
	for _, m := range uc.availableMemberships {
		if i >= len(s) {
			break
		}
		if s[i] == m.Prefix {
			memberships = append(memberships, m)
			i++
		}
	}
	return memberships, s[i:]
}

func (uc *upstreamConn) handleMessage(ctx context.Context, msg *irc.Message) error {
	var label string
	if l, ok := msg.Tags["label"]; ok {
		label = l
		delete(msg.Tags, "label")
	}

	var msgBatch *upstreamBatch
	if batchName, ok := msg.Tags["batch"]; ok {
		b, ok := uc.batches[batchName]
		if !ok {
			return fmt.Errorf("unexpected batch reference: batch was not defined: %q", batchName)
		}
		msgBatch = &b
		if label == "" {
			label = msgBatch.Label
		}
		delete(msg.Tags, "batch")
	}

	var downstreamID uint64
	if label != "" {
		var labelOffset uint64
		n, err := fmt.Sscanf(label, "sd-%d-%d", &downstreamID, &labelOffset)
		if err == nil && n < 2 {
			err = errors.New("not enough arguments")
		}
		if err != nil {
			return fmt.Errorf("unexpected message label: invalid downstream reference for label %q: %v", label, err)
		}
	}

	if msg.Prefix == nil {
		msg.Prefix = uc.serverPrefix
	}

	if !isNumeric(msg.Command) {
		t, err := time.Parse(xirc.ServerTimeLayout, string(msg.Tags["time"]))
		if err != nil {
			t = time.Now()
		}
		msg.Tags["time"] = uc.user.FormatServerTime(t)
	}

	switch msg.Command {
	case "PING":
		uc.SendMessage(ctx, &irc.Message{
			Command: "PONG",
			Params:  msg.Params,
		})
		return nil
	case "NOTICE", "PRIVMSG", "TAGMSG", "REDACT":
		isText := msg.Command == "NOTICE" || msg.Command == "PRIVMSG"

		var target, text string
		if isText {
			if err := parseMessageParams(msg, &target, &text); err != nil {
				return err
			}
		} else {
			if err := parseMessageParams(msg, &target); err != nil {
				return err
			}
		}

		// remove statusmsg sigils from target
		target = strings.TrimLeft(target, uc.availableStatusMsg)

		if uc.network.equalCasemap(msg.Prefix.Name, serviceNick) {
			uc.logger.Printf("skipping %v from soju's service: %v", msg.Command, msg)
			break
		}
		if uc.network.equalCasemap(target, serviceNick) {
			uc.logger.Printf("skipping %v to soju's service: %v", msg.Command, msg)
			break
		}

		if !uc.registered || uc.network.equalCasemap(msg.Prefix.Name, uc.serverPrefix.Name) || target == "*" || strings.HasPrefix(target, "$") {
			// This is a server message
			uc.produce("", msg, 0)
			break
		}

		directMessage := uc.isOurNick(target)
		bufferName := target
		if directMessage {
			bufferName = msg.Prefix.Name
		}
		if t, ok := msg.Tags["+draft/channel-context"]; ok {
			ch := uc.channels.Get(string(t))
			if ch != nil && ch.Members.Has(msg.Prefix.Name) {
				bufferName = ch.Name
				directMessage = false
			}
		}

		self := uc.isOurNick(msg.Prefix.Name)
		ch := uc.network.channels.Get(bufferName)
		highlight := false
		detached := false
		if ch != nil && isText && !self {
			if ch.Detached {
				uc.handleDetachedMessage(ctx, ch, msg)
			}

			highlight = uc.network.isHighlight(msg)
			if ch.DetachOn == database.FilterMessage || ch.DetachOn == database.FilterDefault || (ch.DetachOn == database.FilterHighlight && highlight) {
				uc.updateChannelAutoDetach(bufferName)
			}

			if ch.Detached && ch.RelayDetached == database.FilterNone {
				detached = true
			}
		}

		if !self && !detached && isText && (highlight || directMessage) {
			go uc.network.broadcastWebPush(msg)
			if timestamp, err := time.Parse(xirc.ServerTimeLayout, string(msg.Tags["time"])); err == nil {
				uc.network.pushTargets.Set(bufferName, timestamp)
			}
		}

		uc.produce(bufferName, msg, downstreamID)
	case "CAP":
		var subCmd string
		if err := parseMessageParams(msg, nil, &subCmd); err != nil {
			return err
		}
		subCmd = strings.ToUpper(subCmd)
		subParams := msg.Params[2:]
		switch subCmd {
		case "LS":
			if len(subParams) < 1 {
				return newNeedMoreParamsError(msg.Command)
			}
			caps := subParams[len(subParams)-1]
			more := len(subParams) >= 2 && msg.Params[len(subParams)-2] == "*"

			uc.handleSupportedCaps(caps)

			if more {
				break // wait to receive all capabilities
			}

			uc.updateCaps(ctx)

			if uc.requestSASL() {
				break // we'll send CAP END after authentication is completed
			}

			uc.SendMessage(ctx, &irc.Message{
				Command: "CAP",
				Params:  []string{"END"},
			})
		case "ACK", "NAK":
			if len(subParams) < 1 {
				return newNeedMoreParamsError(msg.Command)
			}
			caps := strings.Fields(subParams[0])

			for _, name := range caps {
				enable := subCmd == "ACK"
				if strings.HasPrefix(name, "-") {
					name = strings.TrimPrefix(name, "-")
					enable = false
				}
				if err := uc.handleCapAck(ctx, strings.ToLower(name), enable); err != nil {
					return err
				}
			}

			if uc.registered {
				uc.forEachDownstream(func(dc *downstreamConn) {
					dc.updateSupportedCaps(ctx)
				})
			}
		case "NEW":
			if len(subParams) < 1 {
				return newNeedMoreParamsError(msg.Command)
			}
			uc.handleSupportedCaps(subParams[0])
			uc.updateCaps(ctx)
		case "DEL":
			if len(subParams) < 1 {
				return newNeedMoreParamsError(msg.Command)
			}
			caps := strings.Fields(subParams[0])

			for _, c := range caps {
				uc.caps.Del(c)
			}

			if uc.registered {
				uc.forEachDownstream(func(dc *downstreamConn) {
					dc.updateSupportedCaps(ctx)
				})
			}
		default:
			uc.logger.Debugf("unhandled message: %v", msg)
		}
	case "AUTHENTICATE":
		if uc.saslClient == nil {
			return fmt.Errorf("received unexpected AUTHENTICATE message")
		}

		// TODO: if a challenge is 400 bytes long, buffer it
		var challengeStr string
		if err := parseMessageParams(msg, &challengeStr); err != nil {
			uc.SendMessage(ctx, &irc.Message{
				Command: "AUTHENTICATE",
				Params:  []string{"*"},
			})
			return err
		}

		var challenge []byte
		if challengeStr != "+" {
			var err error
			challenge, err = base64.StdEncoding.DecodeString(challengeStr)
			if err != nil {
				uc.SendMessage(ctx, &irc.Message{
					Command: "AUTHENTICATE",
					Params:  []string{"*"},
				})
				return err
			}
		}

		var resp []byte
		var err error
		if !uc.saslStarted {
			_, resp, err = uc.saslClient.Start()
			uc.saslStarted = true
		} else {
			resp, err = uc.saslClient.Next(challenge)
		}
		if err != nil {
			uc.SendMessage(ctx, &irc.Message{
				Command: "AUTHENTICATE",
				Params:  []string{"*"},
			})
			return err
		}

		for _, msg := range xirc.GenerateSASL(resp) {
			uc.SendMessage(ctx, msg)
		}
	case irc.RPL_LOGGEDIN:
		var rawPrefix string
		if err := parseMessageParams(msg, nil, &rawPrefix, &uc.account); err != nil {
			return err
		}

		prefix := irc.ParsePrefix(rawPrefix)
		uc.username = prefix.User
		uc.hostname = prefix.Host

		uc.logger.Printf("logged in with account %q", uc.account)
		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.updateAccount(ctx)
			dc.updateHost(ctx)
		})
	case irc.RPL_LOGGEDOUT:
		var rawPrefix string
		if err := parseMessageParams(msg, nil, &rawPrefix); err != nil {
			return err
		}

		uc.account = ""

		prefix := irc.ParsePrefix(rawPrefix)
		uc.username = prefix.User
		uc.hostname = prefix.Host

		uc.logger.Printf("logged out")
		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.updateAccount(ctx)
			dc.updateHost(ctx)
		})
	case xirc.RPL_VISIBLEHOST:
		var rawHost string
		if err := parseMessageParams(msg, nil, &rawHost); err != nil {
			return err
		}

		parts := strings.SplitN(rawHost, "@", 2)
		if len(parts) == 2 {
			uc.username, uc.hostname = parts[0], parts[1]
		} else {
			uc.hostname = rawHost
		}

		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.updateHost(ctx)
		})
	case irc.ERR_NICKLOCKED, irc.RPL_SASLSUCCESS, irc.ERR_SASLFAIL, irc.ERR_SASLTOOLONG, irc.ERR_SASLABORTED:
		var info string
		if err := parseMessageParams(msg, nil, &info); err != nil {
			return err
		}
		switch msg.Command {
		case irc.ERR_NICKLOCKED:
			uc.logger.Printf("invalid nick used with SASL authentication: %v", info)
		case irc.ERR_SASLFAIL:
			uc.logger.Printf("SASL authentication failed: %v", info)
		case irc.ERR_SASLTOOLONG:
			uc.logger.Printf("SASL message too long: %v", info)
		}

		uc.saslClient = nil
		uc.saslStarted = false

		if dc, _ := uc.dequeueCommand("AUTHENTICATE"); dc != nil && dc.sasl != nil {
			if msg.Command == irc.RPL_SASLSUCCESS {
				uc.network.autoSaveSASLPlain(ctx, dc.sasl.plain.Username, dc.sasl.plain.Password)
			}

			dc.endSASL(ctx, msg)
		}

		if !uc.registered {
			uc.SendMessage(ctx, &irc.Message{
				Command: "CAP",
				Params:  []string{"END"},
			})
		}
	case "REGISTER", "VERIFY":
		if dc, cmd := uc.dequeueCommand(msg.Command); dc != nil {
			if msg.Command == "REGISTER" {
				var account, password string
				if err := parseMessageParams(msg, nil, &account); err != nil {
					return err
				}
				if err := parseMessageParams(cmd, nil, nil, &password); err != nil {
					return err
				}
				uc.network.autoSaveSASLPlain(ctx, account, password)
			}

			dc.SendMessage(ctx, msg)
		}
	case irc.RPL_WELCOME:
		if err := parseMessageParams(msg, &uc.nick); err != nil {
			return err
		}

		uc.registered = true
		uc.serverPrefix = msg.Prefix
		uc.logger.Printf("connection registered with nick %q", uc.nick)

		if uc.network.channels.Len() > 0 {
			var channels, keys []string
			uc.network.channels.ForEach(func(_ string, ch *database.Channel) {
				channels = append(channels, ch.Name)
				keys = append(keys, ch.Key)
			})

			for _, msg := range xirc.GenerateJoin(channels, keys) {
				uc.SendMessage(ctx, msg)
			}
		}
	case irc.RPL_MYINFO:
		if err := parseMessageParams(msg, nil, &uc.serverName, nil, &uc.availableUserModes, nil); err != nil {
			return err
		}
	case irc.RPL_ISUPPORT:
		if err := parseMessageParams(msg, nil, nil); err != nil {
			return err
		}

		var downstreamIsupport []string
		for _, token := range msg.Params[1 : len(msg.Params)-1] {
			parameter := token
			var negate, hasValue bool
			var value string
			if strings.HasPrefix(token, "-") {
				negate = true
				token = token[1:]
			} else if i := strings.IndexByte(token, '='); i >= 0 {
				parameter = token[:i]
				value = token[i+1:]
				hasValue = true
			}
			parameter = strings.ToUpper(parameter)

			if hasValue {
				uc.isupport[parameter] = &value
			} else if !negate {
				uc.isupport[parameter] = nil
			} else {
				delete(uc.isupport, parameter)
			}

			var err error
			switch parameter {
			case "CASEMAPPING":
				casemap := xirc.ParseCaseMapping(value)
				if casemap == nil {
					casemap = xirc.CaseMappingRFC1459
				}
				uc.network.updateCasemapping(casemap)
			case "CHANMODES":
				if !negate {
					err = uc.handleChanModes(value)
				} else {
					uc.availableChannelModes = stdChannelModes
				}
			case "CHANTYPES":
				if !negate {
					uc.availableChannelTypes = value
				} else {
					uc.availableChannelTypes = stdChannelTypes
				}
			case "STATUSMSG":
				if !negate {
					uc.availableStatusMsg = value
				} else {
					uc.availableStatusMsg = ""
				}
			case "PREFIX":
				if !negate {
					err = uc.handleMemberships(value)
				} else {
					uc.availableMemberships = stdMemberships
				}
			case "SOJU.IM/SAFERATE":
				uc.rateLimit = negate
			}
			if err != nil {
				return err
			}

			if passthroughIsupport[parameter] {
				downstreamIsupport = append(downstreamIsupport, token)
			}
		}

		uc.updateMonitor()

		uc.forEachDownstream(func(dc *downstreamConn) {
			msgs := xirc.GenerateIsupport(downstreamIsupport)
			for _, msg := range msgs {
				dc.SendMessage(ctx, msg)
			}
		})
	case irc.ERR_NOMOTD, irc.RPL_ENDOFMOTD:
		if !uc.gotMotd {
			// Ignore the initial MOTD upon connection, but forward
			// subsequent MOTD messages downstream
			uc.gotMotd = true

			// If upstream did not send any CASEMAPPING token, assume it
			// implements the old RFCs with rfc1459.
			if uc.isupport["CASEMAPPING"] == nil {
				uc.network.updateCasemapping(stdCaseMapping)
			}

			// If the server doesn't support MONITOR, periodically try to
			// regain our desired nick
			if _, ok := uc.isupport["MONITOR"]; !ok {
				uc.startRegainNickTimer()
			}

			return nil
		}

		uc.forwardMsgByID(ctx, downstreamID, msg)
	case "BATCH":
		var tag string
		if err := parseMessageParams(msg, &tag); err != nil {
			return err
		}

		if strings.HasPrefix(tag, "+") {
			tag = tag[1:]
			if _, ok := uc.batches[tag]; ok {
				return fmt.Errorf("unexpected BATCH reference tag: batch was already defined: %q", tag)
			}
			var batchType string
			if err := parseMessageParams(msg, nil, &batchType); err != nil {
				return err
			}
			label := label
			if label == "" && msgBatch != nil {
				label = msgBatch.Label
			}
			uc.batches[tag] = upstreamBatch{
				Type:   batchType,
				Params: msg.Params[2:],
				Outer:  msgBatch,
				Label:  label,
			}
		} else if strings.HasPrefix(tag, "-") {
			tag = tag[1:]
			if _, ok := uc.batches[tag]; !ok {
				return fmt.Errorf("unknown BATCH reference tag: %q", tag)
			}
			delete(uc.batches, tag)
		} else {
			return fmt.Errorf("unexpected BATCH reference tag: missing +/- prefix: %q", tag)
		}
	case "NICK":
		var newNick string
		if err := parseMessageParams(msg, &newNick); err != nil {
			return err
		}

		me := false
		if uc.isOurNick(msg.Prefix.Name) {
			uc.logger.Printf("changed nick from %q to %q", uc.nick, newNick)
			me = true
			uc.nick = newNick

			if uc.network.equalCasemap(uc.pendingRegainNick, newNick) {
				uc.pendingRegainNick = ""
				uc.stopRegainNickTimer()
			}
			wantNick := database.GetNick(&uc.user.User, &uc.network.Network)
			if uc.network.equalCasemap(wantNick, newNick) {
				uc.hasDesiredNick = true
			}
		}

		uc.channels.ForEach(func(_ string, ch *upstreamChannel) {
			memberships := ch.Members.Get(msg.Prefix.Name)
			if memberships != nil {
				ch.Members.Del(msg.Prefix.Name)
				ch.Members.Set(newNick, memberships)
				uc.appendLog(ch.Name, msg)
			}
		})

		uc.cacheUserInfo(msg.Prefix.Name, &upstreamUser{
			Nickname: newNick,
		})

		if !me {
			uc.forwardMessage(ctx, msg)
		} else {
			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.updateNick(ctx)
			})
			uc.updateMonitor()
		}
	case "SETNAME":
		var newRealname string
		if err := parseMessageParams(msg, &newRealname); err != nil {
			return err
		}

		uc.cacheUserInfo(msg.Prefix.Name, &upstreamUser{
			Realname: newRealname,
		})

		// TODO: consider appending this message to logs

		if uc.isOurNick(msg.Prefix.Name) {
			uc.logger.Printf("changed realname from %q to %q", uc.realname, newRealname)
			uc.realname = newRealname

			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.updateRealname(ctx)
			})
		} else {
			uc.forwardMessage(ctx, msg)
		}
	case "CHGHOST":
		var newUsername, newHostname string
		if err := parseMessageParams(msg, &newUsername, &newHostname); err != nil {
			return err
		}

		newPrefix := &irc.Prefix{
			Name: uc.nick,
			User: newUsername,
			Host: newHostname,
		}

		if uc.isOurNick(msg.Prefix.Name) {
			uc.logger.Printf("changed prefix from %q to %q", msg.Prefix.Host, newPrefix)
			uc.username = newUsername
			uc.hostname = newHostname

			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.updateHost(ctx)
			})
		} else {
			// TODO: add fallback with QUIT/JOIN/MODE messages
			uc.forwardMessage(ctx, msg)
		}
	case "JOIN":
		var channels string
		if err := parseMessageParams(msg, &channels); err != nil {
			return err
		}

		uu := &upstreamUser{
			Username: msg.Prefix.User,
			Hostname: msg.Prefix.Host,
		}
		if uc.caps.IsEnabled("away-notify") {
			// we have enough info to build the user flags in a best-effort manner:
			// - the H/G flag is set to Here first, will be replaced by Gone later if the user is AWAY
			uu.Flags = "H"
			// - the B (bot mode) flag is set if the JOIN comes from a bot
			//   note: we have no way to track the user bot mode after they have joined
			//         (we are not notified of the bot mode updates), but this is good enough.
			if _, ok := msg.Tags["bot"]; ok {
				if bot := uc.isupport["BOT"]; bot != nil {
					uu.Flags += *bot
				}
			}
			// TODO: add the server operator flag (`*`) if the message has an oper-tag
		}
		if len(msg.Params) > 2 { // extended-join
			uu.Account = msg.Params[1]
			uu.Realname = msg.Params[2]
		}
		uc.cacheUserInfo(msg.Prefix.Name, uu)

		for _, ch := range strings.Split(channels, ",") {
			if uc.isOurNick(msg.Prefix.Name) {
				uc.logger.Printf("joined channel %q", ch)
				members := xirc.NewCaseMappingMap[*xirc.MembershipSet](uc.network.casemap)
				uc.channels.Set(ch, &upstreamChannel{
					Name:    ch,
					conn:    uc,
					Members: members,
				})
				uc.updateChannelAutoDetach(ch)

				uc.SendMessage(ctx, &irc.Message{
					Command: "MODE",
					Params:  []string{ch},
				})
			} else {
				ch, err := uc.getChannel(ch)
				if err != nil {
					return err
				}
				ch.Members.Set(msg.Prefix.Name, &xirc.MembershipSet{})
			}

			chMsg := msg.Copy()
			chMsg.Params[0] = ch
			uc.produce(ch, chMsg, 0)
		}
	case "PART":
		var channels string
		if err := parseMessageParams(msg, &channels); err != nil {
			return err
		}

		for _, ch := range strings.Split(channels, ",") {
			if uc.isOurNick(msg.Prefix.Name) {
				uc.logger.Printf("parted channel %q", ch)
				if uch := uc.channels.Get(ch); uch != nil {
					uc.channels.Del(ch)
					uch.updateAutoDetach(0)
					uch.Members.ForEach(func(nick string, memberships *xirc.MembershipSet) {
						if !uc.shouldCacheUserInfo(nick) {
							uc.users.Del(nick)
						}
					})
				}
			} else {
				ch, err := uc.getChannel(ch)
				if err != nil {
					return err
				}
				ch.Members.Del(msg.Prefix.Name)
				if !uc.shouldCacheUserInfo(msg.Prefix.Name) {
					uc.users.Del(msg.Prefix.Name)
				}
			}

			chMsg := msg.Copy()
			chMsg.Params[0] = ch
			uc.produce(ch, chMsg, 0)
		}
	case "KICK":
		var channel, user string
		if err := parseMessageParams(msg, &channel, &user); err != nil {
			return err
		}

		if uc.isOurNick(user) {
			uc.logger.Printf("kicked from channel %q by %s", channel, msg.Prefix.Name)
			if uch := uc.channels.Get(channel); uch != nil {
				uc.channels.Del(channel)
				uch.Members.ForEach(func(nick string, memberships *xirc.MembershipSet) {
					if !uc.shouldCacheUserInfo(nick) {
						uc.users.Del(nick)
					}
				})
			}
		} else {
			ch, err := uc.getChannel(channel)
			if err != nil {
				return err
			}
			ch.Members.Del(user)
			if !uc.shouldCacheUserInfo(user) {
				uc.users.Del(user)
			}
		}

		uc.produce(channel, msg, 0)
	case "QUIT":
		if uc.isOurNick(msg.Prefix.Name) {
			uc.logger.Printf("quit")
		}

		uc.channels.ForEach(func(_ string, ch *upstreamChannel) {
			if ch.Members.Has(msg.Prefix.Name) {
				ch.Members.Del(msg.Prefix.Name)
				uc.appendLog(ch.Name, msg)
			}
		})

		uc.users.Del(msg.Prefix.Name)

		if msg.Prefix.Name != uc.nick {
			uc.forwardMessage(ctx, msg)
		}
	case irc.RPL_TOPIC, irc.RPL_NOTOPIC:
		var name, topic string
		if err := parseMessageParams(msg, nil, &name, &topic); err != nil {
			return err
		}
		ch := uc.channels.Get(name)
		if ch == nil {
			uc.forwardMsgByID(ctx, downstreamID, msg)
		} else {
			if msg.Command == irc.RPL_TOPIC {
				ch.Topic = topic
			} else {
				ch.Topic = ""
			}
		}
	case "TOPIC":
		var name string
		if err := parseMessageParams(msg, &name); err != nil {
			return err
		}
		ch, err := uc.getChannel(name)
		if err != nil {
			return err
		}
		if len(msg.Params) > 1 {
			ch.Topic = msg.Params[1]
			ch.TopicWho = msg.Prefix.Copy()
			ch.TopicTime = time.Now() // TODO use msg.Tags["time"]
		} else {
			ch.Topic = ""
		}
		uc.produce(ch.Name, msg, 0)
	case "MODE":
		var name, modeStr string
		if err := parseMessageParams(msg, &name, &modeStr); err != nil {
			return err
		}

		if !uc.isChannel(name) { // user mode change
			if name != uc.nick {
				return fmt.Errorf("received MODE message for unknown nick %q", name)
			}

			if err := uc.modes.Apply(modeStr); err != nil {
				return err
			}

			uc.forwardMessage(ctx, msg)
		} else { // channel mode change
			ch, err := uc.getChannel(name)
			if err != nil {
				return err
			}

			err = applyChannelModes(ch, modeStr, msg.Params[2:])
			if err != nil {
				return err
			}

			uc.appendLog(ch.Name, msg)

			c := uc.network.channels.Get(name)
			if c == nil || !c.Detached {
				uc.forwardMessage(ctx, msg)
			}
		}
	case irc.RPL_UMODEIS:
		if err := parseMessageParams(msg, nil); err != nil {
			return err
		}
		modeStr := ""
		if len(msg.Params) > 1 {
			modeStr = msg.Params[1]
		}

		uc.modes = ""
		if err := uc.modes.Apply(modeStr); err != nil {
			return err
		}

		uc.forwardMessage(ctx, msg)
	case irc.RPL_CHANNELMODEIS:
		var channel string
		if err := parseMessageParams(msg, nil, &channel); err != nil {
			return err
		}
		modeStr := ""
		var modeArgs []string
		if len(msg.Params) > 2 {
			modeStr = msg.Params[2]
			modeArgs = msg.Params[3:]
		}

		ch := uc.channels.Get(channel)
		if ch == nil {
			uc.forwardMsgByID(ctx, downstreamID, msg)
			return nil
		}

		firstMode := ch.modes == nil
		ch.modes = make(map[byte]string)
		if err := applyChannelModes(ch, modeStr, modeArgs); err != nil {
			return err
		}

		c := uc.network.channels.Get(channel)
		if firstMode && (c == nil || !c.Detached) {
			uc.forwardMessage(ctx, msg)
		}
	case xirc.RPL_CREATIONTIME:
		var channel, creationTime string
		if err := parseMessageParams(msg, nil, &channel, &creationTime); err != nil {
			return err
		}

		ch := uc.channels.Get(channel)
		if ch == nil {
			uc.forwardMsgByID(ctx, downstreamID, msg)
			return nil
		}

		firstCreationTime := ch.creationTime == ""
		ch.creationTime = creationTime

		c := uc.network.channels.Get(channel)
		if firstCreationTime && (c == nil || !c.Detached) {
			uc.forwardMessage(ctx, msg)
		}
	case xirc.RPL_TOPICWHOTIME:
		var channel, who, timeStr string
		if err := parseMessageParams(msg, nil, &channel, &who, &timeStr); err != nil {
			return err
		}

		ch := uc.channels.Get(channel)
		if ch == nil {
			uc.forwardMsgByID(ctx, downstreamID, msg)
			return nil
		}

		firstTopicWhoTime := ch.TopicWho == nil
		ch.TopicWho = irc.ParsePrefix(who)
		sec, err := strconv.ParseInt(timeStr, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse topic time: %v", err)
		}
		ch.TopicTime = time.Unix(sec, 0)

		c := uc.network.channels.Get(channel)
		if firstTopicWhoTime && (c == nil || !c.Detached) {
			uc.forwardMessage(ctx, msg)
		}
	case irc.RPL_LISTSTART, irc.RPL_LIST:
		dc, cmd := uc.currentPendingCommand("LIST")
		if cmd == nil {
			return fmt.Errorf("unexpected RPL_LIST: no matching pending LIST")
		} else if dc == nil {
			return nil
		}

		dc.SendMessage(ctx, msg)
	case irc.RPL_LISTEND:
		dc, cmd := uc.dequeueCommand("LIST")
		if cmd == nil {
			return fmt.Errorf("unexpected RPL_LISTEND: no matching pending LIST")
		} else if dc == nil {
			return nil
		}

		dc.SendMessage(ctx, msg)
	case irc.RPL_NAMREPLY:
		var name, statusStr, members string
		if err := parseMessageParams(msg, nil, &statusStr, &name, &members); err != nil {
			return err
		}

		ch := uc.channels.Get(name)
		if ch == nil {
			// NAMES on a channel we have not joined, forward to downstream
			uc.forwardMsgByID(ctx, downstreamID, msg)
			return nil
		}

		status, err := xirc.ParseChannelStatus(statusStr)
		if err != nil {
			return err
		}
		ch.Status = status

		for _, s := range splitSpace(members) {
			memberships, nick := uc.parseMembershipPrefix(s)
			ch.Members.Set(nick, &memberships)
		}
	case irc.RPL_ENDOFNAMES:
		var name string
		if err := parseMessageParams(msg, nil, &name); err != nil {
			return err
		}

		ch := uc.channels.Get(name)
		if ch == nil {
			// NAMES on a channel we have not joined, forward to downstream
			uc.forwardMsgByID(ctx, downstreamID, msg)
			return nil
		}

		if ch.complete {
			return fmt.Errorf("received unexpected RPL_ENDOFNAMES")
		}
		ch.complete = true

		c := uc.network.channels.Get(name)
		if c == nil || !c.Detached {
			uc.forEachDownstream(func(dc *downstreamConn) {
				forwardChannel(ctx, dc, ch)
			})
		}
	case irc.RPL_WHOREPLY:
		var username, host, server, nick, flags, trailing string
		if err := parseMessageParams(msg, nil, nil, &username, &host, &server, &nick, &flags, &trailing); err != nil {
			return err
		}

		dc, cmd := uc.currentPendingCommand("WHO")
		if cmd == nil {
			return fmt.Errorf("unexpected RPL_WHOREPLY: no matching pending WHO")
		} else if dc == nil {
			return nil
		}

		parts := strings.SplitN(trailing, " ", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed RPL_WHOREPLY: failed to parse real name")
		}
		realname := parts[1]

		dc.SendMessage(ctx, msg)

		if uc.shouldCacheUserInfo(nick) {
			uc.cacheUserInfo(nick, &upstreamUser{
				Username: username,
				Hostname: host,
				Server:   server,
				Nickname: nick,
				Flags:    stripMemberPrefixes(flags, uc),
				Realname: realname,
			})
		}
	case xirc.RPL_WHOSPCRPL:
		dc, cmd := uc.currentPendingCommand("WHO")
		if cmd == nil {
			return fmt.Errorf("unexpected RPL_WHOSPCRPL: no matching pending WHO")
		} else if dc == nil {
			return nil
		}

		dc.SendMessage(ctx, msg)

		if len(cmd.Params) > 1 {
			fields, _ := xirc.ParseWHOXOptions(cmd.Params[1])
			if strings.IndexByte(fields, 'n') < 0 {
				return nil
			}
			info, err := xirc.ParseWHOXReply(msg, fields)
			if err != nil {
				return err
			}

			if uc.shouldCacheUserInfo(info.Nickname) {
				uc.cacheUserInfo(info.Nickname, &upstreamUser{
					Nickname: info.Nickname,
					Username: info.Username,
					Hostname: info.Hostname,
					Server:   info.Server,
					Flags:    stripMemberPrefixes(info.Flags, uc),
					Account:  info.Account,
					Realname: info.Realname,
				})
			}
		}
	case irc.RPL_ENDOFWHO:
		dc, cmd := uc.dequeueCommand("WHO")
		if cmd == nil {
			// Some servers send RPL_TRYAGAIN followed by RPL_ENDOFWHO
			return nil
		} else if dc == nil {
			// Downstream connection is gone
			return nil
		}

		dc.SendMessage(ctx, msg)
	case xirc.RPL_WHOISCERTFP, xirc.RPL_WHOISREGNICK, irc.RPL_WHOISUSER, irc.RPL_WHOISSERVER, irc.RPL_WHOISCHANNELS, irc.RPL_WHOISOPERATOR, irc.RPL_WHOISIDLE, xirc.RPL_WHOISSPECIAL, xirc.RPL_WHOISACCOUNT, xirc.RPL_WHOISACTUALLY, xirc.RPL_WHOISHOST, xirc.RPL_WHOISMODES, xirc.RPL_WHOISSECURE:
		dc, cmd := uc.currentPendingCommand("WHOIS")
		if cmd == nil {
			return fmt.Errorf("unexpected WHOIS reply %q: no matching pending WHOIS", msg.Command)
		} else if dc == nil {
			return nil
		}

		dc.SendMessage(ctx, msg)
	case irc.RPL_ENDOFWHOIS:
		dc, cmd := uc.dequeueCommand("WHOIS")
		if cmd == nil {
			return fmt.Errorf("unexpected RPL_ENDOFWHOIS: no matching pending WHOIS")
		} else if dc == nil {
			return nil
		}

		dc.SendMessage(ctx, msg)
	case "INVITE":
		var nick, channel string
		if err := parseMessageParams(msg, &nick, &channel); err != nil {
			return err
		}

		weAreInvited := uc.isOurNick(nick)

		if weAreInvited {
			joined := uc.channels.Get(channel) != nil
			c := uc.network.channels.Get(channel)
			if !joined && c != nil {
				// Automatically join a saved channel when we are invited
				for _, msg := range xirc.GenerateJoin([]string{c.Name}, []string{c.Key}) {
					uc.SendMessage(ctx, msg)
				}
				break
			}
		}

		uc.forEachDownstream(func(dc *downstreamConn) {
			if !weAreInvited && !dc.caps.IsEnabled("invite-notify") {
				return
			}
			dc.SendMessage(ctx, msg)
		})

		if weAreInvited {
			go uc.network.broadcastWebPush(msg)
		}
	case irc.RPL_INVITING:
		var nick, channel string
		if err := parseMessageParams(msg, nil, &nick, &channel); err != nil {
			return err
		}

		uc.forwardMsgByID(ctx, downstreamID, msg)
	case irc.RPL_MONONLINE, irc.RPL_MONOFFLINE:
		var targetsStr string
		if err := parseMessageParams(msg, nil, &targetsStr); err != nil {
			return err
		}
		targets := strings.Split(targetsStr, ",")

		online := msg.Command == irc.RPL_MONONLINE
		for _, target := range targets {
			prefix := irc.ParsePrefix(target)
			uc.monitored.Set(prefix.Name, online)
		}

		// Check if the nick we want is now free
		wantNick := database.GetNick(&uc.user.User, &uc.network.Network)
		if !online && !uc.isOurNick(wantNick) && !uc.hasDesiredNick {
			found := false
			for _, target := range targets {
				prefix := irc.ParsePrefix(target)
				if uc.network.equalCasemap(prefix.Name, wantNick) {
					found = true
					break
				}
			}
			if found {
				uc.logger.Printf("desired nick %q is now available", wantNick)
				uc.SendMessage(ctx, &irc.Message{
					Command: "NICK",
					Params:  []string{wantNick},
				})
			}
		}

		uc.forEachDownstream(func(dc *downstreamConn) {
			for _, target := range targets {
				prefix := irc.ParsePrefix(target)
				if dc.monitored.Has(prefix.Name) {
					dc.SendMessage(ctx, &irc.Message{
						Command: msg.Command,
						Params:  []string{dc.nick, target},
					})
				}
			}
		})
	case irc.ERR_MONLISTFULL:
		var limit, targetsStr string
		if err := parseMessageParams(msg, nil, &limit, &targetsStr); err != nil {
			return err
		}

		targets := strings.Split(targetsStr, ",")
		uc.forEachDownstream(func(dc *downstreamConn) {
			for _, target := range targets {
				if dc.monitored.Has(target) {
					dc.SendMessage(ctx, &irc.Message{
						Command: msg.Command,
						Params:  []string{dc.nick, limit, target},
					})
				}
			}
		})
	case irc.RPL_AWAY:
		uc.forwardMsgByID(ctx, downstreamID, msg)
	case "AWAY":
		// Update user flags, if we already have the flags cached
		uu := uc.users.Get(msg.Prefix.Name)
		if uu != nil && uu.Flags != "" {
			flags := uu.Flags
			if isAway := len(msg.Params) > 0; isAway {
				flags = strings.ReplaceAll(flags, "H", "G")
			} else {
				flags = strings.ReplaceAll(flags, "G", "H")
			}
			uc.cacheUserInfo(msg.Prefix.Name, &upstreamUser{
				Flags: flags,
			})
		}

		uc.forwardMessage(ctx, msg)
	case "ACCOUNT":
		var account string
		if err := parseMessageParams(msg, &account); err != nil {
			return err
		}
		uc.cacheUserInfo(msg.Prefix.Name, &upstreamUser{
			Account: account,
		})
		uc.forwardMessage(ctx, msg)
	case irc.RPL_BANLIST, irc.RPL_INVITELIST, irc.RPL_EXCEPTLIST, irc.RPL_ENDOFBANLIST, irc.RPL_ENDOFINVITELIST, irc.RPL_ENDOFEXCEPTLIST:
		uc.forwardMsgByID(ctx, downstreamID, msg)
	case irc.ERR_NOSUCHNICK, irc.ERR_NOSUCHSERVER:
		// one argument WHOIS variant errors with NOSUCHNICK
		// two argument WHOIS variant errors with NOSUCHSERVER
		var nick, reason string
		if err := parseMessageParams(msg, nil, &nick, &reason); err != nil {
			return err
		}

		cm := uc.network.casemap
		dc, cmd := uc.currentPendingCommand("WHOIS")
		if cmd != nil && cm(cmd.Params[len(cmd.Params)-1]) == cm(nick) {
			uc.dequeueCommand("WHOIS")
			if dc != nil {
				dc.SendMessage(ctx, msg)
			}
		} else {
			uc.forwardMsgByID(ctx, downstreamID, msg)
		}
	case xirc.ERR_UNKNOWNERROR, irc.ERR_UNKNOWNCOMMAND, irc.ERR_NEEDMOREPARAMS, irc.RPL_TRYAGAIN:
		var command, reason string
		if err := parseMessageParams(msg, nil, &command, &reason); err != nil {
			return err
		}

		if dc, _ := uc.dequeueCommand(command); dc != nil && downstreamID == 0 {
			downstreamID = dc.id
		}

		if command == "AUTHENTICATE" {
			uc.saslClient = nil
			uc.saslStarted = false
		}

		uc.forwardMsgByID(ctx, downstreamID, msg)
	case "FAIL":
		var command, code string
		if err := parseMessageParams(msg, &command, &code); err != nil {
			return err
		}

		if !uc.registered && command == "*" && code == "ACCOUNT_REQUIRED" {
			return registrationError{msg}
		}

		if dc, _ := uc.dequeueCommand(command); dc != nil && downstreamID == 0 {
			downstreamID = dc.id
		}

		uc.forwardMsgByID(ctx, downstreamID, msg)
	case "ACK":
		// Ignore
	case irc.RPL_NOWAWAY, irc.RPL_UNAWAY:
		// Ignore
	case irc.RPL_YOURHOST, irc.RPL_CREATED:
		// Ignore
	case irc.RPL_LUSERCLIENT, irc.RPL_LUSEROP, irc.RPL_LUSERUNKNOWN, irc.RPL_LUSERCHANNELS, irc.RPL_LUSERME:
		fallthrough
	case irc.RPL_STATSVLINE, xirc.RPL_STATSPING, irc.RPL_STATSBLINE, irc.RPL_STATSDLINE:
		fallthrough
	case xirc.RPL_LOCALUSERS, xirc.RPL_GLOBALUSERS:
		fallthrough
	case irc.RPL_MOTDSTART, irc.RPL_MOTD:
		// Ignore these messages if they're part of the initial registration
		// message burst. Forward them if the user explicitly asked for them.
		if !uc.gotMotd {
			return nil
		}

		uc.forwardMsgByID(ctx, downstreamID, msg)
	case "ERROR":
		var text string
		if err := parseMessageParams(msg, &text); err != nil {
			return err
		}
		return fmt.Errorf("fatal server error: %v", text)
	case irc.ERR_NICKNAMEINUSE:
		// At this point, we haven't received ISUPPORT so we don't know the
		// maximum nickname length or whether the server supports MONITOR. Many
		// servers have NICKLEN=30 so let's just use that.
		if !uc.registered && len(uc.nick)+1 < 30 {
			uc.nick = uc.nick + "_"
			uc.hasDesiredNick = false
			uc.logger.Printf("desired nick is not available, falling back to %q", uc.nick)
			uc.SendMessage(ctx, &irc.Message{
				Command: "NICK",
				Params:  []string{uc.nick},
			})
			return nil
		}

		var failedNick string
		if err := parseMessageParams(msg, nil, &failedNick); err != nil {
			return err
		}
		if uc.network.equalCasemap(uc.pendingRegainNick, failedNick) {
			// This message comes from our own logic to try to regain our
			// desired nick, don't relay to downstream connections
			uc.pendingRegainNick = ""
			return nil
		}

		fallthrough
	case irc.ERR_PASSWDMISMATCH, irc.ERR_ERRONEUSNICKNAME, irc.ERR_NICKCOLLISION, irc.ERR_UNAVAILRESOURCE, irc.ERR_NOPERMFORHOST, irc.ERR_YOUREBANNEDCREEP:
		if !uc.registered {
			return registrationError{msg}
		}
		uc.forwardMsgByID(ctx, downstreamID, msg)
	default:
		uc.logger.Debugf("unhandled message: %v", msg)
		uc.forwardMsgByID(ctx, downstreamID, msg)
	}
	return nil
}

func (uc *upstreamConn) handleDetachedMessage(ctx context.Context, ch *database.Channel, msg *irc.Message) {
	if uc.network.detachedMessageNeedsRelay(ch, msg) {
		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.relayDetachedMessage(uc.network, msg)
		})
	}
	if ch.ReattachOn == database.FilterMessage || (ch.ReattachOn == database.FilterHighlight && uc.network.isHighlight(msg)) {
		uc.network.attach(ctx, ch)
		if err := uc.srv.db.StoreChannel(ctx, uc.network.ID, ch); err != nil {
			uc.logger.Printf("failed to update channel %q: %v", ch.Name, err)
		}
	}
}

func (uc *upstreamConn) handleChanModes(s string) error {
	parts := strings.SplitN(s, ",", 5)
	if len(parts) < 4 {
		return fmt.Errorf("malformed ISUPPORT CHANMODES value: %v", s)
	}
	modes := make(map[byte]channelModeType)
	for i, mt := range []channelModeType{modeTypeA, modeTypeB, modeTypeC, modeTypeD} {
		for j := 0; j < len(parts[i]); j++ {
			mode := parts[i][j]
			modes[mode] = mt
		}
	}
	uc.availableChannelModes = modes
	return nil
}

func (uc *upstreamConn) handleMemberships(s string) error {
	if s == "" {
		uc.availableMemberships = nil
		return nil
	}

	if s[0] != '(' {
		return fmt.Errorf("malformed ISUPPORT PREFIX value: %v", s)
	}
	sep := strings.IndexByte(s, ')')
	if sep < 0 || len(s) != sep*2 {
		return fmt.Errorf("malformed ISUPPORT PREFIX value: %v", s)
	}
	memberships := make([]xirc.Membership, len(s)/2-1)
	for i := range memberships {
		memberships[i] = xirc.Membership{
			Mode:   s[i+1],
			Prefix: s[sep+i+1],
		}
	}
	uc.availableMemberships = memberships
	return nil
}

func (uc *upstreamConn) handleSupportedCaps(capsStr string) {
	caps := strings.Fields(capsStr)
	for _, s := range caps {
		kv := strings.SplitN(s, "=", 2)
		k := strings.ToLower(kv[0])
		var v string
		if len(kv) == 2 {
			v = kv[1]
		}
		uc.caps.Available[k] = v
	}
}

func (uc *upstreamConn) updateCaps(ctx context.Context) {
	var requestCaps []string
	for c := range permanentUpstreamCaps {
		if uc.caps.IsAvailable(c) && !uc.caps.IsEnabled(c) {
			requestCaps = append(requestCaps, c)
		}
	}

	echoMessage := uc.caps.IsAvailable("labeled-response")
	if !uc.caps.IsEnabled("echo-message") && echoMessage {
		requestCaps = append(requestCaps, "echo-message")
	} else if uc.caps.IsEnabled("echo-message") && !echoMessage {
		requestCaps = append(requestCaps, "-echo-message")
	}

	if len(requestCaps) == 0 {
		return
	}

	uc.SendMessage(ctx, &irc.Message{
		Command: "CAP",
		Params:  []string{"REQ", strings.Join(requestCaps, " ")},
	})
}

func (uc *upstreamConn) supportsSASL(mech string) bool {
	v, ok := uc.caps.Available["sasl"]
	if !ok {
		return false
	}

	if v == "" {
		return true
	}

	mechanisms := strings.Split(v, ",")
	for _, m := range mechanisms {
		if strings.EqualFold(m, mech) {
			return true
		}
	}
	return false
}

func (uc *upstreamConn) requestSASL() bool {
	if uc.network.SASL.Mechanism == "" {
		return false
	}
	return uc.supportsSASL(uc.network.SASL.Mechanism)
}

func (uc *upstreamConn) handleCapAck(ctx context.Context, name string, ok bool) error {
	uc.caps.SetEnabled(name, ok)

	switch name {
	case "sasl":
		if !uc.requestSASL() {
			return nil
		}
		if !ok {
			uc.logger.Printf("server refused to acknowledge the SASL capability")
			return nil
		}

		auth := &uc.network.SASL
		switch auth.Mechanism {
		case "PLAIN":
			uc.logger.Printf("starting SASL PLAIN authentication with username %q", auth.Plain.Username)
			uc.saslClient = sasl.NewPlainClient("", auth.Plain.Username, auth.Plain.Password)
		case "EXTERNAL":
			uc.logger.Printf("starting SASL EXTERNAL authentication")
			uc.saslClient = sasl.NewExternalClient("")
		default:
			return fmt.Errorf("unsupported SASL mechanism %q", name)
		}

		uc.SendMessage(ctx, &irc.Message{
			Command: "AUTHENTICATE",
			Params:  []string{auth.Mechanism},
		})
	case "echo-message":
	default:
		if permanentUpstreamCaps[name] {
			break
		}
		uc.logger.Printf("received CAP ACK/NAK for a cap we don't support: %v", name)
	}
	return nil
}

func splitSpace(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' '
	})
}

func (uc *upstreamConn) register(ctx context.Context) {
	uc.nick = database.GetNick(&uc.user.User, &uc.network.Network)
	uc.username = database.GetUsername(&uc.user.User, &uc.network.Network)
	uc.realname = database.GetRealname(&uc.user.User, &uc.network.Network)

	uc.SendMessage(ctx, &irc.Message{
		Command: "CAP",
		Params:  []string{"LS", "302"},
	})

	if uc.network.Pass != "" {
		uc.SendMessage(ctx, &irc.Message{
			Command: "PASS",
			Params:  []string{uc.network.Pass},
		})
	}

	uc.SendMessage(ctx, &irc.Message{
		Command: "NICK",
		Params:  []string{uc.nick},
	})
	uc.SendMessage(ctx, &irc.Message{
		Command: "USER",
		Params:  []string{uc.username, "0", "*", uc.realname},
	})
}

func (uc *upstreamConn) ReadMessage() (*irc.Message, error) {
	msg, err := uc.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	uc.srv.metrics.upstreamInMessagesTotal.Inc()
	return msg, nil
}

func (uc *upstreamConn) runUntilRegistered(ctx context.Context) error {
	for !uc.registered {
		msg, err := uc.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to read message: %v", err)
		}

		if err := uc.handleMessage(ctx, msg); err != nil {
			if _, ok := err.(registrationError); ok {
				return err
			} else {
				msg.Tags = nil // prevent message tags from cluttering logs
				return fmt.Errorf("failed to handle message %q: %v", msg, err)
			}
		}
	}

	for _, command := range uc.network.ConnectCommands {
		m, err := irc.ParseMessage(command)
		if err != nil {
			uc.logger.Printf("failed to parse connect command %q: %v", command, err)
		} else {
			uc.SendMessage(ctx, m)
		}
	}

	return nil
}

func (uc *upstreamConn) readMessages(ch chan<- event) error {
	for {
		msg, err := uc.ReadMessage()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read IRC command: %v", err)
		}

		ch <- eventUpstreamMessage{msg, uc}
	}

	return nil
}

func (uc *upstreamConn) SendMessage(ctx context.Context, msg *irc.Message) {
	if !uc.caps.IsEnabled("message-tags") {
		msg = msg.Copy()
		msg.Tags = nil
	}

	uc.srv.metrics.upstreamOutMessagesTotal.Inc()
	uc.conn.SendMessage(ctx, msg)
}

func (uc *upstreamConn) SendMessageLabeled(ctx context.Context, downstreamID uint64, msg *irc.Message) {
	if uc.caps.IsEnabled("labeled-response") {
		if msg.Tags == nil {
			msg.Tags = make(irc.Tags)
		}
		msg.Tags["label"] = fmt.Sprintf("sd-%d-%d", downstreamID, uc.nextLabelID)
		uc.nextLabelID++
	}
	uc.SendMessage(ctx, msg)
}

// appendLog appends a message to the log file.
//
// The internal message ID is returned. If the message isn't recorded in the
// log file, an empty string is returned.
func (uc *upstreamConn) appendLog(entity string, msg *irc.Message) (msgID string) {
	if uc.user.msgStore == nil {
		return ""
	}
	if msg.Command == "TAGMSG" {
		store := false
		for tag := range msg.Tags {
			if storableMessageTags[tag] {
				store = true
				break
			}
		}
		if !store {
			return ""
		}
	}

	// Don't store messages with a server mask target
	if strings.HasPrefix(entity, "$") {
		return ""
	}

	entityCM := uc.network.casemap(entity)
	if entityCM == "nickserv" {
		// The messages sent/received from NickServ may contain
		// security-related information (like passwords). Don't store these.
		return ""
	}

	if !uc.network.delivered.Empty() && !uc.network.delivered.HasTarget(entity) {
		// This is the first message we receive from this target. Save the last
		// message ID in delivery receipts, so that we can send the new message
		// in the backlog if an offline client reconnects.
		lastID, err := uc.user.msgStore.LastMsgID(&uc.network.Network, entityCM, time.Now())
		if err != nil {
			uc.logger.Printf("failed to log message: failed to get last message ID: %v", err)
			return ""
		}

		uc.network.delivered.ForEachClient(func(clientName string) {
			uc.network.delivered.StoreID(entity, clientName, lastID)
		})
	}

	msgID, err := uc.user.msgStore.Append(&uc.network.Network, entityCM, msg)
	if err != nil {
		uc.logger.Printf("failed to append message to store: %v", err)
		return ""
	}

	return msgID
}

// produce appends a message to the logs and forwards it to connected downstream
// connections.
//
// originID is the id of the downstream (origin) that sent the message. If it is not 0
// and origin doesn't support echo-message, the message is forwarded to all
// connections except origin.
func (uc *upstreamConn) produce(target string, msg *irc.Message, originID uint64) {
	var msgID string
	if target != "" {
		msgID = uc.appendLog(target, msg)
	}

	// Don't forward messages if it's a detached channel
	ch := uc.network.channels.Get(target)
	detached := ch != nil && ch.Detached

	ctx := context.TODO()
	uc.forEachDownstream(func(dc *downstreamConn) {
		echo := dc.id == originID && msg.Prefix != nil && uc.isOurNick(msg.Prefix.Name)
		if !detached && (!echo || dc.caps.IsEnabled("echo-message")) {
			dc.sendMessageWithID(ctx, msg, msgID)
		} else {
			dc.advanceMessageWithID(ctx, msg, msgID)
		}
	})
}

func (uc *upstreamConn) updateAway() {
	ctx := context.TODO()

	if !uc.network.AutoAway {
		return
	}

	away := true
	uc.forEachDownstream(func(dc *downstreamConn) {
		if dc.away == nil {
			away = false
		}
	})
	if away == uc.away {
		return
	}
	if away {
		reason := "Auto away"
		if uc.caps.IsAvailable("draft/pre-away") {
			reason = "*"
		}
		uc.SendMessage(ctx, &irc.Message{
			Command: "AWAY",
			Params:  []string{reason},
		})
	} else {
		uc.SendMessage(ctx, &irc.Message{
			Command: "AWAY",
		})
	}
	uc.away = away
}

func (uc *upstreamConn) updateChannelAutoDetach(name string) {
	uch := uc.channels.Get(name)
	if uch == nil {
		return
	}
	ch := uc.network.channels.Get(name)
	if ch == nil || ch.Detached {
		return
	}
	uch.updateAutoDetach(ch.DetachAfter)
}

func (uc *upstreamConn) updateMonitor() {
	if _, ok := uc.isupport["MONITOR"]; !ok {
		return
	}

	ctx := context.TODO()

	add := make(map[string]struct{})
	var addList []string
	seen := make(map[string]struct{})
	uc.forEachDownstream(func(dc *downstreamConn) {
		dc.monitored.ForEach(func(target string, _ struct{}) {
			targetCM := uc.network.casemap(target)
			if targetCM == serviceNickCM {
				return
			}
			if !uc.monitored.Has(targetCM) {
				if _, ok := add[targetCM]; !ok {
					addList = append(addList, targetCM)
					add[targetCM] = struct{}{}
				}
			} else {
				seen[targetCM] = struct{}{}
			}
		})
	})

	wantNick := database.GetNick(&uc.user.User, &uc.network.Network)
	wantNickCM := uc.network.casemap(wantNick)
	if _, ok := add[wantNickCM]; !ok && !uc.monitored.Has(wantNick) && !uc.isOurNick(wantNick) && !uc.hasDesiredNick {
		addList = append(addList, wantNickCM)
		add[wantNickCM] = struct{}{}
	}

	removeAll := true
	var removeList []string
	uc.monitored.ForEach(func(nick string, online bool) {
		if _, ok := seen[uc.network.casemap(nick)]; ok {
			removeAll = false
		} else {
			removeList = append(removeList, nick)
		}
	})

	// TODO: better handle the case where len(uc.monitored) + len(addList)
	// exceeds the limit, probably by immediately sending ERR_MONLISTFULL?

	if removeAll && len(addList) == 0 && len(removeList) > 0 {
		// Optimization when the last MONITOR-aware downstream disconnects
		uc.SendMessage(ctx, &irc.Message{
			Command: "MONITOR",
			Params:  []string{"C"},
		})
	} else {
		msgs := xirc.GenerateMonitor("-", removeList)
		msgs = append(msgs, xirc.GenerateMonitor("+", addList)...)
		for _, msg := range msgs {
			uc.SendMessage(ctx, msg)
		}
	}

	for _, target := range removeList {
		uc.monitored.Del(target)
		if !uc.shouldCacheUserInfo(target) {
			uc.users.Del(target)
		}
	}
}

func (uc *upstreamConn) stopRegainNickTimer() {
	if uc.regainNickTimer != nil {
		uc.regainNickTimer.Stop()
		// Maybe we're racing with the timer goroutine, so maybe we'll receive
		// an eventTryRegainNick later on, but tryRegainNick handles that case
	}
	uc.regainNickTimer = nil
	uc.regainNickBackoff = nil
}

func (uc *upstreamConn) startRegainNickTimer() {
	if uc.regainNickBackoff != nil || uc.regainNickTimer != nil {
		panic("startRegainNickTimer called twice")
	}

	wantNick := database.GetNick(&uc.user.User, &uc.network.Network)
	if uc.isOurNick(wantNick) {
		return
	}

	const (
		min    = 15 * time.Second
		max    = 10 * time.Minute
		jitter = 10 * time.Second
	)
	uc.regainNickBackoff = newBackoffer(min, max, jitter)
	uc.regainNickTimer = time.AfterFunc(uc.regainNickBackoff.Next(), func() {
		e := eventTryRegainNick{uc: uc, nick: wantNick}
		select {
		case uc.network.user.events <- e:
			// ok
		default:
			uc.logger.Printf("skipping nick regain attempt: event queue is full")
		}
	})
}

func (uc *upstreamConn) tryRegainNick(nick string) {
	ctx := context.TODO()

	if uc.regainNickTimer == nil {
		return
	}

	// Maybe the user has updated their desired nick
	wantNick := database.GetNick(&uc.user.User, &uc.network.Network)
	if wantNick != nick || uc.isOurNick(wantNick) {
		uc.stopRegainNickTimer()
		return
	}

	uc.regainNickTimer.Reset(uc.regainNickBackoff.Next())

	if uc.pendingRegainNick != "" {
		return
	}

	uc.SendMessage(ctx, &irc.Message{
		Command: "NICK",
		Params:  []string{wantNick},
	})
	uc.pendingRegainNick = wantNick
}

func (uc *upstreamConn) getCachedWHO(mask, fields string) (l []*upstreamUser, ok bool) {
	// Non-extended WHO fields
	if fields == "" {
		fields = "cuhsnfdr"
	}

	// Some extensions are required to keep our cached state in sync. We could
	// require setname for 'r' and chghost for 'h'/'s', but servers usually
	// implement a QUIT/JOIN fallback, so let's not bother.

	// TODO: Avoid storing fields we cannot keep up to date, instead of storing them
	//       then failing here. eg if we don't have account-notify, avoid storing the ACCOUNT
	//       in the first place.
	if strings.IndexByte(fields, 'a') >= 0 && !uc.caps.IsEnabled("account-notify") {
		return nil, false
	}
	if strings.IndexByte(fields, 'f') >= 0 && !uc.caps.IsEnabled("away-notify") {
		return nil, false
	}

	if uu := uc.users.Get(mask); uu != nil {
		if uu.hasWHOXFields(fields) {
			return []*upstreamUser{uu}, true
		}
	} else if uch := uc.channels.Get(mask); uch != nil {
		l = make([]*upstreamUser, 0, uch.Members.Len())
		ok = true
		uch.Members.ForEach(func(nick string, membershipSet *xirc.MembershipSet) {
			if !ok {
				return
			}
			uu := uc.users.Get(nick)
			if uu == nil || !uu.hasWHOXFields(fields) {
				ok = false
			} else {
				l = append(l, uu)
			}
		})
		if !ok {
			return nil, false
		}
		return l, true
	}

	return nil, false
}

func (uc *upstreamConn) cacheUserInfo(nick string, info *upstreamUser) {
	if nick == "" {
		panic("cacheUserInfo called with empty nickname")
	}

	uu := uc.users.Get(nick)
	if uu == nil {
		if info.Nickname != "" {
			nick = info.Nickname
		} else {
			info.Nickname = nick
		}
		uc.users.Set(info.Nickname, info)
	} else {
		uu.updateFrom(info)
		if info.Nickname != "" && nick != info.Nickname {
			uc.users.Del(nick)
			uc.users.Set(uu.Nickname, uu)
		}
	}
}

func (uc *upstreamConn) shouldCacheUserInfo(nick string) bool {
	if uc.isOurNick(nick) {
		return true
	}
	// keep the cached user info only if we MONITOR it, or we share a channel with them
	if uc.monitored.Has(nick) {
		return true
	}
	found := false
	uc.channels.ForEach(func(_ string, ch *upstreamChannel) {
		found = found || ch.Members.Has(nick)
	})
	return found
}

// resolveIPAddr replaces the standard library's DNS resolver to randomize the
// result order instead of always returning the same IP address. The bouncer
// will often have bursts of connections to the same host (e.g. on startup) so
// it's more important for our use-case to distribute the traffic among
// available IP addresses than to find the fastest link.
//
// See: https://todo.sr.ht/~emersion/soju/221
func resolveIPAddr(ctx context.Context, host string) (*net.IPAddr, error) {
	ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	// Prefer IPv6 if available, for per-user local IP addresses
	ip6Addrs := make([]net.IPAddr, 0, len(ipAddrs))
	for _, ipAddr := range ipAddrs {
		if ipAddr.IP.To4() == nil {
			ip6Addrs = append(ip6Addrs, ipAddr)
		}
	}
	if len(ip6Addrs) > 0 {
		ipAddrs = ip6Addrs
	}

	i := rand.Intn(len(ipAddrs))
	return &ipAddrs[i], nil
}
