package soju

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-sasl"
	"gopkg.in/irc.v3"
)

// permanentUpstreamCaps is the static list of upstream capabilities always
// requested when supported.
var permanentUpstreamCaps = map[string]bool{
	"away-notify":      true,
	"batch":            true,
	"labeled-response": true,
	"message-tags":     true,
	"multi-prefix":     true,
	"server-time":      true,
}

type upstreamChannel struct {
	Name         string
	conn         *upstreamConn
	Topic        string
	TopicWho     string
	TopicTime    time.Time
	Status       channelStatus
	modes        channelModes
	creationTime string
	Members      map[string]*memberships
	complete     bool
}

type upstreamConn struct {
	conn

	network *network
	user    *user

	serverName            string
	availableUserModes    string
	availableChannelModes map[byte]channelModeType
	availableChannelTypes string
	availableMemberships  []membership

	registered    bool
	nick          string
	username      string
	realname      string
	modes         userModes
	channels      map[string]*upstreamChannel
	supportedCaps map[string]string
	caps          map[string]bool
	batches       map[string]batch
	away          bool
	nextLabelID   uint64

	saslClient  sasl.Client
	saslStarted bool

	// set of LIST commands in progress, per downstream
	pendingLISTDownstreamSet map[uint64]struct{}

	messageLoggers map[string]*messageLogger
}

func connectToUpstream(network *network) (*upstreamConn, error) {
	logger := &prefixLogger{network.user.srv.Logger, fmt.Sprintf("upstream %q: ", network.Addr)}

	var scheme string
	var addr string

	addrParts := strings.SplitN(network.Addr, "://", 2)
	if len(addrParts) == 2 {
		scheme = addrParts[0]
		addr = addrParts[1]
	} else {
		scheme = "ircs"
		addr = addrParts[0]
	}

	dialer := net.Dialer{Timeout: connectTimeout}

	var netConn net.Conn
	var err error
	switch scheme {
	case "ircs":
		if !strings.ContainsRune(addr, ':') {
			addr = addr + ":6697"
		}

		logger.Printf("connecting to TLS server at address %q", addr)

		var cfg *tls.Config
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
			cfg = &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{network.SASL.External.CertBlob},
						PrivateKey:  key.(crypto.PrivateKey),
					},
				},
			}
			logger.Printf("using TLS client certificate %x", sha256.Sum256(network.SASL.External.CertBlob))
		}

		netConn, err = tls.DialWithDialer(&dialer, "tcp", addr, cfg)
	case "irc+insecure":
		if !strings.ContainsRune(addr, ':') {
			addr = addr + ":6667"
		}

		logger.Printf("connecting to plain-text server at address %q", addr)
		netConn, err = dialer.Dial("tcp", addr)
	default:
		return nil, fmt.Errorf("failed to dial %q: unknown scheme: %v", addr, scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to dial %q: %v", addr, err)
	}

	uc := &upstreamConn{
		conn:                     *newConn(network.user.srv, newNetIRCConn(netConn), logger),
		network:                  network,
		user:                     network.user,
		channels:                 make(map[string]*upstreamChannel),
		supportedCaps:            make(map[string]string),
		caps:                     make(map[string]bool),
		batches:                  make(map[string]batch),
		availableChannelTypes:    stdChannelTypes,
		availableChannelModes:    stdChannelModes,
		availableMemberships:     stdMemberships,
		pendingLISTDownstreamSet: make(map[uint64]struct{}),
		messageLoggers:           make(map[string]*messageLogger),
	}

	return uc, nil
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

func (uc *upstreamConn) getChannel(name string) (*upstreamChannel, error) {
	ch, ok := uc.channels[name]
	if !ok {
		return nil, fmt.Errorf("unknown channel %q", name)
	}
	return ch, nil
}

func (uc *upstreamConn) isChannel(entity string) bool {
	if i := strings.IndexByte(uc.availableChannelTypes, entity[0]); i >= 0 {
		return true
	}
	return false
}

func (uc *upstreamConn) getPendingLIST() *pendingLIST {
	for _, pl := range uc.user.pendingLISTs {
		if _, ok := pl.pendingCommands[uc.network.ID]; !ok {
			continue
		}
		return &pl
	}
	return nil
}

func (uc *upstreamConn) endPendingLISTs(all bool) (found bool) {
	found = false
	for i := 0; i < len(uc.user.pendingLISTs); i++ {
		pl := uc.user.pendingLISTs[i]
		if _, ok := pl.pendingCommands[uc.network.ID]; !ok {
			continue
		}
		delete(pl.pendingCommands, uc.network.ID)
		if len(pl.pendingCommands) == 0 {
			uc.user.pendingLISTs = append(uc.user.pendingLISTs[:i], uc.user.pendingLISTs[i+1:]...)
			i--
			uc.forEachDownstreamByID(pl.downstreamID, func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_LISTEND,
					Params:  []string{dc.nick, "End of /LIST"},
				})
			})
		}
		found = true
		if !all {
			delete(uc.pendingLISTDownstreamSet, pl.downstreamID)
			uc.user.forEachUpstream(func(uc *upstreamConn) {
				uc.trySendLIST(pl.downstreamID)
			})
			return
		}
	}
	return
}

func (uc *upstreamConn) trySendLIST(downstreamID uint64) {
	if _, ok := uc.pendingLISTDownstreamSet[downstreamID]; ok {
		// a LIST command is already pending
		// we will try again when that command is completed
		return
	}

	for _, pl := range uc.user.pendingLISTs {
		if pl.downstreamID != downstreamID {
			continue
		}
		// this is the first pending LIST command list of the downstream
		listCommand, ok := pl.pendingCommands[uc.network.ID]
		if !ok {
			// there is no command for this upstream in these LIST commands
			// do not send anything
			continue
		}
		// there is a command for this upstream in these LIST commands
		// send it now

		uc.SendMessageLabeled(downstreamID, listCommand)

		uc.pendingLISTDownstreamSet[downstreamID] = struct{}{}
		return
	}
}

func (uc *upstreamConn) parseMembershipPrefix(s string) (ms *memberships, nick string) {
	memberships := make(memberships, 0, 4)
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
	return &memberships, s[i:]
}

func isWordBoundary(r rune) bool {
	switch r {
	case '-', '_', '|':
		return false
	case '\u00A0':
		return true
	default:
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	}
}

func isHighlight(text, nick string) bool {
	for {
		i := strings.Index(text, nick)
		if i < 0 {
			return false
		}

		// Detect word boundaries
		var left, right rune
		if i > 0 {
			left, _ = utf8.DecodeLastRuneInString(text[:i])
		}
		if i < len(text) {
			right, _ = utf8.DecodeRuneInString(text[i+len(nick):])
		}
		if isWordBoundary(left) && isWordBoundary(right) {
			return true
		}

		text = text[i+len(nick):]
	}
}

func (uc *upstreamConn) handleMessage(msg *irc.Message) error {
	var label string
	if l, ok := msg.GetTag("label"); ok {
		label = l
	}

	var msgBatch *batch
	if batchName, ok := msg.GetTag("batch"); ok {
		b, ok := uc.batches[batchName]
		if !ok {
			return fmt.Errorf("unexpected batch reference: batch was not defined: %q", batchName)
		}
		msgBatch = &b
		if label == "" {
			label = msgBatch.Label
		}
	}

	var downstreamID uint64 = 0
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

	if _, ok := msg.Tags["time"]; !ok {
		msg.Tags["time"] = irc.TagValue(time.Now().UTC().Format(serverTimeLayout))
	}

	switch msg.Command {
	case "PING":
		uc.SendMessage(&irc.Message{
			Command: "PONG",
			Params:  msg.Params,
		})
		return nil
	case "NOTICE", "PRIVMSG", "TAGMSG":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		var entity, text string
		if msg.Command != "TAGMSG" {
			if err := parseMessageParams(msg, &entity, &text); err != nil {
				return err
			}
		} else {
			if err := parseMessageParams(msg, &entity); err != nil {
				return err
			}
		}

		if msg.Prefix.Name == serviceNick {
			uc.logger.Printf("skipping %v from soju's service: %v", msg.Command, msg)
			break
		}
		if entity == serviceNick {
			uc.logger.Printf("skipping %v to soju's service: %v", msg.Command, msg)
			break
		}

		if msg.Prefix.User == "" && msg.Prefix.Host == "" { // server message
			uc.produce("", msg, nil)
		} else { // regular user message
			target := entity
			if target == uc.nick {
				target = msg.Prefix.Name
			}
			uc.produce(target, msg, nil)

			highlight := msg.Prefix.Name != uc.nick && isHighlight(text, uc.nick)
			if ch, ok := uc.network.channels[target]; ok && ch.Detached && highlight {
				uc.forEachDownstream(func(dc *downstreamConn) {
					sendServiceNOTICE(dc, fmt.Sprintf("highlight in %v: <%v> %v", dc.marshalEntity(uc.network, ch.Name), msg.Prefix.Name, text))
				})
			}
		}
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

			uc.requestCaps()

			if uc.requestSASL() {
				break // we'll send CAP END after authentication is completed
			}

			uc.SendMessage(&irc.Message{
				Command: "CAP",
				Params:  []string{"END"},
			})
		case "ACK", "NAK":
			if len(subParams) < 1 {
				return newNeedMoreParamsError(msg.Command)
			}
			caps := strings.Fields(subParams[0])

			for _, name := range caps {
				if err := uc.handleCapAck(strings.ToLower(name), subCmd == "ACK"); err != nil {
					return err
				}
			}

			if uc.registered {
				uc.forEachDownstream(func(dc *downstreamConn) {
					dc.updateSupportedCaps()
				})
			}
		case "NEW":
			if len(subParams) < 1 {
				return newNeedMoreParamsError(msg.Command)
			}
			uc.handleSupportedCaps(subParams[0])
			uc.requestCaps()
		case "DEL":
			if len(subParams) < 1 {
				return newNeedMoreParamsError(msg.Command)
			}
			caps := strings.Fields(subParams[0])

			for _, c := range caps {
				delete(uc.supportedCaps, c)
				delete(uc.caps, c)
			}

			if uc.registered {
				uc.forEachDownstream(func(dc *downstreamConn) {
					dc.updateSupportedCaps()
				})
			}
		default:
			uc.logger.Printf("unhandled message: %v", msg)
		}
	case "AUTHENTICATE":
		if uc.saslClient == nil {
			return fmt.Errorf("received unexpected AUTHENTICATE message")
		}

		// TODO: if a challenge is 400 bytes long, buffer it
		var challengeStr string
		if err := parseMessageParams(msg, &challengeStr); err != nil {
			uc.SendMessage(&irc.Message{
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
				uc.SendMessage(&irc.Message{
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
			uc.SendMessage(&irc.Message{
				Command: "AUTHENTICATE",
				Params:  []string{"*"},
			})
			return err
		}

		// TODO: send response in multiple chunks if >= 400 bytes
		var respStr = "+"
		if len(resp) != 0 {
			respStr = base64.StdEncoding.EncodeToString(resp)
		}

		uc.SendMessage(&irc.Message{
			Command: "AUTHENTICATE",
			Params:  []string{respStr},
		})
	case irc.RPL_LOGGEDIN:
		var account string
		if err := parseMessageParams(msg, nil, nil, &account); err != nil {
			return err
		}
		uc.logger.Printf("logged in with account %q", account)
	case irc.RPL_LOGGEDOUT:
		uc.logger.Printf("logged out")
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

		uc.SendMessage(&irc.Message{
			Command: "CAP",
			Params:  []string{"END"},
		})
	case irc.RPL_WELCOME:
		uc.registered = true
		uc.logger.Printf("connection registered")

		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.updateSupportedCaps()
		})

		if len(uc.network.channels) > 0 {
			// TODO: split this into multiple messages if need be
			var names, keys []string
			for _, ch := range uc.network.channels {
				names = append(names, ch.Name)
				keys = append(keys, ch.Key)
			}
			uc.SendMessage(&irc.Message{
				Command: "JOIN",
				Params: []string{
					strings.Join(names, ","),
					strings.Join(keys, ","),
				},
			})
		}
	case irc.RPL_MYINFO:
		if err := parseMessageParams(msg, nil, &uc.serverName, nil, &uc.availableUserModes, nil); err != nil {
			return err
		}
	case irc.RPL_ISUPPORT:
		if err := parseMessageParams(msg, nil, nil); err != nil {
			return err
		}
		for _, token := range msg.Params[1 : len(msg.Params)-1] {
			negate := false
			parameter := token
			value := ""
			if strings.HasPrefix(token, "-") {
				negate = true
				token = token[1:]
			} else {
				if i := strings.IndexByte(token, '='); i >= 0 {
					parameter = token[:i]
					value = token[i+1:]
				}
			}
			if !negate {
				switch parameter {
				case "CHANMODES":
					parts := strings.SplitN(value, ",", 5)
					if len(parts) < 4 {
						return fmt.Errorf("malformed ISUPPORT CHANMODES value: %v", value)
					}
					modes := make(map[byte]channelModeType)
					for i, mt := range []channelModeType{modeTypeA, modeTypeB, modeTypeC, modeTypeD} {
						for j := 0; j < len(parts[i]); j++ {
							mode := parts[i][j]
							modes[mode] = mt
						}
					}
					uc.availableChannelModes = modes
				case "CHANTYPES":
					uc.availableChannelTypes = value
				case "PREFIX":
					if value == "" {
						uc.availableMemberships = nil
					} else {
						if value[0] != '(' {
							return fmt.Errorf("malformed ISUPPORT PREFIX value: %v", value)
						}
						sep := strings.IndexByte(value, ')')
						if sep < 0 || len(value) != sep*2 {
							return fmt.Errorf("malformed ISUPPORT PREFIX value: %v", value)
						}
						memberships := make([]membership, len(value)/2-1)
						for i := range memberships {
							memberships[i] = membership{
								Mode:   value[i+1],
								Prefix: value[sep+i+1],
							}
						}
						uc.availableMemberships = memberships
					}
				}
			} else {
				// TODO: handle ISUPPORT negations
			}
		}
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
			uc.batches[tag] = batch{
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
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		var newNick string
		if err := parseMessageParams(msg, &newNick); err != nil {
			return err
		}

		me := false
		if msg.Prefix.Name == uc.nick {
			uc.logger.Printf("changed nick from %q to %q", uc.nick, newNick)
			me = true
			uc.nick = newNick
		}

		for _, ch := range uc.channels {
			if memberships, ok := ch.Members[msg.Prefix.Name]; ok {
				delete(ch.Members, msg.Prefix.Name)
				ch.Members[newNick] = memberships
				uc.appendLog(ch.Name, msg)
				uc.appendHistory(ch.Name, msg)
			}
		}

		if !me {
			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(dc.marshalMessage(msg, uc.network))
			})
		} else {
			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.updateNick()
			})
		}
	case "JOIN":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		var channels string
		if err := parseMessageParams(msg, &channels); err != nil {
			return err
		}

		for _, ch := range strings.Split(channels, ",") {
			if msg.Prefix.Name == uc.nick {
				uc.logger.Printf("joined channel %q", ch)
				uc.channels[ch] = &upstreamChannel{
					Name:    ch,
					conn:    uc,
					Members: make(map[string]*memberships),
				}

				uc.SendMessage(&irc.Message{
					Command: "MODE",
					Params:  []string{ch},
				})
			} else {
				ch, err := uc.getChannel(ch)
				if err != nil {
					return err
				}
				ch.Members[msg.Prefix.Name] = &memberships{}
			}

			chMsg := msg.Copy()
			chMsg.Params[0] = ch
			uc.produce(ch, chMsg, nil)
		}
	case "PART":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		var channels string
		if err := parseMessageParams(msg, &channels); err != nil {
			return err
		}

		for _, ch := range strings.Split(channels, ",") {
			if msg.Prefix.Name == uc.nick {
				uc.logger.Printf("parted channel %q", ch)
				delete(uc.channels, ch)
			} else {
				ch, err := uc.getChannel(ch)
				if err != nil {
					return err
				}
				delete(ch.Members, msg.Prefix.Name)
			}

			chMsg := msg.Copy()
			chMsg.Params[0] = ch
			uc.produce(ch, chMsg, nil)
		}
	case "KICK":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		var channel, user string
		if err := parseMessageParams(msg, &channel, &user); err != nil {
			return err
		}

		if user == uc.nick {
			uc.logger.Printf("kicked from channel %q by %s", channel, msg.Prefix.Name)
			delete(uc.channels, channel)
		} else {
			ch, err := uc.getChannel(channel)
			if err != nil {
				return err
			}
			delete(ch.Members, user)
		}

		uc.produce(channel, msg, nil)
	case "QUIT":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		if msg.Prefix.Name == uc.nick {
			uc.logger.Printf("quit")
		}

		for _, ch := range uc.channels {
			if _, ok := ch.Members[msg.Prefix.Name]; ok {
				delete(ch.Members, msg.Prefix.Name)

				uc.appendLog(ch.Name, msg)
				uc.appendHistory(ch.Name, msg)
			}
		}

		if msg.Prefix.Name != uc.nick {
			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(dc.marshalMessage(msg, uc.network))
			})
		}
	case irc.RPL_TOPIC, irc.RPL_NOTOPIC:
		var name, topic string
		if err := parseMessageParams(msg, nil, &name, &topic); err != nil {
			return err
		}
		ch, err := uc.getChannel(name)
		if err != nil {
			return err
		}
		if msg.Command == irc.RPL_TOPIC {
			ch.Topic = topic
		} else {
			ch.Topic = ""
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
		} else {
			ch.Topic = ""
		}
		uc.produce(ch.Name, msg, nil)
	case "MODE":
		var name, modeStr string
		if err := parseMessageParams(msg, &name, &modeStr); err != nil {
			return err
		}

		if !uc.isChannel(name) { // user mode change
			if name != uc.nick {
				return fmt.Errorf("received MODE message for unknown nick %q", name)
			}
			return uc.modes.Apply(modeStr)
			// TODO: notify downstreams about user mode change?
		} else { // channel mode change
			ch, err := uc.getChannel(name)
			if err != nil {
				return err
			}

			needMarshaling, err := applyChannelModes(ch, modeStr, msg.Params[2:])
			if err != nil {
				return err
			}

			uc.appendLog(ch.Name, msg)

			if ch, ok := uc.network.channels[name]; !ok || !ch.Detached {
				uc.forEachDownstream(func(dc *downstreamConn) {
					params := make([]string, len(msg.Params))
					params[0] = dc.marshalEntity(uc.network, name)
					params[1] = modeStr

					copy(params[2:], msg.Params[2:])
					for i, modeParam := range params[2:] {
						if _, ok := needMarshaling[i]; ok {
							params[2+i] = dc.marshalEntity(uc.network, modeParam)
						}
					}

					dc.SendMessage(&irc.Message{
						Prefix:  dc.marshalUserPrefix(uc.network, msg.Prefix),
						Command: "MODE",
						Params:  params,
					})
				})
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
		// TODO: send RPL_UMODEIS to downstream connections when applicable
	case irc.RPL_CHANNELMODEIS:
		var channel string
		if err := parseMessageParams(msg, nil, &channel); err != nil {
			return err
		}
		modeStr := ""
		if len(msg.Params) > 2 {
			modeStr = msg.Params[2]
		}

		ch, err := uc.getChannel(channel)
		if err != nil {
			return err
		}

		firstMode := ch.modes == nil
		ch.modes = make(map[byte]string)
		if _, err := applyChannelModes(ch, modeStr, msg.Params[3:]); err != nil {
			return err
		}
		if firstMode {
			if c, ok := uc.network.channels[channel]; !ok || !c.Detached {
				modeStr, modeParams := ch.modes.Format()

				uc.forEachDownstream(func(dc *downstreamConn) {
					params := []string{dc.nick, dc.marshalEntity(uc.network, channel), modeStr}
					params = append(params, modeParams...)

					dc.SendMessage(&irc.Message{
						Prefix:  dc.srv.prefix(),
						Command: irc.RPL_CHANNELMODEIS,
						Params:  params,
					})
				})
			}
		}
	case rpl_creationtime:
		var channel, creationTime string
		if err := parseMessageParams(msg, nil, &channel, &creationTime); err != nil {
			return err
		}

		ch, err := uc.getChannel(channel)
		if err != nil {
			return err
		}

		firstCreationTime := ch.creationTime == ""
		ch.creationTime = creationTime
		if firstCreationTime {
			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: rpl_creationtime,
					Params:  []string{dc.nick, channel, creationTime},
				})
			})
		}
	case rpl_topicwhotime:
		var name, who, timeStr string
		if err := parseMessageParams(msg, nil, &name, &who, &timeStr); err != nil {
			return err
		}
		ch, err := uc.getChannel(name)
		if err != nil {
			return err
		}
		ch.TopicWho = who
		sec, err := strconv.ParseInt(timeStr, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse topic time: %v", err)
		}
		ch.TopicTime = time.Unix(sec, 0)
	case irc.RPL_LIST:
		var channel, clients, topic string
		if err := parseMessageParams(msg, nil, &channel, &clients, &topic); err != nil {
			return err
		}

		pl := uc.getPendingLIST()
		if pl == nil {
			return fmt.Errorf("unexpected RPL_LIST: no matching pending LIST")
		}

		uc.forEachDownstreamByID(pl.downstreamID, func(dc *downstreamConn) {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_LIST,
				Params:  []string{dc.nick, dc.marshalEntity(uc.network, channel), clients, topic},
			})
		})
	case irc.RPL_LISTEND:
		ok := uc.endPendingLISTs(false)
		if !ok {
			return fmt.Errorf("unexpected RPL_LISTEND: no matching pending LIST")
		}
	case irc.RPL_NAMREPLY:
		var name, statusStr, members string
		if err := parseMessageParams(msg, nil, &statusStr, &name, &members); err != nil {
			return err
		}

		ch, ok := uc.channels[name]
		if !ok {
			// NAMES on a channel we have not joined, forward to downstream
			uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
				channel := dc.marshalEntity(uc.network, name)
				members := splitSpace(members)
				for i, member := range members {
					memberships, nick := uc.parseMembershipPrefix(member)
					members[i] = memberships.Format(dc) + dc.marshalEntity(uc.network, nick)
				}
				memberStr := strings.Join(members, " ")

				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_NAMREPLY,
					Params:  []string{dc.nick, statusStr, channel, memberStr},
				})
			})
			return nil
		}

		status, err := parseChannelStatus(statusStr)
		if err != nil {
			return err
		}
		ch.Status = status

		for _, s := range splitSpace(members) {
			memberships, nick := uc.parseMembershipPrefix(s)
			ch.Members[nick] = memberships
		}
	case irc.RPL_ENDOFNAMES:
		var name string
		if err := parseMessageParams(msg, nil, &name); err != nil {
			return err
		}

		ch, ok := uc.channels[name]
		if !ok {
			// NAMES on a channel we have not joined, forward to downstream
			uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
				channel := dc.marshalEntity(uc.network, name)

				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_ENDOFNAMES,
					Params:  []string{dc.nick, channel, "End of /NAMES list"},
				})
			})
			return nil
		}

		if ch.complete {
			return fmt.Errorf("received unexpected RPL_ENDOFNAMES")
		}
		ch.complete = true

		if c, ok := uc.network.channels[name]; !ok || !c.Detached {
			uc.forEachDownstream(func(dc *downstreamConn) {
				forwardChannel(dc, ch)
			})
		}
	case irc.RPL_WHOREPLY:
		var channel, username, host, server, nick, mode, trailing string
		if err := parseMessageParams(msg, nil, &channel, &username, &host, &server, &nick, &mode, &trailing); err != nil {
			return err
		}

		parts := strings.SplitN(trailing, " ", 2)
		if len(parts) != 2 {
			return fmt.Errorf("received malformed RPL_WHOREPLY: wrong trailing parameter: %s", trailing)
		}
		realname := parts[1]
		hops, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("received malformed RPL_WHOREPLY: wrong hop count: %s", parts[0])
		}
		hops++

		trailing = strconv.Itoa(hops) + " " + realname

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			channel := channel
			if channel != "*" {
				channel = dc.marshalEntity(uc.network, channel)
			}
			nick := dc.marshalEntity(uc.network, nick)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOREPLY,
				Params:  []string{dc.nick, channel, username, host, server, nick, mode, trailing},
			})
		})
	case irc.RPL_ENDOFWHO:
		var name string
		if err := parseMessageParams(msg, nil, &name); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			name := name
			if name != "*" {
				// TODO: support WHO masks
				name = dc.marshalEntity(uc.network, name)
			}
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHO,
				Params:  []string{dc.nick, name, "End of /WHO list"},
			})
		})
	case irc.RPL_WHOISUSER:
		var nick, username, host, realname string
		if err := parseMessageParams(msg, nil, &nick, &username, &host, nil, &realname); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			nick := dc.marshalEntity(uc.network, nick)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISUSER,
				Params:  []string{dc.nick, nick, username, host, "*", realname},
			})
		})
	case irc.RPL_WHOISSERVER:
		var nick, server, serverInfo string
		if err := parseMessageParams(msg, nil, &nick, &server, &serverInfo); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			nick := dc.marshalEntity(uc.network, nick)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISSERVER,
				Params:  []string{dc.nick, nick, server, serverInfo},
			})
		})
	case irc.RPL_WHOISOPERATOR:
		var nick string
		if err := parseMessageParams(msg, nil, &nick); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			nick := dc.marshalEntity(uc.network, nick)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISOPERATOR,
				Params:  []string{dc.nick, nick, "is an IRC operator"},
			})
		})
	case irc.RPL_WHOISIDLE:
		var nick string
		if err := parseMessageParams(msg, nil, &nick, nil); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			nick := dc.marshalEntity(uc.network, nick)
			params := []string{dc.nick, nick}
			params = append(params, msg.Params[2:]...)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISIDLE,
				Params:  params,
			})
		})
	case irc.RPL_WHOISCHANNELS:
		var nick, channelList string
		if err := parseMessageParams(msg, nil, &nick, &channelList); err != nil {
			return err
		}
		channels := splitSpace(channelList)

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			nick := dc.marshalEntity(uc.network, nick)
			channelList := make([]string, len(channels))
			for i, channel := range channels {
				prefix, channel := uc.parseMembershipPrefix(channel)
				channel = dc.marshalEntity(uc.network, channel)
				channelList[i] = prefix.Format(dc) + channel
			}
			channels := strings.Join(channelList, " ")
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_WHOISCHANNELS,
				Params:  []string{dc.nick, nick, channels},
			})
		})
	case irc.RPL_ENDOFWHOIS:
		var nick string
		if err := parseMessageParams(msg, nil, &nick); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			nick := dc.marshalEntity(uc.network, nick)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHOIS,
				Params:  []string{dc.nick, nick, "End of /WHOIS list"},
			})
		})
	case "INVITE":
		var nick, channel string
		if err := parseMessageParams(msg, &nick, &channel); err != nil {
			return err
		}

		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.marshalUserPrefix(uc.network, msg.Prefix),
				Command: "INVITE",
				Params:  []string{dc.marshalEntity(uc.network, nick), dc.marshalEntity(uc.network, channel)},
			})
		})
	case irc.RPL_INVITING:
		var nick, channel string
		if err := parseMessageParams(msg, nil, &nick, &channel); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_INVITING,
				Params:  []string{dc.nick, dc.marshalEntity(uc.network, nick), dc.marshalEntity(uc.network, channel)},
			})
		})
	case irc.RPL_AWAY:
		var nick, reason string
		if err := parseMessageParams(msg, nil, &nick, &reason); err != nil {
			return err
		}

		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_AWAY,
				Params:  []string{dc.nick, dc.marshalEntity(uc.network, nick), reason},
			})
		})
	case "AWAY":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		uc.forEachDownstream(func(dc *downstreamConn) {
			if !dc.caps["away-notify"] {
				return
			}
			dc.SendMessage(&irc.Message{
				Prefix:  dc.marshalUserPrefix(uc.network, msg.Prefix),
				Command: "AWAY",
				Params:  msg.Params,
			})
		})
	case irc.RPL_BANLIST, irc.RPL_INVITELIST, irc.RPL_EXCEPTLIST:
		var channel, mask string
		if err := parseMessageParams(msg, nil, &channel, &mask); err != nil {
			return err
		}
		var addNick, addTime string
		if len(msg.Params) >= 5 {
			addNick = msg.Params[3]
			addTime = msg.Params[4]
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			channel := dc.marshalEntity(uc.network, channel)

			var params []string
			if addNick != "" && addTime != "" {
				addNick := dc.marshalEntity(uc.network, addNick)
				params = []string{dc.nick, channel, mask, addNick, addTime}
			} else {
				params = []string{dc.nick, channel, mask}
			}

			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: msg.Command,
				Params:  params,
			})
		})
	case irc.RPL_ENDOFBANLIST, irc.RPL_ENDOFINVITELIST, irc.RPL_ENDOFEXCEPTLIST:
		var channel, trailing string
		if err := parseMessageParams(msg, nil, &channel, &trailing); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			upstreamChannel := dc.marshalEntity(uc.network, channel)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: msg.Command,
				Params:  []string{dc.nick, upstreamChannel, trailing},
			})
		})
	case irc.ERR_UNKNOWNCOMMAND, irc.RPL_TRYAGAIN:
		var command, reason string
		if err := parseMessageParams(msg, nil, &command, &reason); err != nil {
			return err
		}

		if command == "LIST" {
			ok := uc.endPendingLISTs(false)
			if !ok {
				return fmt.Errorf("unexpected response for LIST: %q: no matching pending LIST", msg.Command)
			}
		}

		if downstreamID != 0 {
			uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  uc.srv.prefix(),
					Command: msg.Command,
					Params:  []string{dc.nick, command, reason},
				})
			})
		}
	case "ACK":
		// Ignore
	case irc.RPL_NOWAWAY, irc.RPL_UNAWAY:
		// Ignore
	case irc.RPL_YOURHOST, irc.RPL_CREATED:
		// Ignore
	case irc.RPL_LUSERCLIENT, irc.RPL_LUSEROP, irc.RPL_LUSERUNKNOWN, irc.RPL_LUSERCHANNELS, irc.RPL_LUSERME:
		// Ignore
	case irc.RPL_MOTDSTART, irc.RPL_MOTD, irc.RPL_ENDOFMOTD:
		// Ignore
	case irc.RPL_LISTSTART:
		// Ignore
	case rpl_localusers, rpl_globalusers:
		// Ignore
	case irc.RPL_STATSVLINE, rpl_statsping, irc.RPL_STATSBLINE, irc.RPL_STATSDLINE:
		// Ignore
	case irc.ERR_PASSWDMISMATCH, irc.ERR_ERRONEUSNICKNAME, irc.ERR_NICKNAMEINUSE, irc.ERR_NICKCOLLISION, irc.ERR_UNAVAILRESOURCE:
		if !uc.registered {
			return fmt.Errorf("registration failed: %v", msg.Params[len(msg.Params) - 1])
		}
		fallthrough
	default:
		uc.logger.Printf("unhandled message: %v", msg)
		if downstreamID != 0 {
			uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
				// best effort marshaling for unknown messages, replies and errors:
				// most numerics start with the user nick, marshal it if that's the case
				// otherwise, conservately keep the params without marshaling
				params := msg.Params
				if _, err := strconv.Atoi(msg.Command); err == nil { // numeric
					if len(msg.Params) > 0 && isOurNick(uc.network, msg.Params[0]) {
						params[0] = dc.nick
					}
				}
				dc.SendMessage(&irc.Message{
					Prefix:  uc.srv.prefix(),
					Command: msg.Command,
					Params:  params,
				})
			})
		}
	}
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
		uc.supportedCaps[k] = v
	}
}

func (uc *upstreamConn) requestCaps() {
	var requestCaps []string
	for c := range permanentUpstreamCaps {
		if _, ok := uc.supportedCaps[c]; ok && !uc.caps[c] {
			requestCaps = append(requestCaps, c)
		}
	}

	if uc.requestSASL() && !uc.caps["sasl"] {
		requestCaps = append(requestCaps, "sasl")
	}

	if len(requestCaps) == 0 {
		return
	}

	uc.SendMessage(&irc.Message{
		Command: "CAP",
		Params:  []string{"REQ", strings.Join(requestCaps, " ")},
	})
}

func (uc *upstreamConn) requestSASL() bool {
	if uc.network.SASL.Mechanism == "" {
		return false
	}

	v, ok := uc.supportedCaps["sasl"]
	if !ok {
		return false
	}
	if v != "" {
		mechanisms := strings.Split(v, ",")
		found := false
		for _, mech := range mechanisms {
			if strings.EqualFold(mech, uc.network.SASL.Mechanism) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (uc *upstreamConn) handleCapAck(name string, ok bool) error {
	uc.caps[name] = ok

	switch name {
	case "sasl":
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

		uc.SendMessage(&irc.Message{
			Command: "AUTHENTICATE",
			Params:  []string{auth.Mechanism},
		})
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

func (uc *upstreamConn) register() {
	uc.nick = uc.network.Nick
	uc.username = uc.network.Username
	if uc.username == "" {
		uc.username = uc.nick
	}
	uc.realname = uc.network.Realname
	if uc.realname == "" {
		uc.realname = uc.nick
	}

	uc.SendMessage(&irc.Message{
		Command: "CAP",
		Params:  []string{"LS", "302"},
	})

	if uc.network.Pass != "" {
		uc.SendMessage(&irc.Message{
			Command: "PASS",
			Params:  []string{uc.network.Pass},
		})
	}

	uc.SendMessage(&irc.Message{
		Command: "NICK",
		Params:  []string{uc.nick},
	})
	uc.SendMessage(&irc.Message{
		Command: "USER",
		Params:  []string{uc.username, "0", "*", uc.realname},
	})
}

func (uc *upstreamConn) runUntilRegistered() error {
	for !uc.registered {
		msg, err := uc.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to read message: %v", err)
		}

		if err := uc.handleMessage(msg); err != nil {
			return fmt.Errorf("failed to handle message %q: %v", msg, err)
		}
	}

	for _, command := range uc.network.ConnectCommands {
		m, err := irc.ParseMessage(command)
		if err != nil {
			uc.logger.Printf("failed to parse connect command %q: %v", command, err)
		} else {
			uc.SendMessage(m)
		}
	}

	return nil
}

func (uc *upstreamConn) readMessages(ch chan<- event) error {
	for {
		msg, err := uc.ReadMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read IRC command: %v", err)
		}

		ch <- eventUpstreamMessage{msg, uc}
	}

	return nil
}

func (uc *upstreamConn) SendMessage(msg *irc.Message) {
	if !uc.caps["message-tags"] {
		msg = msg.Copy()
		msg.Tags = nil
	}

	uc.conn.SendMessage(msg)
}

func (uc *upstreamConn) SendMessageLabeled(downstreamID uint64, msg *irc.Message) {
	if uc.caps["labeled-response"] {
		if msg.Tags == nil {
			msg.Tags = make(map[string]irc.TagValue)
		}
		msg.Tags["label"] = irc.TagValue(fmt.Sprintf("sd-%d-%d", downstreamID, uc.nextLabelID))
		uc.nextLabelID++
	}
	uc.SendMessage(msg)
}

// TODO: handle moving logs when a network name changes, when support for this is added
func (uc *upstreamConn) appendLog(entity string, msg *irc.Message) {
	if uc.srv.LogPath == "" {
		return
	}

	ml, ok := uc.messageLoggers[entity]
	if !ok {
		ml = newMessageLogger(uc.network, entity)
		uc.messageLoggers[entity] = ml
	}

	if err := ml.Append(msg); err != nil {
		uc.logger.Printf("failed to log message: %v", err)
	}
}

// appendHistory appends a message to the history. entity can be empty.
func (uc *upstreamConn) appendHistory(entity string, msg *irc.Message) {
	detached := false
	if ch, ok := uc.network.channels[entity]; ok {
		detached = ch.Detached
	}

	// If no client is offline, no need to append the message to the buffer
	if len(uc.network.offlineClients) == 0 && !detached {
		return
	}

	history, ok := uc.network.history[entity]
	if !ok {
		history = &networkHistory{
			offlineClients: make(map[string]uint64),
			ring:           NewRing(uc.srv.RingCap),
		}
		uc.network.history[entity] = history

		for clientName, _ := range uc.network.offlineClients {
			history.offlineClients[clientName] = 0
		}

		if detached {
			// If the channel is detached, online clients act as offline
			// clients too
			uc.forEachDownstream(func(dc *downstreamConn) {
				history.offlineClients[dc.clientName] = 0
			})
		}
	}

	history.ring.Produce(msg)
}

// produce appends a message to the logs, adds it to the history and forwards
// it to connected downstream connections.
//
// If origin is not nil and origin doesn't support echo-message, the message is
// forwarded to all connections except origin.
func (uc *upstreamConn) produce(target string, msg *irc.Message, origin *downstreamConn) {
	if target != "" {
		uc.appendLog(target, msg)
	}

	uc.appendHistory(target, msg)

	// Don't forward messages if it's a detached channel
	if ch, ok := uc.network.channels[target]; ok && ch.Detached {
		return
	}

	uc.forEachDownstream(func(dc *downstreamConn) {
		if dc != origin || dc.caps["echo-message"] {
			dc.SendMessage(dc.marshalMessage(msg, uc.network))
		}
	})
}

func (uc *upstreamConn) updateAway() {
	away := true
	uc.forEachDownstream(func(*downstreamConn) {
		away = false
	})
	if away == uc.away {
		return
	}
	if away {
		uc.SendMessage(&irc.Message{
			Command: "AWAY",
			Params:  []string{"Auto away"},
		})
	} else {
		uc.SendMessage(&irc.Message{
			Command: "AWAY",
		})
	}
	uc.away = away
}
