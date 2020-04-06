package soju

import (
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
	"gopkg.in/irc.v3"
)

type upstreamChannel struct {
	Name         string
	conn         *upstreamConn
	Topic        string
	TopicWho     string
	TopicTime    time.Time
	Status       channelStatus
	modes        channelModes
	creationTime string
	Members      map[string]*membership
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

	registered bool
	nick       string
	username   string
	realname   string
	modes      userModes
	channels   map[string]*upstreamChannel
	caps       map[string]string
	batches    map[string]batch
	away       bool

	tagsSupported   bool
	labelsSupported bool
	nextLabelID     uint64

	saslClient  sasl.Client
	saslStarted bool

	// set of LIST commands in progress, per downstream
	pendingLISTDownstreamSet map[uint64]struct{}

	messageLoggers map[string]*messageLogger
}

func connectToUpstream(network *network) (*upstreamConn, error) {
	logger := &prefixLogger{network.user.srv.Logger, fmt.Sprintf("upstream %q: ", network.Addr)}

	addr := network.Addr
	if !strings.ContainsRune(addr, ':') {
		addr = addr + ":6697"
	}

	dialer := net.Dialer{Timeout: connectTimeout}

	logger.Printf("connecting to TLS server at address %q", addr)
	netConn, err := tls.DialWithDialer(&dialer, "tcp", addr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %q: %v", addr, err)
	}

	uc := &upstreamConn{
		conn:                     *newConn(network.user.srv, netConn, logger),
		network:                  network,
		user:                     network.user,
		channels:                 make(map[string]*upstreamChannel),
		caps:                     make(map[string]string),
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
	// must be called with a lock in uc.user.pendingLISTsLock

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

func (uc *upstreamConn) parseMembershipPrefix(s string) (membership *membership, nick string) {
	for _, m := range uc.availableMemberships {
		if m.Prefix == s[0] {
			return &m, s[1:]
		}
	}
	return nil, s
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
	case "NOTICE":
		if msg.Prefix.User == "" && msg.Prefix.Host == "" { // server message
			uc.produce("", msg, nil)
		} else { // regular user NOTICE
			var entity, text string
			if err := parseMessageParams(msg, &entity, &text); err != nil {
				return err
			}

			target := entity
			if target == uc.nick {
				target = msg.Prefix.Name
			}
			uc.produce(target, msg, nil)
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
			caps := strings.Fields(subParams[len(subParams)-1])
			more := len(subParams) >= 2 && msg.Params[len(subParams)-2] == "*"

			for _, s := range caps {
				kv := strings.SplitN(s, "=", 2)
				k := strings.ToLower(kv[0])
				var v string
				if len(kv) == 2 {
					v = kv[1]
				}
				uc.caps[k] = v
			}

			if more {
				break // wait to receive all capabilities
			}

			requestCaps := make([]string, 0, 16)
			for _, c := range []string{"message-tags", "batch", "labeled-response", "server-time"} {
				if _, ok := uc.caps[c]; ok {
					requestCaps = append(requestCaps, c)
				}
			}

			if uc.requestSASL() {
				requestCaps = append(requestCaps, "sasl")
			}

			if len(requestCaps) > 0 {
				uc.SendMessage(&irc.Message{
					Command: "CAP",
					Params:  []string{"REQ", strings.Join(requestCaps, " ")},
				})
			}

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

			if uc.saslClient == nil {
				uc.SendMessage(&irc.Message{
					Command: "CAP",
					Params:  []string{"END"},
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
		if resp != nil {
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

		channels, err := uc.srv.db.ListChannels(uc.network.ID)
		if err != nil {
			uc.logger.Printf("failed to list channels from database: %v", err)
			break
		}

		for _, ch := range channels {
			params := []string{ch.Name}
			if ch.Key != "" {
				params = append(params, ch.Key)
			}
			uc.SendMessage(&irc.Message{
				Command: "JOIN",
				Params:  params,
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

		if msg.Prefix.Name == uc.nick {
			uc.logger.Printf("changed nick from %q to %q", uc.nick, newNick)
			uc.nick = newNick
		}

		for _, ch := range uc.channels {
			if membership, ok := ch.Members[msg.Prefix.Name]; ok {
				delete(ch.Members, msg.Prefix.Name)
				ch.Members[newNick] = membership
				uc.appendLog(ch.Name, msg)
			}
		}

		if msg.Prefix.Name != uc.nick {
			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
					Command: "NICK",
					Params:  []string{newNick},
				})
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
					Members: make(map[string]*membership),
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
				ch.Members[msg.Prefix.Name] = nil
			}

			uc.appendLog(ch, msg)

			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
					Command: "JOIN",
					Params:  []string{dc.marshalChannel(uc, ch)},
				})
			})
		}
	case "PART":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		var channels string
		if err := parseMessageParams(msg, &channels); err != nil {
			return err
		}

		var reason string
		if len(msg.Params) > 1 {
			reason = msg.Params[1]
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

			uc.appendLog(ch, msg)

			uc.forEachDownstream(func(dc *downstreamConn) {
				params := []string{dc.marshalChannel(uc, ch)}
				if reason != "" {
					params = append(params, reason)
				}
				dc.SendMessage(&irc.Message{
					Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
					Command: "PART",
					Params:  params,
				})
			})
		}
	case "KICK":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		var channel, user string
		if err := parseMessageParams(msg, &channel, &user); err != nil {
			return err
		}

		var reason string
		if len(msg.Params) > 2 {
			reason = msg.Params[2]
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

		uc.appendLog(channel, msg)

		uc.forEachDownstream(func(dc *downstreamConn) {
			params := []string{dc.marshalChannel(uc, channel), dc.marshalNick(uc, user)}
			if reason != "" {
				params = append(params, reason)
			}
			dc.SendMessage(&irc.Message{
				Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
				Command: "KICK",
				Params:  params,
			})
		})
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
			}
		}

		if msg.Prefix.Name != uc.nick {
			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
					Command: "QUIT",
					Params:  msg.Params,
				})
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
		uc.appendLog(ch.Name, msg)
		uc.forEachDownstream(func(dc *downstreamConn) {
			params := []string{dc.marshalChannel(uc, name)}
			if ch.Topic != "" {
				params = append(params, ch.Topic)
			}
			dc.SendMessage(&irc.Message{
				Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
				Command: "TOPIC",
				Params:  params,
			})
		})
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

			if ch.modes != nil {
				if err := ch.modes.Apply(uc.availableChannelModes, modeStr, msg.Params[2:]...); err != nil {
					return err
				}
			}

			uc.appendLog(ch.Name, msg)

			uc.forEachDownstream(func(dc *downstreamConn) {
				params := []string{dc.marshalChannel(uc, name), modeStr}
				params = append(params, msg.Params[2:]...)

				dc.SendMessage(&irc.Message{
					Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
					Command: "MODE",
					Params:  params,
				})
			})
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
		if err := ch.modes.Apply(uc.availableChannelModes, modeStr, msg.Params[3:]...); err != nil {
			return err
		}
		if firstMode {
			modeStr, modeParams := ch.modes.Format()

			uc.forEachDownstream(func(dc *downstreamConn) {
				params := []string{dc.nick, dc.marshalChannel(uc, channel), modeStr}
				params = append(params, modeParams...)

				dc.SendMessage(&irc.Message{
					Prefix:  dc.srv.prefix(),
					Command: irc.RPL_CHANNELMODEIS,
					Params:  params,
				})
			})
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
				Params:  []string{dc.nick, dc.marshalChannel(uc, channel), clients, topic},
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
				channel := dc.marshalChannel(uc, name)
				members := splitSpace(members)
				for i, member := range members {
					membership, nick := uc.parseMembershipPrefix(member)
					members[i] = membership.String() + dc.marshalNick(uc, nick)
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
			membership, nick := uc.parseMembershipPrefix(s)
			ch.Members[nick] = membership
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
				channel := dc.marshalChannel(uc, name)

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

		uc.forEachDownstream(func(dc *downstreamConn) {
			forwardChannel(dc, ch)
		})
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
				channel = dc.marshalChannel(uc, channel)
			}
			nick := dc.marshalNick(uc, nick)
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
				name = dc.marshalEntity(uc, name)
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
			nick := dc.marshalNick(uc, nick)
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
			nick := dc.marshalNick(uc, nick)
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
			nick := dc.marshalNick(uc, nick)
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
			nick := dc.marshalNick(uc, nick)
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
			nick := dc.marshalNick(uc, nick)
			channelList := make([]string, len(channels))
			for i, channel := range channels {
				prefix, channel := uc.parseMembershipPrefix(channel)
				channel = dc.marshalChannel(uc, channel)
				channelList[i] = prefix.String() + channel
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
			nick := dc.marshalNick(uc, nick)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_ENDOFWHOIS,
				Params:  []string{dc.nick, nick, "End of /WHOIS list"},
			})
		})
	case "PRIVMSG":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		var entity, text string
		if err := parseMessageParams(msg, &entity, &text); err != nil {
			return err
		}

		if msg.Prefix.Name == serviceNick {
			uc.logger.Printf("skipping PRIVMSG from soju's service: %v", msg)
			break
		}
		if entity == serviceNick {
			uc.logger.Printf("skipping PRIVMSG to soju's service: %v", msg)
			break
		}

		target := entity
		if target == uc.nick {
			target = msg.Prefix.Name
		}
		uc.produce(target, msg, nil)
	case "INVITE":
		var nick string
		var channel string
		if err := parseMessageParams(msg, &nick, &channel); err != nil {
			return err
		}

		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
				Command: "INVITE",
				Params:  []string{dc.marshalNick(uc, nick), dc.marshalChannel(uc, channel)},
			})
		})
	case irc.RPL_INVITING:
		var nick string
		var channel string
		if err := parseMessageParams(msg, &nick, &channel); err != nil {
			return err
		}

		uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_INVITING,
				Params:  []string{dc.nick, dc.marshalNick(uc, nick), dc.marshalChannel(uc, channel)},
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
			uc.forEachDownstreamByID(downstreamID, func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  uc.srv.prefix(),
					Command: msg.Command,
					Params:  []string{dc.nick, "LIST", reason},
				})
			})
		}
	case "TAGMSG":
		// TODO: relay to downstream connections that accept message-tags
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
	default:
		uc.logger.Printf("unhandled message: %v", msg)
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

	return nil
}

func (uc *upstreamConn) requestSASL() bool {
	if uc.network.SASL.Mechanism == "" {
		return false
	}

	v, ok := uc.caps["sasl"]
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
	auth := &uc.network.SASL
	switch name {
	case "sasl":
		if !ok {
			uc.logger.Printf("server refused to acknowledge the SASL capability")
			return nil
		}

		switch auth.Mechanism {
		case "PLAIN":
			uc.logger.Printf("starting SASL PLAIN authentication with username %q", auth.Plain.Username)
			uc.saslClient = sasl.NewPlainClient("", auth.Plain.Username, auth.Plain.Password)
		default:
			return fmt.Errorf("unsupported SASL mechanism %q", name)
		}

		uc.SendMessage(&irc.Message{
			Command: "AUTHENTICATE",
			Params:  []string{auth.Mechanism},
		})
	case "message-tags":
		uc.tagsSupported = ok
	case "labeled-response":
		uc.labelsSupported = ok
	case "batch", "server-time":
		// Nothing to do
	default:
		uc.logger.Printf("received CAP ACK/NAK for a cap we don't support: %v", name)
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

func (uc *upstreamConn) SendMessageLabeled(downstreamID uint64, msg *irc.Message) {
	if uc.labelsSupported {
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
		ml = newMessageLogger(uc, entity)
		uc.messageLoggers[entity] = ml
	}

	if err := ml.Append(msg); err != nil {
		uc.logger.Printf("failed to log message: %v", err)
	}
}

func (uc *upstreamConn) produce(target string, msg *irc.Message, origin *downstreamConn) {
	if target != "" {
		uc.appendLog(target, msg)
	}

	uc.network.ring.Produce(msg)

	uc.forEachDownstream(func(dc *downstreamConn) {
		if dc != origin || dc.caps["echo-message"] {
			dc.sendFromUpstream(msg, uc)
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
