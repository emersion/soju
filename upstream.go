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
	"gopkg.in/irc.v3"
)

type upstreamChannel struct {
	Name      string
	conn      *upstreamConn
	Topic     string
	TopicWho  string
	TopicTime time.Time
	Status    channelStatus
	modes     modeSet
	Members   map[string]membership
	complete  bool
}

type upstreamConn struct {
	network  *network
	logger   Logger
	net      net.Conn
	irc      *irc.Conn
	srv      *Server
	user     *user
	outgoing chan<- *irc.Message
	ring     *Ring

	serverName            string
	availableUserModes    string
	availableChannelModes string
	channelModesWithParam string

	registered bool
	nick       string
	username   string
	realname   string
	closed     bool
	modes      modeSet
	channels   map[string]*upstreamChannel
	history    map[string]uint64
	caps       map[string]string

	saslClient  sasl.Client
	saslStarted bool
}

func connectToUpstream(network *network) (*upstreamConn, error) {
	logger := &prefixLogger{network.user.srv.Logger, fmt.Sprintf("upstream %q: ", network.Addr)}

	addr := network.Addr
	if !strings.ContainsRune(addr, ':') {
		addr = addr + ":6697"
	}

	logger.Printf("connecting to TLS server at address %q", addr)
	netConn, err := tls.Dial("tcp", addr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %q: %v", addr, err)
	}

	setKeepAlive(netConn)

	outgoing := make(chan *irc.Message, 64)
	uc := &upstreamConn{
		network:  network,
		logger:   logger,
		net:      netConn,
		irc:      irc.NewConn(netConn),
		srv:      network.user.srv,
		user:     network.user,
		outgoing: outgoing,
		ring:     NewRing(network.user.srv.RingCap),
		channels: make(map[string]*upstreamChannel),
		history:  make(map[string]uint64),
		caps:     make(map[string]string),
	}

	go func() {
		for msg := range outgoing {
			if uc.srv.Debug {
				uc.logger.Printf("sent: %v", msg)
			}
			if err := uc.irc.WriteMessage(msg); err != nil {
				uc.logger.Printf("failed to write message: %v", err)
			}
		}
		if err := uc.net.Close(); err != nil {
			uc.logger.Printf("failed to close connection: %v", err)
		} else {
			uc.logger.Printf("connection closed")
		}
	}()

	return uc, nil
}

func (uc *upstreamConn) Close() error {
	if uc.closed {
		return fmt.Errorf("upstream connection already closed")
	}
	close(uc.outgoing)
	uc.closed = true
	return nil
}

func (uc *upstreamConn) forEachDownstream(f func(*downstreamConn)) {
	uc.user.forEachDownstream(func(dc *downstreamConn) {
		if dc.network != nil && dc.network != uc.network {
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

func (uc *upstreamConn) handleMessage(msg *irc.Message) error {
	switch msg.Command {
	case "PING":
		uc.SendMessage(&irc.Message{
			Command: "PONG",
			Params:  msg.Params,
		})
		return nil
	case "MODE":
		if msg.Prefix == nil {
			return fmt.Errorf("missing prefix")
		}

		var name, modeStr string
		if err := parseMessageParams(msg, &name, &modeStr); err != nil {
			return err
		}

		if name == msg.Prefix.Name { // user mode change
			if name != uc.nick {
				return fmt.Errorf("received MODE message for unknow nick %q", name)
			}
			return uc.modes.Apply(modeStr)
		} else { // channel mode change
			ch, err := uc.getChannel(name)
			if err != nil {
				return err
			}
			if err := ch.modes.Apply(modeStr); err != nil {
				return err
			}

			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
					Command: "MODE",
					Params:  []string{dc.marshalChannel(uc, name), modeStr},
				})
			})
		}
	case "NOTICE":
		uc.logger.Print(msg)

		uc.forEachDownstream(func(dc *downstreamConn) {
			dc.SendMessage(msg)
		})
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

			if uc.requestSASL() {
				uc.SendMessage(&irc.Message{
					Command: "CAP",
					Params:  []string{"REQ", "sasl"},
				})
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
	case rpl_loggedin:
		var account string
		if err := parseMessageParams(msg, nil, nil, &account); err != nil {
			return err
		}
		uc.logger.Printf("logged in with account %q", account)
	case rpl_loggedout:
		uc.logger.Printf("logged out")
	case err_nicklocked, rpl_saslsuccess, err_saslfail, err_sasltoolong, err_saslaborted:
		var info string
		if err := parseMessageParams(msg, nil, &info); err != nil {
			return err
		}
		switch msg.Command {
		case err_nicklocked:
			uc.logger.Printf("invalid nick used with SASL authentication: %v", info)
		case err_saslfail:
			uc.logger.Printf("SASL authentication failed: %v", info)
		case err_sasltoolong:
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
			uc.SendMessage(&irc.Message{
				Command: "JOIN",
				Params:  []string{ch.Name},
			})
		}
	case irc.RPL_MYINFO:
		if err := parseMessageParams(msg, nil, &uc.serverName, nil, &uc.availableUserModes, &uc.availableChannelModes); err != nil {
			return err
		}
		if len(msg.Params) > 5 {
			uc.channelModesWithParam = msg.Params[5]
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
					Members: make(map[string]membership),
				}
			} else {
				ch, err := uc.getChannel(ch)
				if err != nil {
					return err
				}
				ch.Members[msg.Prefix.Name] = 0
			}

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

			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.marshalUserPrefix(uc, msg.Prefix),
					Command: "PART",
					Params:  []string{dc.marshalChannel(uc, ch)},
				})
			})
		}
	case "QUIT":
		if msg.Prefix == nil {
			return fmt.Errorf("expected a prefix")
		}

		if msg.Prefix.Name == uc.nick {
			uc.logger.Printf("quit")
		}

		for _, ch := range uc.channels {
			delete(ch.Members, msg.Prefix.Name)
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
	case irc.RPL_NAMREPLY:
		var name, statusStr, members string
		if err := parseMessageParams(msg, nil, &statusStr, &name, &members); err != nil {
			return err
		}
		ch, err := uc.getChannel(name)
		if err != nil {
			return err
		}

		status, err := parseChannelStatus(statusStr)
		if err != nil {
			return err
		}
		ch.Status = status

		for _, s := range strings.Split(members, " ") {
			membership, nick := parseMembershipPrefix(s)
			ch.Members[nick] = membership
		}
	case irc.RPL_ENDOFNAMES:
		var name string
		if err := parseMessageParams(msg, nil, &name); err != nil {
			return err
		}
		ch, err := uc.getChannel(name)
		if err != nil {
			return err
		}

		if ch.complete {
			return fmt.Errorf("received unexpected RPL_ENDOFNAMES")
		}
		ch.complete = true

		uc.forEachDownstream(func(dc *downstreamConn) {
			forwardChannel(dc, ch)
		})
	case "PRIVMSG":
		if err := parseMessageParams(msg, nil, nil); err != nil {
			return err
		}
		uc.ring.Produce(msg)
	case irc.RPL_YOURHOST, irc.RPL_CREATED:
		// Ignore
	case irc.RPL_LUSERCLIENT, irc.RPL_LUSEROP, irc.RPL_LUSERUNKNOWN, irc.RPL_LUSERCHANNELS, irc.RPL_LUSERME:
		// Ignore
	case irc.RPL_MOTDSTART, irc.RPL_MOTD, irc.RPL_ENDOFMOTD:
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
	}
	return nil
}

func (uc *upstreamConn) readMessages(ch chan<- upstreamIncomingMessage) error {
	for {
		msg, err := uc.irc.ReadMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read IRC command: %v", err)
		}

		if uc.srv.Debug {
			uc.logger.Printf("received: %v", msg)
		}

		ch <- upstreamIncomingMessage{msg, uc}
	}

	return nil
}

func (uc *upstreamConn) SendMessage(msg *irc.Message) {
	uc.outgoing <- msg
}
