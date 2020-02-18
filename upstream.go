package jounce

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

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
	upstream *Upstream
	logger   Logger
	net      net.Conn
	irc      *irc.Conn
	srv      *Server
	user     *user
	messages chan<- *irc.Message
	ring     *Ring

	serverName            string
	availableUserModes    string
	availableChannelModes string
	channelModesWithParam string

	registered bool
	nick       string
	closed     bool
	modes      modeSet
	channels   map[string]*upstreamChannel
	history    map[string]uint64
}

func connectToUpstream(u *user, upstream *Upstream) (*upstreamConn, error) {
	logger := &prefixLogger{u.srv.Logger, fmt.Sprintf("upstream %q: ", upstream.Addr)}
	logger.Printf("connecting to server")

	netConn, err := tls.Dial("tcp", upstream.Addr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %q: %v", upstream.Addr, err)
	}

	msgs := make(chan *irc.Message, 64)
	uc := &upstreamConn{
		upstream: upstream,
		logger:   logger,
		net:      netConn,
		irc:      irc.NewConn(netConn),
		srv:      u.srv,
		user:     u,
		messages: msgs,
		ring:     NewRing(u.srv.RingCap),
		channels: make(map[string]*upstreamChannel),
		history:  make(map[string]uint64),
	}

	go func() {
		for msg := range msgs {
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
	close(uc.messages)
	uc.closed = true
	return nil
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
		var from, to string
		if len(msg.Params) >= 1 {
			from = msg.Params[0]
		}
		if len(msg.Params) >= 2 {
			to = msg.Params[1]
		}

		if to != "" && to != uc.srv.Hostname {
			return fmt.Errorf("invalid PING destination %q", to)
		}

		params := []string{uc.srv.Hostname}
		if from != "" {
			params = append(params, from)
		}
		uc.SendMessage(&irc.Message{
			Command: "PONG",
			Params:  params,
		})
		return nil
	case "MODE":
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
		}

		uc.user.forEachDownstream(func(dc *downstreamConn) {
			dc.SendMessage(msg)
		})
	case "NOTICE":
		uc.logger.Print(msg)
	case irc.RPL_WELCOME:
		uc.registered = true
		uc.logger.Printf("connection registered")

		for _, ch := range uc.upstream.Channels {
			uc.SendMessage(&irc.Message{
				Command: "JOIN",
				Params:  []string{ch},
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

		uc.user.forEachDownstream(func(dc *downstreamConn) {
			dc.SendMessage(msg)
		})
	case "JOIN":
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
		}

		uc.user.forEachDownstream(func(dc *downstreamConn) {
			dc.SendMessage(msg)
		})
	case "PART":
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
		}

		uc.user.forEachDownstream(func(dc *downstreamConn) {
			dc.SendMessage(msg)
		})
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
		if err := parseMessageParams(msg, nil, &name); err != nil {
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

		uc.user.forEachDownstream(func(dc *downstreamConn) {
			forwardChannel(dc, ch)
		})
	case "PRIVMSG":
		uc.ring.Produce(msg)
	case irc.RPL_YOURHOST, irc.RPL_CREATED:
		// Ignore
	case irc.RPL_LUSERCLIENT, irc.RPL_LUSEROP, irc.RPL_LUSERUNKNOWN, irc.RPL_LUSERCHANNELS, irc.RPL_LUSERME:
		// Ignore
	case irc.RPL_MOTDSTART, irc.RPL_MOTD, irc.RPL_ENDOFMOTD:
		// Ignore
	case rpl_localusers, rpl_globalusers:
		// Ignore
	case irc.RPL_STATSVLINE, irc.RPL_STATSPING, irc.RPL_STATSBLINE, irc.RPL_STATSDLINE:
		// Ignore
	default:
		uc.logger.Printf("unhandled upstream message: %v", msg)
	}
	return nil
}

func (uc *upstreamConn) register() {
	uc.nick = uc.upstream.Nick
	uc.SendMessage(&irc.Message{
		Command: "NICK",
		Params:  []string{uc.upstream.Nick},
	})
	uc.SendMessage(&irc.Message{
		Command: "USER",
		Params:  []string{uc.upstream.Username, "0", "*", uc.upstream.Realname},
	})
}

func (uc *upstreamConn) readMessages() error {
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

		if err := uc.handleMessage(msg); err != nil {
			uc.logger.Printf("failed to handle message %q: %v", msg, err)
		}
	}

	return nil
}

func (uc *upstreamConn) SendMessage(msg *irc.Message) {
	uc.messages <- msg
}
