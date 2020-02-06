package jounce

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"

	"gopkg.in/irc.v3"
)

const (
	rpl_localusers  = "265"
	rpl_globalusers = "266"
)

type modeSet string

func (ms modeSet) Has(c byte) bool {
	return strings.IndexByte(string(ms), c) >= 0
}

func (ms *modeSet) Add(c byte) {
	if !ms.Has(c) {
		*ms += modeSet(c)
	}
}

func (ms *modeSet) Del(c byte) {
	i := strings.IndexByte(string(*ms), c)
	if i >= 0 {
		*ms = (*ms)[:i] + (*ms)[i+1:]
	}
}

func (ms *modeSet) Apply(s string) error {
	var plusMinus byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '+', '-':
			plusMinus = c
		default:
			switch plusMinus {
			case '+':
				ms.Add(c)
			case '-':
				ms.Del(c)
			default:
				return fmt.Errorf("malformed modestring %q: missing plus/minus", s)
			}
		}
	}
	return nil
}

type upstreamConn struct {
	upstream   *Upstream
	net        net.Conn
	irc        *irc.Conn
	srv        *Server
	registered bool
	modes      modeSet

	serverName            string
	availableUserModes    string
	availableChannelModes string
	channelModesWithParam string
}

func (c *upstreamConn) handleMessage(msg *irc.Message) error {
	switch msg.Command {
	case "PING":
		// TODO: handle params
		return c.irc.WriteMessage(&irc.Message{
			Command: "PONG",
			Params:  []string{c.srv.Hostname},
		})
	case "MODE":
		if len(msg.Params) < 2 {
			return newNeedMoreParamsError(msg.Command)
		}
		if nick := msg.Params[0]; nick != c.upstream.Nick {
			return fmt.Errorf("received MODE message for unknow nick %q", nick)
		}
		return c.modes.Apply(msg.Params[1])
	case "NOTICE":
		c.srv.Logger.Printf("%q: %v", c.upstream.Addr, msg)
	case irc.RPL_WELCOME:
		c.registered = true
		c.srv.Logger.Printf("Connection to %q registered", c.upstream.Addr)
	case irc.RPL_MYINFO:
		if len(msg.Params) < 5 {
			return newNeedMoreParamsError(msg.Command)
		}
		c.serverName = msg.Params[1]
		c.availableUserModes = msg.Params[3]
		c.availableChannelModes = msg.Params[4]
		if len(msg.Params) > 5 {
			c.channelModesWithParam = msg.Params[5]
		}
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
		c.srv.Logger.Printf("Unhandled upstream message: %v", msg)
	}
	return nil
}

func connect(s *Server, upstream *Upstream) error {
	s.Logger.Printf("Connecting to %v", upstream.Addr)

	netConn, err := tls.Dial("tcp", upstream.Addr, nil)
	if err != nil {
		return fmt.Errorf("failed to dial %q: %v", upstream.Addr, err)
	}

	c := upstreamConn{
		upstream: upstream,
		net:      netConn,
		irc:      irc.NewConn(netConn),
		srv:      s,
	}
	defer netConn.Close()

	err = c.irc.WriteMessage(&irc.Message{
		Command: "NICK",
		Params:  []string{upstream.Nick},
	})
	if err != nil {
		return err
	}

	err = c.irc.WriteMessage(&irc.Message{
		Command: "USER",
		Params:  []string{upstream.Username, "0", "*", upstream.Realname},
	})
	if err != nil {
		return err
	}

	for {
		msg, err := c.irc.ReadMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read IRC command: %v", err)
		}

		if err := c.handleMessage(msg); err != nil {
			c.srv.Logger.Printf("Failed to handle message %q from %q: %v", msg, upstream.Addr, err)
		}
	}

	return netConn.Close()
}
