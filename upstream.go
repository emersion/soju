package jounce

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"gopkg.in/irc.v3"
)

const (
	rpl_localusers = "265"
	rpl_globalusers = "266"
)

type upstreamConn struct {
	net net.Conn
	irc *irc.Conn
	srv *Server
	registered bool
}

func (c *upstreamConn) handleMessage(msg *irc.Message) error {
	switch msg.Command {
	case "PING":
		// TODO: handle params
		return c.irc.WriteMessage(&irc.Message{
			Command: "PONG",
			Params:  []string{c.srv.Hostname},
		})
	case irc.RPL_WELCOME:
		c.registered = true
	case irc.RPL_YOURHOST, irc.RPL_CREATED, irc.RPL_MYINFO:
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

	c := upstreamConn{net: netConn, irc: irc.NewConn(netConn), srv: s}
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
			return err
		}
	}

	return netConn.Close()
}
