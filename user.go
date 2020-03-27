package soju

import (
	"sync"
	"time"

	"gopkg.in/irc.v3"
)

type event interface{}

type eventUpstreamMessage struct {
	msg *irc.Message
	uc  *upstreamConn
}

type eventDownstreamMessage struct {
	msg *irc.Message
	dc  *downstreamConn
}

type eventDownstreamConnected struct {
	dc *downstreamConn
}

type eventDownstreamDisconnected struct {
	dc *downstreamConn
}

type network struct {
	Network
	user *user
	ring *Ring

	lock    sync.Mutex
	conn    *upstreamConn
	history map[string]uint64
}

func newNetwork(user *user, record *Network) *network {
	return &network{
		Network: *record,
		user:    user,
		ring:    NewRing(user.srv.RingCap),
		history: make(map[string]uint64),
	}
}

func (net *network) run() {
	var lastTry time.Time
	for {
		if dur := time.Now().Sub(lastTry); dur < retryConnectMinDelay {
			delay := retryConnectMinDelay - dur
			net.user.srv.Logger.Printf("waiting %v before trying to reconnect to %q", delay.Truncate(time.Second), net.Addr)
			time.Sleep(delay)
		}
		lastTry = time.Now()

		uc, err := connectToUpstream(net)
		if err != nil {
			net.user.srv.Logger.Printf("failed to connect to upstream server %q: %v", net.Addr, err)
			continue
		}

		uc.register()

		net.lock.Lock()
		net.conn = uc
		net.lock.Unlock()

		if err := uc.readMessages(net.user.events); err != nil {
			uc.logger.Printf("failed to handle messages: %v", err)
		}
		uc.Close()

		net.lock.Lock()
		net.conn = nil
		net.lock.Unlock()
	}
}

func (net *network) upstream() *upstreamConn {
	net.lock.Lock()
	defer net.lock.Unlock()
	return net.conn
}

type user struct {
	User
	srv *Server

	events chan event

	networks        []*network
	downstreamConns []*downstreamConn
}

func newUser(srv *Server, record *User) *user {
	return &user{
		User:   *record,
		srv:    srv,
		events: make(chan event, 64),
	}
}

func (u *user) forEachNetwork(f func(*network)) {
	for _, network := range u.networks {
		f(network)
	}
}

func (u *user) forEachUpstream(f func(uc *upstreamConn)) {
	for _, network := range u.networks {
		uc := network.upstream()
		if uc == nil || !uc.registered || uc.closed {
			continue
		}
		f(uc)
	}
}

func (u *user) forEachDownstream(f func(dc *downstreamConn)) {
	for _, dc := range u.downstreamConns {
		f(dc)
	}
}

func (u *user) getNetwork(name string) *network {
	for _, network := range u.networks {
		if network.Addr == name {
			return network
		}
	}
	return nil
}

func (u *user) run() {
	networks, err := u.srv.db.ListNetworks(u.Username)
	if err != nil {
		u.srv.Logger.Printf("failed to list networks for user %q: %v", u.Username, err)
		return
	}

	for _, record := range networks {
		network := newNetwork(u, &record)
		u.networks = append(u.networks, network)

		go network.run()
	}

	for e := range u.events {
		switch e := e.(type) {
		case eventUpstreamMessage:
			msg, uc := e.msg, e.uc
			if uc.closed {
				uc.logger.Printf("ignoring message on closed connection: %v", msg)
				break
			}
			if err := uc.handleMessage(msg); err != nil {
				uc.logger.Printf("failed to handle message %q: %v", msg, err)
			}
		case eventDownstreamConnected:
			dc := e.dc

			if err := dc.welcome(); err != nil {
				dc.logger.Printf("failed to handle new registered connection: %v", err)
				break
			}

			u.downstreamConns = append(u.downstreamConns, dc)
		case eventDownstreamDisconnected:
			dc := e.dc
			for i := range u.downstreamConns {
				if u.downstreamConns[i] == dc {
					u.downstreamConns = append(u.downstreamConns[:i], u.downstreamConns[i+1:]...)
					break
				}
			}
		case eventDownstreamMessage:
			msg, dc := e.msg, e.dc
			if dc.isClosed() {
				dc.logger.Printf("ignoring message on closed connection: %v", msg)
				break
			}
			err := dc.handleMessage(msg)
			if ircErr, ok := err.(ircError); ok {
				ircErr.Message.Prefix = dc.srv.prefix()
				dc.SendMessage(ircErr.Message)
			} else if err != nil {
				dc.logger.Printf("failed to handle message %q: %v", msg, err)
				dc.Close()
			}
		default:
			u.srv.Logger.Printf("received unknown event type: %T", e)
		}
	}
}

func (u *user) createNetwork(net *Network) (*network, error) {
	if net.ID != 0 {
		panic("tried creating an already-existing network")
	}

	network := newNetwork(u, net)
	err := u.srv.db.StoreNetwork(u.Username, &network.Network)
	if err != nil {
		return nil, err
	}

	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.network == nil {
			dc.runNetwork(network, false)
		}
	})

	u.networks = append(u.networks, network)

	go network.run()
	return network, nil
}
