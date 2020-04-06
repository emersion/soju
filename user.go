package soju

import (
	"fmt"
	"sync"
	"time"

	"gopkg.in/irc.v3"
)

type event interface{}

type eventUpstreamMessage struct {
	msg *irc.Message
	uc  *upstreamConn
}

type eventUpstreamConnectionError struct {
	net *network
	err error
}

type eventUpstreamConnected struct {
	uc *upstreamConn
}

type eventUpstreamDisconnected struct {
	uc *upstreamConn
}

type eventUpstreamError struct {
	uc  *upstreamConn
	err error
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
	user    *user
	ring    *Ring
	stopped chan struct{}

	history   map[string]uint64
	lastError error

	lock sync.Mutex
	conn *upstreamConn
}

func newNetwork(user *user, record *Network) *network {
	return &network{
		Network: *record,
		user:    user,
		ring:    NewRing(user.srv.RingCap),
		stopped: make(chan struct{}),
		history: make(map[string]uint64),
	}
}

func (net *network) forEachDownstream(f func(*downstreamConn)) {
	net.user.forEachDownstream(func(dc *downstreamConn) {
		if dc.network != nil && dc.network != net {
			return
		}
		f(dc)
	})
}

func (net *network) run() {
	var lastTry time.Time
	for {
		select {
		case <-net.stopped:
			return
		default:
			// This space is intentionally left blank
		}

		if dur := time.Now().Sub(lastTry); dur < retryConnectMinDelay {
			delay := retryConnectMinDelay - dur
			net.user.srv.Logger.Printf("waiting %v before trying to reconnect to %q", delay.Truncate(time.Second), net.Addr)
			time.Sleep(delay)
		}
		lastTry = time.Now()

		uc, err := connectToUpstream(net)
		if err != nil {
			net.user.srv.Logger.Printf("failed to connect to upstream server %q: %v", net.Addr, err)
			net.user.events <- eventUpstreamConnectionError{net, fmt.Errorf("failed to connect: %v", err)}
			continue
		}

		uc.register()
		if err := uc.runUntilRegistered(); err != nil {
			uc.logger.Printf("failed to register: %v", err)
			net.user.events <- eventUpstreamConnectionError{net, fmt.Errorf("failed to register: %v", err)}
			uc.Close()
			continue
		}

		net.user.events <- eventUpstreamConnected{uc}
		if err := uc.readMessages(net.user.events); err != nil {
			uc.logger.Printf("failed to handle messages: %v", err)
			net.user.events <- eventUpstreamError{uc, fmt.Errorf("failed to handle messages: %v", err)}
		}
		uc.Close()
		net.user.events <- eventUpstreamDisconnected{uc}
	}
}

func (net *network) upstream() *upstreamConn {
	net.lock.Lock()
	defer net.lock.Unlock()
	return net.conn
}

func (net *network) Stop() {
	select {
	case <-net.stopped:
		return
	default:
		close(net.stopped)
	}

	if uc := net.upstream(); uc != nil {
		uc.Close()
	}
}

func (net *network) createUpdateChannel(ch *Channel) error {
	if dbCh, err := net.user.srv.db.GetChannel(net.ID, ch.Name); err == nil {
		ch.ID = dbCh.ID
	} else if err != ErrNoSuchChannel {
		return err
	}
	return net.user.srv.db.StoreChannel(net.ID, ch)
}

func (net *network) deleteChannel(name string) error {
	return net.user.srv.db.DeleteChannel(net.ID, name)
}

type user struct {
	User
	srv *Server

	events chan event

	networks        []*network
	downstreamConns []*downstreamConn

	// LIST commands in progress
	pendingLISTs []pendingLIST
}

type pendingLIST struct {
	downstreamID uint64
	// list of per-upstream LIST commands not yet sent or completed
	pendingCommands map[int64]*irc.Message
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
		if uc == nil {
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
		if network.Name != "" && network.Name == name {
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
		case eventUpstreamConnected:
			uc := e.uc

			uc.network.lock.Lock()
			uc.network.conn = uc
			uc.network.lock.Unlock()

			uc.updateAway()

			uc.forEachDownstream(func(dc *downstreamConn) {
				sendServiceNOTICE(dc, fmt.Sprintf("connected to %s", uc.network.GetName()))
			})
			uc.network.lastError = nil
		case eventUpstreamDisconnected:
			uc := e.uc

			uc.network.lock.Lock()
			uc.network.conn = nil
			uc.network.lock.Unlock()

			for _, ml := range uc.messageLoggers {
				if err := ml.Close(); err != nil {
					uc.logger.Printf("failed to close message logger: %v", err)
				}
			}

			uc.endPendingLISTs(true)

			if uc.network.lastError == nil {
				uc.forEachDownstream(func(dc *downstreamConn) {
					sendServiceNOTICE(dc, fmt.Sprintf("disconnected from %s", uc.network.GetName()))
				})
			}
		case eventUpstreamConnectionError:
			net := e.net

			if net.lastError == nil || net.lastError.Error() != e.err.Error() {
				net.forEachDownstream(func(dc *downstreamConn) {
					sendServiceNOTICE(dc, fmt.Sprintf("failed connecting/registering to %s: %v", net.GetName(), e.err))
				})
			}
			net.lastError = e.err
		case eventUpstreamError:
			uc := e.uc

			uc.forEachDownstream(func(dc *downstreamConn) {
				sendServiceNOTICE(dc, fmt.Sprintf("disconnected from %s: %v", uc.network.GetName(), e.err))
			})
			uc.network.lastError = e.err
		case eventUpstreamMessage:
			msg, uc := e.msg, e.uc
			if uc.isClosed() {
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

			u.forEachUpstream(func(uc *upstreamConn) {
				uc.updateAway()
			})
		case eventDownstreamDisconnected:
			dc := e.dc

			for net, rc := range dc.ringConsumers {
				seq := rc.Close()
				net.history[dc.clientName] = seq
			}

			for i := range u.downstreamConns {
				if u.downstreamConns[i] == dc {
					u.downstreamConns = append(u.downstreamConns[:i], u.downstreamConns[i+1:]...)
					break
				}
			}

			u.forEachUpstream(func(uc *upstreamConn) {
				uc.updateAway()
			})
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
			dc.ringConsumers[network] = network.ring.NewConsumer(nil)
		}
	})

	u.networks = append(u.networks, network)

	go network.run()
	return network, nil
}

func (u *user) deleteNetwork(id int64) error {
	for i, net := range u.networks {
		if net.ID != id {
			continue
		}

		if err := u.srv.db.DeleteNetwork(net.ID); err != nil {
			return err
		}

		u.forEachDownstream(func(dc *downstreamConn) {
			if dc.network != nil && dc.network == net {
				dc.Close()
			}
			delete(dc.ringConsumers, net)
		})

		net.Stop()
		net.ring.Close()
		u.networks = append(u.networks[:i], u.networks[i+1:]...)
		return nil
	}

	panic("tried deleting a non-existing network")
}
