package soju

import (
	"sync"
	"time"
)

type network struct {
	Network
	user *user
	conn *upstreamConn
}

func newNetwork(user *user, record *Network) *network {
	return &network{
		Network: *record,
		user:    user,
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

		net.user.lock.Lock()
		net.conn = uc
		net.user.lock.Unlock()

		if err := uc.readMessages(); err != nil {
			uc.logger.Printf("failed to handle messages: %v", err)
		}
		uc.Close()

		net.user.lock.Lock()
		net.conn = nil
		net.user.lock.Unlock()
	}
}

type user struct {
	User
	srv *Server

	lock            sync.Mutex
	networks        []*network
	downstreamConns []*downstreamConn
}

func newUser(srv *Server, record *User) *user {
	return &user{
		User: *record,
		srv:  srv,
	}
}

func (u *user) forEachNetwork(f func(*network)) {
	u.lock.Lock()
	for _, network := range u.networks {
		f(network)
	}
	u.lock.Unlock()
}

func (u *user) forEachUpstream(f func(uc *upstreamConn)) {
	u.lock.Lock()
	for _, network := range u.networks {
		uc := network.conn
		if uc == nil || !uc.registered || uc.closed {
			continue
		}
		f(uc)
	}
	u.lock.Unlock()
}

func (u *user) forEachDownstream(f func(dc *downstreamConn)) {
	u.lock.Lock()
	for _, dc := range u.downstreamConns {
		f(dc)
	}
	u.lock.Unlock()
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

	u.lock.Lock()
	for _, record := range networks {
		network := newNetwork(u, &record)
		u.networks = append(u.networks, network)

		go network.run()
	}
	u.lock.Unlock()
}

func (u *user) createNetwork(addr, nick string) (*network, error) {
	network := newNetwork(u, &Network{
		Addr: addr,
		Nick: nick,
	})
	err := u.srv.db.StoreNetwork(u.Username, &network.Network)
	if err != nil {
		return nil, err
	}
	u.lock.Lock()
	u.networks = append(u.networks, network)
	u.lock.Unlock()
	go network.run()
	return network, nil
}
