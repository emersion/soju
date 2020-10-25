package soju

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

type eventStop struct{}

type networkHistory struct {
	clients map[string]string // indexed by client name
}

type network struct {
	Network
	user    *user
	stopped chan struct{}

	conn           *upstreamConn
	channels       map[string]*Channel
	history        map[string]*networkHistory // indexed by entity
	offlineClients map[string]struct{}        // indexed by client name
	lastError      error
}

func newNetwork(user *user, record *Network, channels []Channel) *network {
	m := make(map[string]*Channel, len(channels))
	for _, ch := range channels {
		ch := ch
		m[ch.Name] = &ch
	}

	return &network{
		Network:        *record,
		user:           user,
		stopped:        make(chan struct{}),
		channels:       m,
		history:        make(map[string]*networkHistory),
		offlineClients: make(map[string]struct{}),
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

func (net *network) isStopped() bool {
	select {
	case <-net.stopped:
		return true
	default:
		return false
	}
}

func userIdent(u *User) string {
	// The ident is a string we will send to upstream servers in clear-text.
	// For privacy reasons, make sure it doesn't expose any meaningful user
	// metadata. We just use the base64-encoded hashed ID, so that people don't
	// start relying on the string being an integer or following a pattern.
	var b [64]byte
	binary.LittleEndian.PutUint64(b[:], uint64(u.ID))
	h := sha256.Sum256(b[:])
	return hex.EncodeToString(h[:16])
}

func (net *network) run() {
	var lastTry time.Time
	for {
		if net.isStopped() {
			return
		}

		if dur := time.Now().Sub(lastTry); dur < retryConnectDelay {
			delay := retryConnectDelay - dur
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

		if net.user.srv.Identd != nil {
			net.user.srv.Identd.Store(uc.RemoteAddr().String(), uc.LocalAddr().String(), userIdent(&net.user.User))
		}

		uc.register()
		if err := uc.runUntilRegistered(); err != nil {
			text := err.Error()
			if regErr, ok := err.(registrationError); ok {
				text = string(regErr)
			}
			uc.logger.Printf("failed to register: %v", text)
			net.user.events <- eventUpstreamConnectionError{net, fmt.Errorf("failed to register: %v", text)}
			uc.Close()
			continue
		}

		// TODO: this is racy with net.stopped. If the network is stopped
		// before the user goroutine receives eventUpstreamConnected, the
		// connection won't be closed.
		net.user.events <- eventUpstreamConnected{uc}
		if err := uc.readMessages(net.user.events); err != nil {
			uc.logger.Printf("failed to handle messages: %v", err)
			net.user.events <- eventUpstreamError{uc, fmt.Errorf("failed to handle messages: %v", err)}
		}
		uc.Close()
		net.user.events <- eventUpstreamDisconnected{uc}

		if net.user.srv.Identd != nil {
			net.user.srv.Identd.Delete(uc.RemoteAddr().String(), uc.LocalAddr().String())
		}
	}
}

func (net *network) stop() {
	if !net.isStopped() {
		close(net.stopped)
	}

	if net.conn != nil {
		net.conn.Close()
	}
}

func (net *network) createUpdateChannel(ch *Channel) error {
	if current, ok := net.channels[ch.Name]; ok {
		ch.ID = current.ID // update channel if it already exists
	}
	if err := net.user.srv.db.StoreChannel(net.ID, ch); err != nil {
		return err
	}
	prev := net.channels[ch.Name]
	net.channels[ch.Name] = ch

	if prev != nil && prev.Detached != ch.Detached {
		history := net.history[ch.Name]
		if ch.Detached {
			net.user.srv.Logger.Printf("network %q: detaching channel %q", net.GetName(), ch.Name)
			net.forEachDownstream(func(dc *downstreamConn) {
				net.offlineClients[dc.clientName] = struct{}{}

				dc.SendMessage(&irc.Message{
					Prefix:  dc.prefix(),
					Command: "PART",
					Params:  []string{dc.marshalEntity(net, ch.Name), "Detach"},
				})
			})
		} else {
			net.user.srv.Logger.Printf("network %q: attaching channel %q", net.GetName(), ch.Name)

			var uch *upstreamChannel
			if net.conn != nil {
				uch = net.conn.channels[ch.Name]
			}

			net.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(&irc.Message{
					Prefix:  dc.prefix(),
					Command: "JOIN",
					Params:  []string{dc.marshalEntity(net, ch.Name)},
				})

				if uch != nil {
					forwardChannel(dc, uch)
				}

				if history != nil {
					dc.sendNetworkHistory(net)
				}
			})
		}
	}

	return nil
}

func (net *network) deleteChannel(name string) error {
	ch, ok := net.channels[name]
	if !ok {
		return fmt.Errorf("unknown channel %q", name)
	}
	if err := net.user.srv.db.DeleteChannel(ch.ID); err != nil {
		return err
	}
	delete(net.channels, name)
	return nil
}

type user struct {
	User
	srv *Server

	events chan event
	done   chan struct{}

	networks        []*network
	downstreamConns []*downstreamConn
	msgStore        *messageStore

	// LIST commands in progress
	pendingLISTs []pendingLIST
}

type pendingLIST struct {
	downstreamID uint64
	// list of per-upstream LIST commands not yet sent or completed
	pendingCommands map[int64]*irc.Message
}

func newUser(srv *Server, record *User) *user {
	var msgStore *messageStore
	if srv.LogPath != "" {
		msgStore = newMessageStore(srv.LogPath, record.Username)
	}

	return &user{
		User:     *record,
		srv:      srv,
		events:   make(chan event, 64),
		done:     make(chan struct{}),
		msgStore: msgStore,
	}
}

func (u *user) forEachNetwork(f func(*network)) {
	for _, network := range u.networks {
		f(network)
	}
}

func (u *user) forEachUpstream(f func(uc *upstreamConn)) {
	for _, network := range u.networks {
		if network.conn == nil {
			continue
		}
		f(network.conn)
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

func (u *user) getNetworkByID(id int64) *network {
	for _, net := range u.networks {
		if net.ID == id {
			return net
		}
	}
	return nil
}

func (u *user) run() {
	defer func() {
		if u.msgStore != nil {
			if err := u.msgStore.Close(); err != nil {
				u.srv.Logger.Printf("failed to close message store for user %q: %v", u.Username, err)
			}
		}
		close(u.done)
	}()

	networks, err := u.srv.db.ListNetworks(u.ID)
	if err != nil {
		u.srv.Logger.Printf("failed to list networks for user %q: %v", u.Username, err)
		return
	}

	for _, record := range networks {
		record := record
		channels, err := u.srv.db.ListChannels(record.ID)
		if err != nil {
			u.srv.Logger.Printf("failed to list channels for user %q, network %q: %v", u.Username, record.GetName(), err)
			continue
		}

		network := newNetwork(u, &record, channels)
		u.networks = append(u.networks, network)

		go network.run()
	}

	for e := range u.events {
		switch e := e.(type) {
		case eventUpstreamConnected:
			uc := e.uc

			uc.network.conn = uc

			uc.updateAway()

			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.updateSupportedCaps()
				sendServiceNOTICE(dc, fmt.Sprintf("connected to %s", uc.network.GetName()))

				dc.updateNick()
			})
			uc.network.lastError = nil
		case eventUpstreamDisconnected:
			u.handleUpstreamDisconnected(e.uc)
		case eventUpstreamConnectionError:
			net := e.net

			stopped := false
			select {
			case <-net.stopped:
				stopped = true
			default:
			}

			if !stopped && (net.lastError == nil || net.lastError.Error() != e.err.Error()) {
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

			dc.updateSupportedCaps()
		case eventDownstreamDisconnected:
			dc := e.dc

			for i := range u.downstreamConns {
				if u.downstreamConns[i] == dc {
					u.downstreamConns = append(u.downstreamConns[:i], u.downstreamConns[i+1:]...)
					break
				}
			}

			// Save history if we're the last client with this name
			skipHistory := make(map[*network]bool)
			u.forEachDownstream(func(conn *downstreamConn) {
				if dc.clientName == conn.clientName {
					skipHistory[conn.network] = true
				}
			})

			dc.forEachNetwork(func(net *network) {
				if skipHistory[net] || skipHistory[nil] {
					return
				}

				net.offlineClients[dc.clientName] = struct{}{}
			})

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
		case eventStop:
			u.forEachDownstream(func(dc *downstreamConn) {
				dc.Close()
			})
			for _, n := range u.networks {
				n.stop()
			}
			return
		default:
			u.srv.Logger.Printf("received unknown event type: %T", e)
		}
	}
}

func (u *user) handleUpstreamDisconnected(uc *upstreamConn) {
	uc.network.conn = nil

	uc.endPendingLISTs(true)

	uc.forEachDownstream(func(dc *downstreamConn) {
		dc.updateSupportedCaps()
	})

	if uc.network.lastError == nil {
		uc.forEachDownstream(func(dc *downstreamConn) {
			sendServiceNOTICE(dc, fmt.Sprintf("disconnected from %s", uc.network.GetName()))
		})
	}
}

func (u *user) addNetwork(network *network) {
	u.networks = append(u.networks, network)
	go network.run()
}

func (u *user) removeNetwork(network *network) {
	network.stop()

	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.network != nil && dc.network == network {
			dc.Close()
		}
	})

	for i, net := range u.networks {
		if net == network {
			u.networks = append(u.networks[:i], u.networks[i+1:]...)
			return
		}
	}

	panic("tried to remove a non-existing network")
}

func (u *user) createNetwork(record *Network) (*network, error) {
	if record.ID != 0 {
		panic("tried creating an already-existing network")
	}

	network := newNetwork(u, record, nil)
	err := u.srv.db.StoreNetwork(u.ID, &network.Network)
	if err != nil {
		return nil, err
	}

	u.addNetwork(network)

	return network, nil
}

func (u *user) updateNetwork(record *Network) (*network, error) {
	if record.ID == 0 {
		panic("tried updating a new network")
	}

	network := u.getNetworkByID(record.ID)
	if network == nil {
		panic("tried updating a non-existing network")
	}

	if err := u.srv.db.StoreNetwork(u.ID, record); err != nil {
		return nil, err
	}

	// Most network changes require us to re-connect to the upstream server

	channels := make([]Channel, 0, len(network.channels))
	for _, ch := range network.channels {
		channels = append(channels, *ch)
	}

	updatedNetwork := newNetwork(u, record, channels)

	// If we're currently connected, disconnect and perform the necessary
	// bookkeeping
	if network.conn != nil {
		network.stop()
		// Note: this will set network.conn to nil
		u.handleUpstreamDisconnected(network.conn)
	}

	// Patch downstream connections to use our fresh updated network
	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.network != nil && dc.network == network {
			dc.network = updatedNetwork
		}
	})

	// We need to remove the network after patching downstream connections,
	// otherwise they'll get closed
	u.removeNetwork(network)

	// This will re-connect to the upstream server
	u.addNetwork(updatedNetwork)

	return updatedNetwork, nil
}

func (u *user) deleteNetwork(id int64) error {
	network := u.getNetworkByID(id)
	if network == nil {
		panic("tried deleting a non-existing network")
	}

	if err := u.srv.db.DeleteNetwork(network.ID); err != nil {
		return err
	}

	u.removeNetwork(network)
	return nil
}

func (u *user) updatePassword(hashed string) error {
	u.User.Password = hashed
	return u.srv.db.StoreUser(&u.User)
}

func (u *user) stop() {
	u.events <- eventStop{}
	<-u.done
}
