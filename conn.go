package soju

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"gopkg.in/irc.v3"
	"nhooyr.io/websocket"
)

// ircConn is a generic IRC connection. It's similar to net.Conn but focuses on
// reading and writing IRC messages.
type ircConn interface {
	ReadMessage() (*irc.Message, error)
	WriteMessage(*irc.Message) error
	Close() error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
}

func newNetIRCConn(c net.Conn) ircConn {
	type netConn net.Conn
	return struct {
		*irc.Conn
		netConn
	}{irc.NewConn(c), c}
}

type websocketIRCConn struct {
	conn                        *websocket.Conn
	readDeadline, writeDeadline time.Time
	remoteAddr                  string
}

func newWebsocketIRCConn(c *websocket.Conn, remoteAddr string) ircConn {
	return &websocketIRCConn{conn: c, remoteAddr: remoteAddr}
}

func (wic *websocketIRCConn) ReadMessage() (*irc.Message, error) {
	ctx := context.Background()
	if !wic.readDeadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, wic.readDeadline)
		defer cancel()
	}
	_, b, err := wic.conn.Read(ctx)
	if err != nil {
		switch websocket.CloseStatus(err) {
		case websocket.StatusNormalClosure, websocket.StatusGoingAway:
			return nil, io.EOF
		default:
			return nil, err
		}
	}
	return irc.ParseMessage(string(b))
}

func (wic *websocketIRCConn) WriteMessage(msg *irc.Message) error {
	b := []byte(strings.ToValidUTF8(msg.String(), string(unicode.ReplacementChar)))
	ctx := context.Background()
	if !wic.writeDeadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, wic.writeDeadline)
		defer cancel()
	}
	return wic.conn.Write(ctx, websocket.MessageText, b)
}

func isErrWebSocketClosed(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), "failed to close WebSocket: already wrote close")
}

func (wic *websocketIRCConn) Close() error {
	err := wic.conn.Close(websocket.StatusNormalClosure, "")
	// TODO: remove once this PR is merged:
	// https://github.com/nhooyr/websocket/pull/303
	if isErrWebSocketClosed(err) {
		return nil
	}
	return err
}

func (wic *websocketIRCConn) SetReadDeadline(t time.Time) error {
	wic.readDeadline = t
	return nil
}

func (wic *websocketIRCConn) SetWriteDeadline(t time.Time) error {
	wic.writeDeadline = t
	return nil
}

func (wic *websocketIRCConn) RemoteAddr() net.Addr {
	return websocketAddr(wic.remoteAddr)
}

func (wic *websocketIRCConn) LocalAddr() net.Addr {
	// Behind a reverse HTTP proxy, we don't have access to the real listening
	// address
	return websocketAddr("")
}

type websocketAddr string

func (websocketAddr) Network() string {
	return "ws"
}

func (wa websocketAddr) String() string {
	return string(wa)
}

type rateLimiter struct {
	C       <-chan struct{}
	ticker  *time.Ticker
	stopped chan struct{}
}

func newRateLimiter(delay time.Duration, burst int) *rateLimiter {
	ch := make(chan struct{}, burst)
	for i := 0; i < burst; i++ {
		ch <- struct{}{}
	}
	ticker := time.NewTicker(delay)
	stopped := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				select {
				case ch <- struct{}{}:
					// This space is intentionally left blank
				case <-stopped:
					return
				}
			case <-stopped:
				return
			}
		}
	}()
	return &rateLimiter{
		C:       ch,
		ticker:  ticker,
		stopped: stopped,
	}
}

func (rl *rateLimiter) Stop() {
	rl.ticker.Stop()
	close(rl.stopped)
}

type connOptions struct {
	Logger         Logger
	RateLimitDelay time.Duration
	RateLimitBurst int
}

type conn struct {
	conn   ircConn
	srv    *Server
	logger Logger

	lock     sync.Mutex
	outgoing chan<- *irc.Message
	closed   bool
}

func newConn(srv *Server, ic ircConn, options *connOptions) *conn {
	outgoing := make(chan *irc.Message, 64)
	c := &conn{
		conn:     ic,
		srv:      srv,
		outgoing: outgoing,
		logger:   options.Logger,
	}

	go func() {
		var rl *rateLimiter
		if options.RateLimitDelay > 0 && options.RateLimitBurst > 0 {
			rl = newRateLimiter(options.RateLimitDelay, options.RateLimitBurst)
			defer rl.Stop()
		}

		for msg := range outgoing {
			if rl != nil {
				<-rl.C
			}

			if c.srv.Debug {
				c.logger.Printf("sent: %v", msg)
			}
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := c.conn.WriteMessage(msg); err != nil {
				c.logger.Printf("failed to write message: %v", err)
				break
			}
		}
		if err := c.conn.Close(); err != nil && !isErrClosed(err) {
			c.logger.Printf("failed to close connection: %v", err)
		} else {
			c.logger.Printf("connection closed")
		}
		// Drain the outgoing channel to prevent SendMessage from blocking
		for range outgoing {
			// This space is intentionally left blank
		}
	}()

	c.logger.Printf("new connection")
	return c
}

func (c *conn) isClosed() bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.closed
}

// Close closes the connection. It is safe to call from any goroutine.
func (c *conn) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.closed {
		return fmt.Errorf("connection already closed")
	}

	err := c.conn.Close()
	c.closed = true
	close(c.outgoing)
	return err
}

func (c *conn) ReadMessage() (*irc.Message, error) {
	msg, err := c.conn.ReadMessage()
	if isErrClosed(err) {
		return nil, io.EOF
	} else if err != nil {
		return nil, err
	}

	if c.srv.Debug {
		c.logger.Printf("received: %v", msg)
	}

	return msg, nil
}

// SendMessage queues a new outgoing message. It is safe to call from any
// goroutine.
//
// If the connection is closed before the message is sent, SendMessage silently
// drops the message.
func (c *conn) SendMessage(msg *irc.Message) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.closed {
		return
	}
	c.outgoing <- msg
}

func (c *conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}
