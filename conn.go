package soju

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

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
}

func newWebsocketIRCConn(c *websocket.Conn) ircConn {
	return websocketIRCConn{conn: c}
}

func (wic websocketIRCConn) ReadMessage() (*irc.Message, error) {
	ctx := context.Background()
	if !wic.readDeadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, wic.readDeadline)
		defer cancel()
	}
	_, b, err := wic.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	return irc.ParseMessage(string(b))
}

func (wic websocketIRCConn) WriteMessage(msg *irc.Message) error {
	b := []byte(msg.String())
	ctx := context.Background()
	if !wic.writeDeadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, wic.writeDeadline)
		defer cancel()
	}
	return wic.conn.Write(ctx, websocket.MessageText, b)
}

func (wic websocketIRCConn) Close() error {
	return wic.conn.Close(websocket.StatusNormalClosure, "")
}

func (wic websocketIRCConn) SetReadDeadline(t time.Time) error {
	wic.readDeadline = t
	return nil
}

func (wic websocketIRCConn) SetWriteDeadline(t time.Time) error {
	wic.writeDeadline = t
	return nil
}

type conn struct {
	conn   ircConn
	srv    *Server
	logger Logger

	lock     sync.Mutex
	outgoing chan<- *irc.Message
	closed   bool
}

func newConn(srv *Server, ic ircConn, logger Logger) *conn {
	outgoing := make(chan *irc.Message, 64)
	c := &conn{
		conn:     ic,
		srv:      srv,
		outgoing: outgoing,
		logger:   logger,
	}

	go func() {
		for msg := range outgoing {
			if c.srv.Debug {
				c.logger.Printf("sent: %v", msg)
			}
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := c.conn.WriteMessage(msg); err != nil {
				c.logger.Printf("failed to write message: %v", err)
				break
			}
		}
		if err := c.conn.Close(); err != nil {
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
	if err != nil {
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
