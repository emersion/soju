package soju

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/coder/websocket"
	"github.com/pires/go-proxyproto"
	"github.com/pires/go-proxyproto/tlvparse"
	"golang.org/x/time/rate"
	"gopkg.in/irc.v4"
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
	GetPeerCertificate() *x509.Certificate
}

type netConn net.Conn

type netIRCConn struct {
	*irc.Conn
	netConn
}

func (nc netIRCConn) GetPeerCertificate() *x509.Certificate {
	var c net.Conn = nc.netConn
	if pc, ok := c.(*proxyproto.Conn); ok {
		header := pc.ProxyHeader()
		if header != nil {
			cert, _ := certFromProxyprotoHeader(header)
			return cert
		}
		c = pc.Raw()
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		return nil
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}

func newNetIRCConn(c net.Conn) ircConn {
	return netIRCConn{irc.NewConn(c), c}
}

func certFromProxyprotoHeader(header *proxyproto.Header) (*x509.Certificate, error) {
	tlvs, err := header.TLVs()
	if err != nil {
		return nil, err
	}

	pp2ssl, ok := tlvparse.FindSSL(tlvs)
	if !ok {
		return nil, nil
	}

	raw, ok := pp2ssl.ClientCert()
	if !ok {
		return nil, nil
	}

	return x509.ParseCertificate(raw)
}

type websocketIRCConn struct {
	conn        *websocket.Conn
	req         *http.Request
	acceptProxy bool

	readDeadline, writeDeadline time.Time
}

func newWebsocketIRCConn(c *websocket.Conn, req *http.Request, acceptProxy bool) ircConn {
	return &websocketIRCConn{conn: c, req: req, acceptProxy: acceptProxy}
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

func (wic *websocketIRCConn) Close() error {
	return wic.conn.Close(websocket.StatusNormalClosure, "")
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
	// Only trust the Forwarded header field if this is a trusted proxy IP
	// to prevent users from spoofing the remote address
	remoteAddr := wic.req.RemoteAddr
	if wic.acceptProxy {
		forwarded := parseForwarded(wic.req.Header)
		if forwarded["for"] != "" {
			remoteAddr = forwarded["for"]
		}
	}
	return websocketAddr(remoteAddr)
}

func parseForwarded(h http.Header) map[string]string {
	forwarded := h.Get("Forwarded")
	if forwarded == "" {
		return map[string]string{
			"for":   h.Get("X-Forwarded-For"),
			"proto": h.Get("X-Forwarded-Proto"),
			"host":  h.Get("X-Forwarded-Host"),
		}
	}
	// Hack to easily parse header parameters
	_, params, _ := mime.ParseMediaType("hack; " + forwarded)
	return params
}

func (wic *websocketIRCConn) LocalAddr() net.Addr {
	// Behind a reverse HTTP proxy, we don't have access to the real listening
	// address
	return websocketAddr("")
}

func (wic *websocketIRCConn) GetPeerCertificate() *x509.Certificate {
	clientCert := wic.req.Header.Get("Client-Cert")
	if clientCert != "" && wic.acceptProxy {
		cert, _ := parseClientCert(clientCert)
		return cert
	}

	certs := wic.req.TLS.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}

func parseClientCert(s string) (*x509.Certificate, error) {
	s, prefixOK := strings.CutPrefix(s, ":")
	s, suffixOK := strings.CutSuffix(s, ":")
	if !prefixOK || !suffixOK {
		return nil, errors.New("missing ':' delimiters around byte sequence")
	}

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(b)
}

type websocketAddr string

func (websocketAddr) Network() string {
	return "ws"
}

func (wa websocketAddr) String() string {
	return string(wa)
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

	closed     atomic.Bool
	outgoingCh chan<- *irc.Message
	closedCh   chan struct{}
	rateLimit  bool
}

func newConn(srv *Server, ic ircConn, options *connOptions) *conn {
	outgoingCh := make(chan *irc.Message, 64)
	c := &conn{
		conn:       ic,
		srv:        srv,
		logger:     options.Logger,
		outgoingCh: outgoingCh,
		closedCh:   make(chan struct{}),
		rateLimit:  true,
	}

	go func() {
		ctx, cancel := c.NewContext(context.Background())
		defer cancel()

		rl := rate.NewLimiter(rate.Every(options.RateLimitDelay), options.RateLimitBurst)
		for {
			var msg *irc.Message
			select {
			case msg = <-outgoingCh:
			case <-c.closedCh:
			}
			if msg == nil {
				break
			}

			if c.rateLimit {
				if err := rl.Wait(ctx); err != nil {
					break
				}
			}

			c.logger.Debugf("sent: %v", msg)
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := c.conn.WriteMessage(msg); err != nil {
				c.logger.Printf("failed to write message: %v", err)
				break
			}
		}

		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.logger.Printf("failed to close connection: %v", err)
		} else {
			c.logger.Debugf("connection closed")
		}
	}()

	c.logger.Debugf("new connection")
	return c
}

func (c *conn) isClosed() bool {
	return c.closed.Load()
}

// Close closes the connection. It is safe to call from any goroutine.
func (c *conn) Close() error {
	if c.closed.Swap(true) {
		return net.ErrClosed
	}

	err := c.conn.Close()
	close(c.closedCh)
	return err
}

// Read reads an incoming message. It must be called from a single goroutine
// at a time.
//
// io.EOF is returned when there are no more messages to read.
func (c *conn) ReadMessage() (*irc.Message, error) {
	msg, err := c.conn.ReadMessage()
	if errors.Is(err, net.ErrClosed) {
		return nil, io.EOF
	} else if err != nil {
		return nil, err
	}

	c.logger.Debugf("received: %v", msg)
	return msg, nil
}

// SendMessage queues a new outgoing message. It is safe to call from any
// goroutine.
//
// If the connection is closed before the message is sent, SendMessage silently
// drops the message.
func (c *conn) SendMessage(ctx context.Context, msg *irc.Message) {
	if c.closed.Load() {
		return
	}

	select {
	case c.outgoingCh <- msg:
		// Success
	case <-c.closedCh:
		// Ignore
	case <-ctx.Done():
		c.logger.Printf("failed to send message: %v", ctx.Err())
	}
}

// Shutdown gracefully closes the connection, flushing any pending message.
func (c *conn) Shutdown(ctx context.Context) {
	if c.closed.Load() {
		return
	}

	select {
	case c.outgoingCh <- nil:
		// Success
	case <-c.closedCh:
		// Ignore
	case <-ctx.Done():
		c.logger.Printf("failed to shutdown connection: %v", ctx.Err())
		// Forcibly close the connection
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.logger.Printf("failed to close connection: %v", err)
		}
	}
}

func (c *conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// NewContext returns a copy of the parent context with a new Done channel. The
// returned context's Done channel is closed when the connection is closed,
// when the returned cancel function is called, or when the parent context's
// Done channel is closed, whichever happens first.
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this Context complete.
func (c *conn) NewContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)

	go func() {
		defer cancel()

		select {
		case <-ctx.Done():
			// The parent context has been cancelled, or the caller has called
			// cancel()
		case <-c.closedCh:
			// The connection has been closed
		}
	}()

	return ctx, cancel
}
