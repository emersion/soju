package soju

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gopkg.in/irc.v4"

	"codeberg.org/emersion/soju/auth"
	"codeberg.org/emersion/soju/config"
	"codeberg.org/emersion/soju/database"
	"codeberg.org/emersion/soju/fileupload"
	"codeberg.org/emersion/soju/identd"
)

var (
	retryConnectMinDelay           = time.Minute
	retryConnectMaxDelay           = 10 * time.Minute
	retryConnectJitter             = time.Minute
	connectTimeout                 = 15 * time.Second
	writeTimeout                   = 10 * time.Second
	upstreamMessageDelay           = 2 * time.Second
	upstreamMessageBurst           = 10
	backlogTimeout                 = 10 * time.Second
	handleDownstreamMessageTimeout = 10 * time.Second
	downstreamRegisterTimeout      = 30 * time.Second
	webpushCheckSubscriptionDelay  = 24 * time.Hour
	webpushPruneSubscriptionDelay  = 30 * 24 * time.Hour
	chatHistoryLimit               = 1000
	backlogLimit                   = 4000
)

var errWebPushSubscriptionExpired = fmt.Errorf("Web Push subscription expired")

var errWebPushToInternalIP = fmt.Errorf("cannot connect to internal IP address")

var webPushHTTPClient webpush.HTTPClient = buildWebPushHTTPClient()

type Logger interface {
	Printf(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

type logger interface {
	Printf(format string, v ...interface{})
}

type DebugLogger struct {
	logger
	debug atomic.Bool
}

func (l *DebugLogger) Debugf(format string, v ...interface{}) {
	if !l.debug.Load() {
		return
	}
	l.logger.Printf(format, v...)
}

func NewLogger(out io.Writer, debug bool) *DebugLogger {
	l := &DebugLogger{
		logger: log.New(out, "", log.LstdFlags),
	}
	l.debug.Store(debug)
	return l
}

type prefixLogger struct {
	logger Logger
	prefix string
}

var _ Logger = (*prefixLogger)(nil)

func (l *prefixLogger) Printf(format string, v ...interface{}) {
	v = append([]interface{}{l.prefix}, v...)
	l.logger.Printf("%v"+format, v...)
}

func (l *prefixLogger) Debugf(format string, v ...interface{}) {
	v = append([]interface{}{l.prefix}, v...)
	l.logger.Debugf("%v"+format, v...)
}

type int64Gauge struct {
	v int64 // atomic
}

func (g *int64Gauge) Add(delta int64) {
	atomic.AddInt64(&g.v, delta)
}

func (g *int64Gauge) Value() int64 {
	return atomic.LoadInt64(&g.v)
}

func (g *int64Gauge) Float64() float64 {
	return float64(g.Value())
}

type retryListener struct {
	net.Listener
	Logger Logger

	delay time.Duration
}

func NewRetryListener(ln net.Listener) net.Listener {
	return &retryListener{Listener: ln}
}

func (ln *retryListener) Accept() (net.Conn, error) {
	for {
		conn, err := ln.Listener.Accept()
		if ne, ok := err.(net.Error); ok && ne.Temporary() {
			if ln.delay == 0 {
				ln.delay = 5 * time.Millisecond
			} else {
				ln.delay *= 2
			}
			if max := 1 * time.Second; ln.delay > max {
				ln.delay = max
			}
			if ln.Logger != nil {
				ln.Logger.Printf("accept error (retrying in %v): %v", ln.delay, err)
			}
			time.Sleep(ln.delay)
		} else {
			ln.delay = 0
			return conn, err
		}
	}
}

type Config struct {
	Hostname                  string
	Title                     string
	IconPath                  string
	IconURL                   string
	MsgStoreDriver            string
	MsgStorePath              string
	HTTPOrigins               []string
	HTTPIngress               string
	AcceptProxyIPs            config.IPSet
	AcceptProxyUnix           bool
	MaxUserNetworks           int
	MOTD                      string
	UpstreamUserIPs           []*net.IPNet
	DisableInactiveUsersDelay time.Duration
	EnableUsersOnAuth         bool
	Auth                      *auth.Authenticator
	FileUploader              fileupload.Uploader
}

type Server struct {
	Logger          *DebugLogger
	Identd          *identd.Identd        // can be nil
	MetricsRegistry prometheus.Registerer // can be nil

	config atomic.Value // *Config
	db     database.Database
	stopWG sync.WaitGroup
	stopCh chan struct{}

	lock      sync.Mutex
	listeners map[net.Listener]struct{}
	users     map[string]*user
	shutdown  bool

	metrics struct {
		downstreams int64Gauge
		upstreams   int64Gauge

		upstreamOutMessagesTotal   prometheus.Counter
		upstreamInMessagesTotal    prometheus.Counter
		downstreamOutMessagesTotal prometheus.Counter
		downstreamInMessagesTotal  prometheus.Counter

		upstreamConnectErrorsTotal prometheus.Counter
		workerPanicsTotal          prometheus.Counter
	}

	webPush *database.WebPushConfig
}

func NewServer(db database.Database) *Server {
	srv := &Server{
		Logger:    NewLogger(log.Writer(), true),
		db:        db,
		listeners: make(map[net.Listener]struct{}),
		users:     make(map[string]*user),
		stopCh:    make(chan struct{}),
	}
	srv.config.Store(&Config{
		Hostname:        "localhost",
		MaxUserNetworks: -1,
		Auth:            auth.NewInternal(),
	})
	return srv
}

func (s *Server) prefix() *irc.Prefix {
	return &irc.Prefix{Name: s.Config().Hostname}
}

func (s *Server) Config() *Config {
	return s.config.Load().(*Config)
}

func (s *Server) SetConfig(cfg *Config) {
	s.config.Store(cfg)
}

func (s *Server) Start() error {
	s.registerMetrics()

	if err := s.loadWebPushConfig(context.TODO()); err != nil {
		return err
	}

	users, err := s.db.ListUsers(context.TODO())
	if err != nil {
		return err
	}

	s.lock.Lock()
	for i := range users {
		s.addUserLocked(&users[i])
	}
	s.lock.Unlock()

	s.stopWG.Add(1)
	go func() {
		defer s.stopWG.Done()
		s.disableInactiveUsersLoop()
	}()

	return nil
}

func (s *Server) registerMetrics() {
	factory := promauto.With(s.MetricsRegistry)

	factory.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "soju_users_active",
		Help: "Current number of active users",
	}, func() float64 {
		s.lock.Lock()
		n := len(s.users)
		s.lock.Unlock()
		return float64(n)
	})

	factory.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "soju_downstreams_active",
		Help: "Current number of downstream connections",
	}, s.metrics.downstreams.Float64)

	factory.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "soju_upstreams_active",
		Help: "Current number of upstream connections",
	}, s.metrics.upstreams.Float64)

	s.metrics.upstreamOutMessagesTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_upstream_out_messages_total",
		Help: "Total number of outgoing messages sent to upstream servers",
	})

	s.metrics.upstreamInMessagesTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_upstream_in_messages_total",
		Help: "Total number of incoming messages received from upstream servers",
	})

	s.metrics.downstreamOutMessagesTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_downstream_out_messages_total",
		Help: "Total number of outgoing messages sent to downstream clients",
	})

	s.metrics.downstreamInMessagesTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_downstream_in_messages_total",
		Help: "Total number of incoming messages received from downstream clients",
	})

	s.metrics.upstreamConnectErrorsTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_upstream_connect_errors_total",
		Help: "Total number of upstream connection errors",
	})

	s.metrics.workerPanicsTotal = factory.NewCounter(prometheus.CounterOpts{
		Name: "soju_worker_panics_total",
		Help: "Total number of panics in worker goroutines",
	})
}

func (s *Server) loadWebPushConfig(ctx context.Context) error {
	configs, err := s.db.ListWebPushConfigs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list Web push configs: %v", err)
	}

	if len(configs) > 1 {
		return fmt.Errorf("expected zero or one Web push config, got %v", len(configs))
	} else if len(configs) == 1 {
		s.webPush = &configs[0]
		return nil
	}

	s.Logger.Printf("generating Web push VAPID key pair")
	priv, pub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return fmt.Errorf("failed to generate Web push VAPID key pair: %v", err)
	}

	config := new(database.WebPushConfig)
	config.VAPIDKeys.Public = pub
	config.VAPIDKeys.Private = priv
	if err := s.db.StoreWebPushConfig(ctx, config); err != nil {
		return fmt.Errorf("failed to store Web push config: %v", err)
	}

	s.webPush = config
	return nil
}

func (s *Server) sendWebPush(ctx context.Context, sub *webpush.Subscription, vapidPubKey string, msg *irc.Message) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var urgency webpush.Urgency
	switch msg.Command {
	case "PRIVMSG", "NOTICE", "INVITE":
		urgency = webpush.UrgencyHigh
	default:
		urgency = webpush.UrgencyNormal
	}

	options := webpush.Options{
		HTTPClient:      webPushHTTPClient,
		VAPIDPublicKey:  s.webPush.VAPIDKeys.Public,
		VAPIDPrivateKey: s.webPush.VAPIDKeys.Private,
		Subscriber:      "https://soju.im",
		TTL:             7 * 24 * 60 * 60, // seconds
		Urgency:         urgency,
		RecordSize:      2048,
	}

	if vapidPubKey != options.VAPIDPublicKey {
		return fmt.Errorf("unknown VAPID public key %q", vapidPubKey)
	}

	payload := []byte(msg.String())
	resp, err := webpush.SendNotificationWithContext(ctx, payload, sub, &options)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// 404 means the subscription has expired as per RFC 8030 section 7.3
	if resp.StatusCode == http.StatusNotFound {
		return errWebPushSubscriptionExpired
	} else if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP error: %v", resp.Status)
	}

	return nil
}

func (s *Server) Shutdown() {
	s.Logger.Printf("shutting down server")

	close(s.stopCh)

	s.lock.Lock()
	s.shutdown = true
	for ln := range s.listeners {
		if err := ln.Close(); err != nil {
			s.Logger.Printf("failed to stop listener: %v", err)
		}
	}
	for _, u := range s.users {
		u.events <- eventStop{}
	}
	s.lock.Unlock()

	s.Logger.Printf("waiting for users to finish")
	s.stopWG.Wait()

	if err := s.db.Close(); err != nil {
		s.Logger.Printf("failed to close DB: %v", err)
	}
}

func (s *Server) createUser(ctx context.Context, user *database.User) (*user, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.users[user.Username]; ok {
		return nil, fmt.Errorf("user %q already exists", user.Username)
	}

	err := s.db.StoreUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("could not create user in db: %v", err)
	}

	return s.addUserLocked(user), nil
}

func (s *Server) forEachUser(f func(*user)) {
	s.lock.Lock()
	for _, u := range s.users {
		f(u)
	}
	s.lock.Unlock()
}

func (s *Server) getUser(name string) *user {
	s.lock.Lock()
	u := s.users[name]
	s.lock.Unlock()
	return u
}

func (s *Server) addUserLocked(user *database.User) *user {
	s.Logger.Printf("starting bouncer for user %q", user.Username)
	u := newUser(s, user)
	s.users[u.Username] = u

	s.stopWG.Add(1)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				s.Logger.Printf("panic serving user %q: %v\n%v", user.Username, err, string(debug.Stack()))
				s.metrics.workerPanicsTotal.Inc()
			}

			s.lock.Lock()
			delete(s.users, u.Username)
			s.lock.Unlock()

			s.stopWG.Done()
		}()

		u.run()
	}()

	return u
}

var lastDownstreamID uint64

func (s *Server) Handle(ic ircConn) {
	defer func() {
		if err := recover(); err != nil {
			s.Logger.Printf("panic serving downstream %q: %v\n%v", ic.RemoteAddr(), err, string(debug.Stack()))
		}
	}()

	s.lock.Lock()
	shutdown := s.shutdown
	s.lock.Unlock()

	s.metrics.downstreams.Add(1)
	defer s.metrics.downstreams.Add(-1)

	id := atomic.AddUint64(&lastDownstreamID, 1)
	dc := newDownstreamConn(s, ic, id)
	defer dc.Shutdown(context.TODO())

	if shutdown {
		dc.SendMessage(context.TODO(), &irc.Message{
			Command: "ERROR",
			Params:  []string{"Server is shutting down"},
		})
		return
	}

	if err := dc.runUntilRegistered(); err != nil {
		if !errors.Is(err, io.EOF) {
			dc.logger.Printf("%v", err)
		}
		return
	}

	user, err := s.getOrCreateUser(context.TODO(), dc.registration.authUsername)
	if err != nil {
		dc.logger.Printf("failed to get/create user: %v", err)
		dc.SendMessage(context.TODO(), &irc.Message{
			Command: "ERROR",
			Params:  []string{"Internal server error"},
		})
		return
	}

	user.events <- eventDownstreamConnected{dc}
	if err := dc.readMessages(user.events); err != nil {
		dc.logger.Printf("%v", err)
	}
	user.events <- eventDownstreamDisconnected{dc}
}

func (s *Server) getOrCreateUser(ctx context.Context, username string) (*user, error) {
	user := s.getUser(username)
	if user != nil {
		return user, nil
	}

	if _, err := s.db.GetUser(ctx, username); err == nil {
		return nil, fmt.Errorf("user %q exists in the DB but hasn't been loaded by the bouncer -- a restart may help", username)
	}

	if !s.Config().EnableUsersOnAuth {
		return nil, fmt.Errorf("cannot find user %q in the DB", username)
	}

	// Can't find the user in the DB -- try to create it
	record := database.NewUser(username)
	user, err := s.createUser(ctx, record)
	if err != nil {
		return nil, fmt.Errorf("failed to automatically create user %q after successful authentication: %v", username, err)
	}
	return user, nil
}

func (s *Server) HandleAdmin(ic ircConn) {
	defer func() {
		if err := recover(); err != nil {
			s.Logger.Printf("panic serving admin client %q: %v\n%v", ic.RemoteAddr(), err, string(debug.Stack()))
		}
	}()

	s.lock.Lock()
	shutdown := s.shutdown
	s.lock.Unlock()

	ctx := context.TODO()
	remoteAddr := ic.RemoteAddr().String()
	logger := &prefixLogger{s.Logger, fmt.Sprintf("admin %q: ", remoteAddr)}
	c := newConn(s, ic, &connOptions{Logger: logger})
	defer c.Close()

	if shutdown {
		c.SendMessage(ctx, &irc.Message{
			Command: "ERROR",
			Params:  []string{"Server is shutting down"},
		})
		return
	}
	for {
		msg, err := c.ReadMessage()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			logger.Printf("failed to read IRC command: %v", err)
			break
		}
		switch msg.Command {
		case "CAP", "NICK", "USER", "PASS":
			// Ensure regular IRC clients cannot connect. This is important to
			// e.g. prevent unprivileged soju users from connecting to the
			// admin socket.
			c.SendMessage(ctx, &irc.Message{
				Command: "ERROR",
				Params:  []string{"This is not a regular IRC server"},
			})
			return
		case "BOUNCERSERV":
			if len(msg.Params) < 1 {
				c.SendMessage(ctx, &irc.Message{
					Command: irc.ERR_NEEDMOREPARAMS,
					Params: []string{
						"*",
						msg.Command,
						"Not enough parameters",
					},
				})
				break
			}
			err := handleServicePRIVMSG(&serviceContext{
				Context: ctx,
				srv:     s,
				admin:   true,
				print: func(text string) {
					c.SendMessage(ctx, &irc.Message{
						Prefix:  s.prefix(),
						Command: "PRIVMSG",
						Params:  []string{"*", text},
					})
				},
			}, msg.Params[0])
			if err != nil {
				c.SendMessage(ctx, &irc.Message{
					Prefix:  s.prefix(),
					Command: "FAIL",
					Params:  []string{msg.Command, err.Error()},
				})
			} else {
				c.SendMessage(ctx, &irc.Message{
					Prefix:  s.prefix(),
					Command: msg.Command,
					Params:  []string{"OK"},
				})
			}
		default:
			c.SendMessage(ctx, &irc.Message{
				Prefix:  s.prefix(),
				Command: irc.ERR_UNKNOWNCOMMAND,
				Params: []string{
					"*",
					msg.Command,
					"Unknown command",
				},
			})
		}
	}
}

func (s *Server) Serve(ln net.Listener, handler func(ircConn)) error {
	ln = &retryListener{
		Listener: ln,
		Logger:   &prefixLogger{logger: s.Logger, prefix: fmt.Sprintf("listener %v: ", ln.Addr())},
	}

	s.lock.Lock()
	s.listeners[ln] = struct{}{}
	s.lock.Unlock()

	s.stopWG.Add(1)

	defer func() {
		s.lock.Lock()
		delete(s.listeners, ln)
		s.lock.Unlock()

		s.stopWG.Done()
	}()

	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go handler(newNetIRCConn(conn))
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		Subprotocols:   []string{"text.ircv3.net"}, // non-compliant, fight me
		OriginPatterns: s.Config().HTTPOrigins,
	})
	if err != nil {
		s.Logger.Printf("failed to serve HTTP connection: %v", err)
		return
	}

	isProxy := false
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			isProxy = s.Config().AcceptProxyIPs.Contains(ip)
		}
	}

	// Only trust the Forwarded header field if this is a trusted proxy IP
	// to prevent users from spoofing the remote address
	remoteAddr := req.RemoteAddr
	if isProxy {
		forwarded := parseForwarded(req.Header)
		if forwarded["for"] != "" {
			remoteAddr = forwarded["for"]
		}
	}

	s.Handle(newWebsocketIRCConn(conn, remoteAddr))
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

type ServerStats struct {
	Users       int
	Downstreams int64
	Upstreams   int64
}

func (s *Server) Stats() *ServerStats {
	var stats ServerStats
	s.lock.Lock()
	stats.Users = len(s.users)
	s.lock.Unlock()
	stats.Downstreams = s.metrics.downstreams.Value()
	stats.Upstreams = s.metrics.upstreams.Value()
	return &stats
}

func (s *Server) disableInactiveUsersLoop() {
	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
		}

		if err := s.disableInactiveUsers(context.TODO()); err != nil {
			s.Logger.Printf("failed to disable inactive users: %v", err)
		}
	}
}

func (s *Server) disableInactiveUsers(ctx context.Context) error {
	delay := s.Config().DisableInactiveUsersDelay
	if delay == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	usernames, err := s.db.ListInactiveUsernames(ctx, time.Now().Add(-delay))
	if err != nil {
		return fmt.Errorf("failed to list inactive users: %v", err)
	} else if len(usernames) == 0 {
		return nil
	}

	// Filter out users with active downstream connections
	var users []*user
	s.lock.Lock()
	for _, username := range usernames {
		u := s.users[username]
		if u == nil {
			// TODO: disable the user in the DB
			continue
		}

		if n := u.numDownstreamConns.Load(); n > 0 {
			continue
		}

		users = append(users, u)
	}
	s.lock.Unlock()

	if len(users) == 0 {
		return nil
	}

	s.Logger.Printf("found %v inactive users", len(users))
	for _, u := range users {
		done := make(chan error, 1)
		enabled := false
		event := eventUserUpdate{
			enabled: &enabled,
			done:    done,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case u.events <- event:
			// Event was sent, let's wait for the reply
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			if err != nil {
				return err
			} else {
				s.Logger.Printf("deleted inactive user %q", u.Username)
			}
		}
	}

	return nil
}

func buildWebPushHTTPClient() *http.Client {
	// this is a dialer that can only connect to external IP addresses
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			ip, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			parsedIP, err := netip.ParseAddr(ip)
			if err != nil {
				return err
			}
			if parsedIP.IsLoopback() || parsedIP.IsMulticast() || parsedIP.IsPrivate() {
				return errWebPushToInternalIP
			}
			return nil
		},
	}

	return &http.Client{
		Transport: &userAgentHTTPTransport{
			userAgent: "soju",
			transport: http.Transport{
				DialContext: dialer.DialContext,
			},
		},
	}
}

type userAgentHTTPTransport struct {
	userAgent string
	transport http.Transport
}

func (ua *userAgentHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", ua.userAgent)
	return ua.transport.RoundTrip(req)
}
