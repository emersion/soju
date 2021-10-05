package soju

import (
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/irc.v3"
	"nhooyr.io/websocket"

	"git.sr.ht/~emersion/soju/config"
)

// TODO: make configurable
var retryConnectDelay = time.Minute
var connectTimeout = 15 * time.Second
var writeTimeout = 10 * time.Second
var upstreamMessageDelay = 2 * time.Second
var upstreamMessageBurst = 10

type Logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
}

type prefixLogger struct {
	logger Logger
	prefix string
}

var _ Logger = (*prefixLogger)(nil)

func (l *prefixLogger) Print(v ...interface{}) {
	v = append([]interface{}{l.prefix}, v...)
	l.logger.Print(v...)
}

func (l *prefixLogger) Printf(format string, v ...interface{}) {
	v = append([]interface{}{l.prefix}, v...)
	l.logger.Printf("%v"+format, v...)
}

type Server struct {
	Hostname       string
	Logger         Logger
	HistoryLimit   int
	LogPath        string
	Debug          bool
	HTTPOrigins    []string
	AcceptProxyIPs config.IPSet
	Identd         *Identd // can be nil

	db     Database
	stopWG sync.WaitGroup

	lock      sync.Mutex
	listeners map[net.Listener]struct{}
	users     map[string]*user
}

func NewServer(db Database) *Server {
	return &Server{
		Logger:       log.New(log.Writer(), "", log.LstdFlags),
		HistoryLimit: 1000,
		db:           db,
		listeners:    make(map[net.Listener]struct{}),
		users:        make(map[string]*user),
	}
}

func (s *Server) prefix() *irc.Prefix {
	return &irc.Prefix{Name: s.Hostname}
}

func (s *Server) Start() error {
	users, err := s.db.ListUsers()
	if err != nil {
		return err
	}

	s.lock.Lock()
	for i := range users {
		s.addUserLocked(&users[i])
	}
	s.lock.Unlock()

	return nil
}

func (s *Server) Shutdown() {
	s.lock.Lock()
	for ln := range s.listeners {
		if err := ln.Close(); err != nil {
			s.Logger.Printf("failed to stop listener: %v", err)
		}
	}
	for _, u := range s.users {
		u.events <- eventStop{}
	}
	s.lock.Unlock()

	s.stopWG.Wait()

	if err := s.db.Close(); err != nil {
		s.Logger.Printf("failed to close DB: %v", err)
	}
}

func (s *Server) createUser(user *User) (*user, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.users[user.Username]; ok {
		return nil, fmt.Errorf("user %q already exists", user.Username)
	}

	err := s.db.StoreUser(user)
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

func (s *Server) addUserLocked(user *User) *user {
	s.Logger.Printf("starting bouncer for user %q", user.Username)
	u := newUser(s, user)
	s.users[u.Username] = u

	s.stopWG.Add(1)

	go func() {
		u.run()

		s.lock.Lock()
		delete(s.users, u.Username)
		s.lock.Unlock()

		s.stopWG.Done()
	}()

	return u
}

var lastDownstreamID uint64 = 0

func (s *Server) handle(ic ircConn) {
	id := atomic.AddUint64(&lastDownstreamID, 1)
	dc := newDownstreamConn(s, ic, id)
	if err := dc.runUntilRegistered(); err != nil {
		dc.logger.Print(err)
	} else {
		dc.user.events <- eventDownstreamConnected{dc}
		if err := dc.readMessages(dc.user.events); err != nil {
			dc.logger.Print(err)
		}
		dc.user.events <- eventDownstreamDisconnected{dc}
	}
	dc.Close()
}

func (s *Server) Serve(ln net.Listener) error {
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
		// TODO: use net.ErrClosed when available
		if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go s.handle(newNetIRCConn(conn))
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		OriginPatterns: s.HTTPOrigins,
	})
	if err != nil {
		s.Logger.Printf("failed to serve HTTP connection: %v", err)
		return
	}

	isProxy := false
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			isProxy = s.AcceptProxyIPs.Contains(ip)
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

	s.handle(newWebsocketIRCConn(conn, remoteAddr))
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
