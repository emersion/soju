package soju

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var identdTimeout = 10 * time.Second

type identKey struct {
	remoteHost string
	remotePort int
	localPort  int
}

func newIdentKey(remoteAddr, localAddr string) (*identKey, error) {
	remoteHost, remotePort, err := splitHostPort(remoteAddr)
	if err != nil {
		return nil, err
	}
	_, localPort, err := splitHostPort(localAddr)
	if err != nil {
		return nil, err
	}
	return &identKey{
		remoteHost: remoteHost,
		remotePort: remotePort,
		localPort:  localPort,
	}, nil
}

func splitHostPort(addr string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err = strconv.Atoi(portStr)
	return host, port, err
}

// Identd implements an ident server, as described in RFC 1413.
type Identd struct {
	entries map[identKey]string
	lock    sync.RWMutex
}

func NewIdentd() *Identd {
	return &Identd{entries: make(map[identKey]string)}
}

func (s *Identd) Store(remoteAddr, localAddr, ident string) {
	k, err := newIdentKey(remoteAddr, localAddr)
	if err != nil {
		return
	}
	s.lock.Lock()
	s.entries[*k] = ident
	s.lock.Unlock()
}

func (s *Identd) Delete(remoteAddr, localAddr string) {
	k, err := newIdentKey(remoteAddr, localAddr)
	if err != nil {
		return
	}
	s.lock.Lock()
	delete(s.entries, *k)
	s.lock.Unlock()
}

func (s *Identd) Serve(ln net.Listener) error {
	ln = &retryListener{Listener: ln}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go s.handle(conn)
	}
}

func (s *Identd) handle(c net.Conn) {
	defer c.Close()

	remoteHost, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(c)

	// We only read to read lines with two port numbers
	var buf [512]byte
	scanner.Buffer(buf[:], len(buf))

	for {
		c.SetDeadline(time.Now().Add(identdTimeout))
		if !scanner.Scan() {
			break
		}
		l := scanner.Text()

		localPort, remotePort, err := parseIdentQuery(l)
		if err != nil {
			fmt.Fprintf(c, "%s : ERROR : INVALID-PORT\r\n", l)
			break
		}

		k := identKey{
			remoteHost: remoteHost,
			remotePort: remotePort,
			localPort:  localPort,
		}

		s.lock.RLock()
		ident := s.entries[k]
		s.lock.RUnlock()

		if ident == "" {
			fmt.Fprintf(c, "%s : ERROR : NO-USER\r\n", l)
			break
		}

		fmt.Fprintf(c, "%s : USERID : OTHER : %s\r\n", l, ident)
	}
}

func parseIdentQuery(l string) (localPort, remotePort int, err error) {
	parts := strings.SplitN(l, ",", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected two ports")
	}
	localStr, remoteStr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if localPort, err = strconv.Atoi(localStr); err != nil {
		return 0, 0, err
	}
	if remotePort, err = strconv.Atoi(remoteStr); err != nil {
		return 0, 0, err
	}
	if localPort <= 0 || remotePort <= 0 {
		return 0, 0, fmt.Errorf("invalid port")
	}
	return localPort, remotePort, nil
}
