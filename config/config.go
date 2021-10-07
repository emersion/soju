package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"git.sr.ht/~emersion/go-scfg"
)

var (
	DefaultPath          string
	DefaultUnixAdminPath = "/run/soju/admin"
)

type IPSet []*net.IPNet

func (set IPSet) Contains(ip net.IP) bool {
	for _, n := range set {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// loopbackIPs contains the loopback networks 127.0.0.0/8 and ::1/128.
var loopbackIPs = IPSet{
	&net.IPNet{
		IP:   net.IP{127, 0, 0, 0},
		Mask: net.CIDRMask(8, 32),
	},
	&net.IPNet{
		IP:   net.IPv6loopback,
		Mask: net.CIDRMask(128, 128),
	},
}

func parseDuration(s string) (time.Duration, error) {
	if !strings.HasSuffix(s, "d") {
		return 0, fmt.Errorf("missing 'd' suffix in duration")
	}
	s = strings.TrimSuffix(s, "d")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration: %v", err)
	}
	return time.Duration(v * 24 * float64(time.Hour)), nil
}

type TLS struct {
	CertPath, KeyPath string
}

type DB struct {
	Driver, Source string
}

type MsgStore struct {
	Driver, Source string
}

type Auth struct {
	Driver, Source string
}

type Server struct {
	Listen   []string
	TLS      *TLS
	Hostname string
	Title    string
	MOTDPath string

	DB       DB
	MsgStore MsgStore
	Auth     Auth

	HTTPOrigins    []string
	AcceptProxyIPs IPSet

	MaxUserNetworks           int
	UpstreamUserIPs           []*net.IPNet
	DisableInactiveUsersDelay time.Duration
	EnableUsersOnAuth         bool
}

func Defaults() *Server {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	return &Server{
		Hostname: hostname,
		DB: DB{
			Driver: "sqlite3",
			Source: "soju.db",
		},
		MsgStore: MsgStore{
			Driver: "memory",
		},
		Auth: Auth{
			Driver: "internal",
		},
		MaxUserNetworks: -1,
	}
}

func Load(path string) (*Server, error) {
	cfg, err := scfg.Load(path)
	if err != nil {
		return nil, err
	}
	return parse(cfg)
}

func parse(cfg scfg.Block) (*Server, error) {
	srv := Defaults()
	for _, d := range cfg {
		switch d.Name {
		case "listen":
			var uri string
			if err := d.ParseParams(&uri); err != nil {
				return nil, err
			}
			srv.Listen = append(srv.Listen, uri)
		case "hostname":
			if err := d.ParseParams(&srv.Hostname); err != nil {
				return nil, err
			}
		case "title":
			if err := d.ParseParams(&srv.Title); err != nil {
				return nil, err
			}
		case "motd":
			if err := d.ParseParams(&srv.MOTDPath); err != nil {
				return nil, err
			}
		case "tls":
			tls := &TLS{}
			if err := d.ParseParams(&tls.CertPath, &tls.KeyPath); err != nil {
				return nil, err
			}
			srv.TLS = tls
		case "db":
			if err := d.ParseParams(&srv.DB.Driver, &srv.DB.Source); err != nil {
				return nil, err
			}
		case "message-store", "log":
			if err := d.ParseParams(&srv.MsgStore.Driver); err != nil {
				return nil, err
			}
			switch srv.MsgStore.Driver {
			case "memory", "db":
			case "fs":
				if err := d.ParseParams(nil, &srv.MsgStore.Source); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("directive %q: unknown driver %q", d.Name, srv.MsgStore.Driver)
			}
		case "auth":
			if err := d.ParseParams(&srv.Auth.Driver); err != nil {
				return nil, err
			}
			switch srv.Auth.Driver {
			case "internal", "pam", "srht":
				srv.Auth.Source = ""
			case "oauth2":
				if err := d.ParseParams(nil, &srv.Auth.Source); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("directive %q: unknown driver %q", d.Name, srv.Auth.Driver)
			}
		case "http-origin":
			srv.HTTPOrigins = d.Params
		case "accept-proxy-ip":
			srv.AcceptProxyIPs = nil
			for _, s := range d.Params {
				if s == "localhost" {
					srv.AcceptProxyIPs = append(srv.AcceptProxyIPs, loopbackIPs...)
					continue
				}
				_, n, err := net.ParseCIDR(s)
				if err != nil {
					return nil, fmt.Errorf("directive %q: failed to parse CIDR: %v", d.Name, err)
				}
				srv.AcceptProxyIPs = append(srv.AcceptProxyIPs, n)
			}
		case "max-user-networks":
			var max string
			if err := d.ParseParams(&max); err != nil {
				return nil, err
			}
			var err error
			if srv.MaxUserNetworks, err = strconv.Atoi(max); err != nil {
				return nil, fmt.Errorf("directive %q: %v", d.Name, err)
			}
		case "upstream-user-ip":
			if len(srv.UpstreamUserIPs) > 0 {
				return nil, fmt.Errorf("directive %q: can only be specified once", d.Name)
			}
			var hasIPv4, hasIPv6 bool
			for _, s := range d.Params {
				_, n, err := net.ParseCIDR(s)
				if err != nil {
					return nil, fmt.Errorf("directive %q: failed to parse CIDR: %v", d.Name, err)
				}
				if n.IP.To4() == nil {
					if hasIPv6 {
						return nil, fmt.Errorf("directive %q: found two IPv6 CIDRs", d.Name)
					}
					hasIPv6 = true
				} else {
					if hasIPv4 {
						return nil, fmt.Errorf("directive %q: found two IPv4 CIDRs", d.Name)
					}
					hasIPv4 = true
				}
				srv.UpstreamUserIPs = append(srv.UpstreamUserIPs, n)
			}
		case "disable-inactive-user":
			var durStr string
			if err := d.ParseParams(&durStr); err != nil {
				return nil, err
			}
			dur, err := parseDuration(durStr)
			if err != nil {
				return nil, fmt.Errorf("directive %q: %v", d.Name, err)
			} else if dur < 0 {
				return nil, fmt.Errorf("directive %q: duration must be positive", d.Name)
			}
			srv.DisableInactiveUsersDelay = dur
		case "enable-user-on-auth":
			var s string
			if err := d.ParseParams(&s); err != nil {
				return nil, err
			}
			b, err := strconv.ParseBool(s)
			if err != nil {
				return nil, fmt.Errorf("directive %q: %v", d.Name, err)
			}
			srv.EnableUsersOnAuth = b
		default:
			return nil, fmt.Errorf("unknown directive %q", d.Name)
		}
	}

	return srv, nil
}
