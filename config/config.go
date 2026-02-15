package config

import (
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"codeberg.org/emersion/go-scfg"
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

type FileUpload struct {
	Driver, Source string
}

type Server struct {
	Listen   []string
	TLS      *TLS
	Hostname string
	Title    string
	Icon     string
	MOTDPath string

	DB         DB
	MsgStore   MsgStore
	Auth       []Auth
	FileUpload *FileUpload

	HTTPOrigins     []string
	HTTPIngress     string
	AcceptProxyIPs  IPSet
	AcceptProxyUnix bool

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
			Driver: "db",
		},
		Auth: []Auth{{
			Driver: "internal",
		}},
		HTTPIngress:     "https://" + hostname,
		MaxUserNetworks: -1,
	}
}

func Load(filename string) (*Server, error) {
	var raw struct {
		Listen []struct {
			Addr string `scfg:",param"`
		} `scfg:"listen"`
		Hostname     string     `scfg:"hostname"`
		Title        string     `scfg:"title"`
		Icon         string     `scfg:"icon"`
		MOTD         string     `scfg:"motd"`
		TLS          *[2]string `scfg:"tls"`
		DB           *[2]string `scfg:"db"`
		MessageStore []string   `scfg:"message-store"`
		Log          []string   `scfg:"log"`
		Auth         []struct {
			Params []string `scfg:",param"`
		} `scfg:"auth"`
		FileUpload          []string `scfg:"file-upload"`
		HTTPOrigin          []string `scfg:"http-origin"`
		HTTPIngress         string   `scfg:"http-ingress"`
		AcceptProxyIP       []string `scfg:"accept-proxy-ip"`
		AcceptProxyUnix     string   `scfg:"accept-proxy-unix"`
		MaxUserNetworks     int      `scfg:"max-user-networks"`
		UpstreamUserIP      []string `scfg:"upstream-user-ip"`
		DisableInactiveUser string   `scfg:"disable-inactive-user"`
		EnableUserOnAuth    string   `scfg:"enable-user-on-auth"`
	}

	raw.MaxUserNetworks = -1

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := scfg.NewDecoder(f).Decode(&raw); err != nil {
		return nil, err
	}

	srv := Defaults()

	for _, listen := range raw.Listen {
		srv.Listen = append(srv.Listen, listen.Addr)
	}
	if raw.Hostname != "" {
		srv.Hostname = raw.Hostname
	}
	srv.Title = raw.Title
	srv.Icon = raw.Icon
	srv.MOTDPath = raw.MOTD
	if raw.TLS != nil {
		srv.TLS = &TLS{CertPath: raw.TLS[0], KeyPath: raw.TLS[1]}
	}
	if raw.DB != nil {
		srv.DB = DB{Driver: raw.DB[0], Source: raw.DB[1]}
	}
	if raw.MessageStore == nil {
		raw.MessageStore = raw.Log
	}
	if raw.MessageStore != nil {
		driver, source, err := parseDriverSource("message-store", raw.MessageStore)
		if err != nil {
			return nil, err
		}
		switch driver {
		case "memory", "db":
			if source != "" {
				return nil, fmt.Errorf("directive message-store: driver %q requires zero parameters", driver)
			}
		case "fs":
			if source == "" {
				return nil, fmt.Errorf("directive message-store: driver %q requires a source", driver)
			}
		default:
			return nil, fmt.Errorf("directive message-store: unknown driver %q", driver)
		}
		srv.MsgStore = MsgStore{driver, source}
	}
	if len(raw.Auth) != 0 {
		// drop default auth if we are explicitly defining any auth
		srv.Auth = nil
	}
	for _, auth := range raw.Auth {
		driver, source, err := parseDriverSource("auth", auth.Params)
		if err != nil {
			return nil, err
		}
		switch driver {
		case "internal", "pam":
			if source != "" {
				return nil, fmt.Errorf("directive auth: driver %q requires zero parameters", driver)
			}
		case "http", "oauth2":
			if source == "" {
				return nil, fmt.Errorf("directive auth: driver %q requires a source", driver)
			}
		default:
			return nil, fmt.Errorf("directive auth: unknown driver %q", driver)
		}
		srv.Auth = append(srv.Auth, Auth{driver, source})
	}
	if raw.FileUpload != nil {
		driver, source, err := parseDriverSource("file-upload", raw.FileUpload)
		if err != nil {
			return nil, err
		}
		switch driver {
		case "fs", "http":
			if source == "" {
				return nil, fmt.Errorf("directive file-upload: driver %q requires a source", driver)
			}
		default:
			return nil, fmt.Errorf("directive file-upload: unknown driver %q", driver)
		}
		srv.FileUpload = &FileUpload{driver, source}
	}
	for _, origin := range raw.HTTPOrigin {
		if _, err := path.Match(origin, origin); err != nil {
			return nil, fmt.Errorf("directive http-origin: %v", err)
		}
	}
	srv.HTTPOrigins = raw.HTTPOrigin
	if raw.HTTPIngress != "" {
		srv.HTTPIngress = raw.HTTPIngress
	} else {
		srv.HTTPIngress = "https://" + srv.Hostname
	}
	for _, s := range raw.AcceptProxyIP {
		if s == "localhost" {
			srv.AcceptProxyIPs = append(srv.AcceptProxyIPs, loopbackIPs...)
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("directive accept-proxy-ip: failed to parse CIDR: %v", err)
		}
		srv.AcceptProxyIPs = append(srv.AcceptProxyIPs, n)
	}
	if raw.AcceptProxyUnix != "" {
		b, err := strconv.ParseBool(raw.AcceptProxyUnix)
		if err != nil {
			return nil, fmt.Errorf("directive accept-proxy-unix: %v", err)
		}
		srv.AcceptProxyUnix = b
	}
	srv.MaxUserNetworks = raw.MaxUserNetworks
	var hasIPv4, hasIPv6 bool
	for _, s := range raw.UpstreamUserIP {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("directive upstream-user-ip: failed to parse CIDR: %v", err)
		}
		if n.IP.To4() == nil {
			if hasIPv6 {
				return nil, fmt.Errorf("directive upstream-user-ip: found two IPv6 CIDRs")
			}
			hasIPv6 = true
		} else {
			if hasIPv4 {
				return nil, fmt.Errorf("directive upstream-user-ip: found two IPv4 CIDRs")
			}
			hasIPv4 = true
		}
		srv.UpstreamUserIPs = append(srv.UpstreamUserIPs, n)
	}
	if raw.DisableInactiveUser != "" {
		dur, err := parseDuration(raw.DisableInactiveUser)
		if err != nil {
			return nil, fmt.Errorf("directive disable-inactive-user: %v", err)
		} else if dur < 0 {
			return nil, fmt.Errorf("directive disable-inactive-user: duration must be positive")
		}
		srv.DisableInactiveUsersDelay = dur
	}
	if raw.EnableUserOnAuth != "" {
		b, err := strconv.ParseBool(raw.EnableUserOnAuth)
		if err != nil {
			return nil, fmt.Errorf("directive enable-user-on-auth: %v", err)
		}
		srv.EnableUsersOnAuth = b
	}

	return srv, nil
}

func parseDriverSource(name string, params []string) (driver, source string, err error) {
	switch len(params) {
	case 2:
		source = params[1]
		fallthrough
	case 1:
		driver = params[0]
	default:
		err = fmt.Errorf("directive %v requires exactly 1 or 2 parameters", name)
	}
	return driver, source, err
}
