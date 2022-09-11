package config

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"git.sr.ht/~emersion/go-scfg"
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

type TLS struct {
	CertPath, KeyPath string
}

type DB struct {
	Driver, Source string
}

type MsgStore struct {
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

	HTTPOrigins    []string
	AcceptProxyIPs IPSet

	MaxUserNetworks int
	MultiUpstream   bool
	UpstreamUserIPs []*net.IPNet
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
		MaxUserNetworks: -1,
		MultiUpstream:   true,
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
			case "memory":
				srv.MsgStore.Source = ""
			case "fs":
				if err := d.ParseParams(nil, &srv.MsgStore.Source); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("directive %q: unknown driver %q", d.Name, srv.MsgStore.Driver)
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
		case "multi-upstream-mode":
			var str string
			if err := d.ParseParams(&str); err != nil {
				return nil, err
			}
			v, err := strconv.ParseBool(str)
			if err != nil {
				return nil, fmt.Errorf("directive %q: %v", d.Name, err)
			}
			srv.MultiUpstream = v
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
		default:
			return nil, fmt.Errorf("unknown directive %q", d.Name)
		}
	}

	return srv, nil
}
