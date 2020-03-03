package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"

	"git.sr.ht/~emersion/jounce"
	"git.sr.ht/~emersion/jounce/config"
)

func main() {
	var addr, configPath string
	var debug bool
	flag.StringVar(&addr, "listen", "", "listening address")
	flag.StringVar(&configPath, "config", "", "path to configuration file")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.Parse()

	var cfg *config.Server
	if configPath != "" {
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			log.Fatalf("failed to load config file: %v", err)
		}
	} else {
		cfg = config.Defaults()
	}

	if addr != "" {
		cfg.Addr = addr
	}

	var ln net.Listener
	if cfg.TLS != nil {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertPath, cfg.TLS.KeyPath)
		if err != nil {
			log.Fatalf("failed to load TLS certificate and key: %v", err)
		}

		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		ln, err = tls.Listen("tcp", cfg.Addr, tlsCfg)
		if err != nil {
			log.Fatalf("failed to start TLS listener: %v", err)
		}
	} else {
		var err error
		ln, err = net.Listen("tcp", cfg.Addr)
		if err != nil {
			log.Fatalf("failed to start listener: %v", err)
		}
	}

	srv := jounce.NewServer()
	// TODO: load from config/DB
	srv.Hostname = cfg.Hostname
	srv.Debug = debug
	srv.Upstreams = []jounce.Upstream{{
		Addr:     "chat.freenode.net:6697",
		Nick:     "jounce",
		Username: "jounce",
		Realname: "jounce",
		Channels: []string{"#jounce"},
	}}

	log.Printf("server listening on %q", cfg.Addr)
	go srv.Run()
	log.Fatal(srv.Serve(ln))
}
