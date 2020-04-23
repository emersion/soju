package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"git.sr.ht/~emersion/soju"
	"git.sr.ht/~emersion/soju/config"
)

func main() {
	var listen, configPath string
	var debug bool
	flag.StringVar(&listen, "listen", "", "listening address")
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

	if listen != "" {
		cfg.Listen = append(cfg.Listen, listen)
	}
	if len(cfg.Listen) == 0 {
		cfg.Listen = []string{":6697"}
	}

	db, err := soju.OpenSQLDB(cfg.SQLDriver, cfg.SQLSource)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	var tlsCfg *tls.Config
	if cfg.TLS != nil {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertPath, cfg.TLS.KeyPath)
		if err != nil {
			log.Fatalf("failed to load TLS certificate and key: %v", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	srv := soju.NewServer(db)
	// TODO: load from config/DB
	srv.Hostname = cfg.Hostname
	srv.LogPath = cfg.LogPath
	srv.HTTPOrigins = cfg.HTTPOrigins
	srv.Debug = debug

	for _, listen := range cfg.Listen {
		listenURI := listen
		if !strings.Contains(listenURI, ":/") {
			// This is a raw domain name, make it an URL with an empty scheme
			listenURI = "//" + listenURI
		}
		u, err := url.Parse(listenURI)
		if err != nil {
			log.Fatalf("failed to parse listen URI %q: %v", listen, err)
		}

		switch u.Scheme {
		case "ircs", "":
			if tlsCfg == nil {
				log.Fatalf("failed to listen on %q: missing TLS configuration", listen)
			}
			host := u.Host
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = host + ":6697"
			}
			ln, err := tls.Listen("tcp", host, tlsCfg)
			if err != nil {
				log.Fatalf("failed to start TLS listener on %q: %v", listen, err)
			}
			go func() {
				log.Fatal(srv.Serve(ln))
			}()
		case "irc+insecure":
			host := u.Host
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = host + ":6667"
			}
			ln, err := net.Listen("tcp", host)
			if err != nil {
				log.Fatalf("failed to start listener on %q: %v", listen, err)
			}
			go func() {
				log.Fatal(srv.Serve(ln))
			}()
		case "wss":
			addr := u.Host
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr = addr + ":https"
			}
			httpSrv := http.Server{
				Addr:      addr,
				TLSConfig: tlsCfg,
				Handler:   srv,
			}
			go func() {
				log.Fatal(httpSrv.ListenAndServeTLS("", ""))
			}()
		case "ws+insecure":
			addr := u.Host
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr = addr + ":http"
			}
			httpSrv := http.Server{
				Addr:    addr,
				Handler: srv,
			}
			go func() {
				log.Fatal(httpSrv.ListenAndServe())
			}()
		default:
			log.Fatalf("failed to listen on %q: unsupported scheme", listen)
		}

		log.Printf("server listening on %q", listen)
	}
	log.Fatal(srv.Run())
}
