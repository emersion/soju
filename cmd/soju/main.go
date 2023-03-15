package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"git.sr.ht/~emersion/soju"
	"git.sr.ht/~emersion/soju/auth"
	"git.sr.ht/~emersion/soju/config"
	"git.sr.ht/~emersion/soju/database"
	"git.sr.ht/~emersion/soju/identd"
)

// TCP keep-alive interval for downstream TCP connections
const downstreamKeepAlive = 1 * time.Hour

type stringSliceFlag []string

func (v *stringSliceFlag) String() string {
	return fmt.Sprint([]string(*v))
}

func (v *stringSliceFlag) Set(s string) error {
	*v = append(*v, s)
	return nil
}

var (
	configPath string
	debug      bool

	tlsCert atomic.Value // *tls.Certificate
)

func loadConfig() (*config.Server, *soju.Config, error) {
	var raw *config.Server
	if configPath != "" {
		var err error
		raw, err = config.Load(configPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load config file: %v", err)
		}
	} else {
		raw = config.Defaults()
	}

	// A hostname without a dot can confuse clients
	if !strings.Contains(raw.Hostname, ".") {
		log.Printf("warning: hostname %q is not a fully qualified domain name", raw.Hostname)
	}

	var motd string
	if raw.MOTDPath != "" {
		b, err := ioutil.ReadFile(raw.MOTDPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load MOTD: %v", err)
		}
		motd = strings.TrimSuffix(string(b), "\n")
	}

	auth, err := auth.New(raw.Auth.Driver, raw.Auth.Source)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create authenticator: %v", err)
	}

	if raw.TLS != nil {
		cert, err := tls.LoadX509KeyPair(raw.TLS.CertPath, raw.TLS.KeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load TLS certificate and key: %v", err)
		}
		tlsCert.Store(&cert)
	}

	cfg := &soju.Config{
		Hostname:                  raw.Hostname,
		Title:                     raw.Title,
		LogDriver:                 raw.MsgStore.Driver,
		LogPath:                   raw.MsgStore.Source,
		HTTPOrigins:               raw.HTTPOrigins,
		AcceptProxyIPs:            raw.AcceptProxyIPs,
		MaxUserNetworks:           raw.MaxUserNetworks,
		UpstreamUserIPs:           raw.UpstreamUserIPs,
		DisableInactiveUsersDelay: raw.DisableInactiveUsersDelay,
		EnableUsersOnAuth:         raw.EnableUsersOnAuth,
		MOTD:                      motd,
		Auth:                      auth,
	}
	return raw, cfg, nil
}

func main() {
	var listen []string
	flag.Var((*stringSliceFlag)(&listen), "listen", "listening address")
	flag.StringVar(&configPath, "config", config.DefaultPath, "path to configuration file")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.Parse()

	cfg, serverCfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	cfg.Listen = append(cfg.Listen, listen...)
	if len(cfg.Listen) == 0 {
		cfg.Listen = []string{":6697"}
	}

	if err := bumpOpenedFileLimit(); err != nil {
		log.Printf("failed to bump max number of opened files: %v", err)
	}

	db, err := database.Open(cfg.DB.Driver, cfg.DB.Source)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	var tlsCfg *tls.Config
	if cfg.TLS != nil {
		tlsCfg = &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return tlsCert.Load().(*tls.Certificate), nil
			},
		}
	}

	srv := soju.NewServer(db)
	srv.SetConfig(serverCfg)
	srv.Logger = soju.NewLogger(log.Writer(), debug)

	for _, listen := range cfg.Listen {
		listen := listen // copy
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
			ircsTLSCfg := tlsCfg.Clone()
			ircsTLSCfg.NextProtos = []string{"irc"}
			lc := net.ListenConfig{
				KeepAlive: downstreamKeepAlive,
			}
			l, err := lc.Listen(context.Background(), "tcp", host)
			if err != nil {
				log.Fatalf("failed to start TLS listener on %q: %v", listen, err)
			}
			ln := tls.NewListener(l, ircsTLSCfg)
			ln = proxyProtoListener(ln, srv)
			go func() {
				if err := srv.Serve(ln, srv.Handle); err != nil {
					log.Printf("serving %q: %v", listen, err)
				}
			}()
		case "irc+insecure":
			host := u.Host
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = host + ":6667"
			}
			lc := net.ListenConfig{
				KeepAlive: downstreamKeepAlive,
			}
			ln, err := lc.Listen(context.Background(), "tcp", host)
			if err != nil {
				log.Fatalf("failed to start listener on %q: %v", listen, err)
			}
			ln = proxyProtoListener(ln, srv)
			go func() {
				if err := srv.Serve(ln, srv.Handle); err != nil {
					log.Printf("serving %q: %v", listen, err)
				}
			}()
		case "unix":
			ln, err := net.Listen("unix", u.Path)
			if err != nil {
				log.Fatalf("failed to start listener on %q: %v", listen, err)
			}
			ln = proxyProtoListener(ln, srv)
			go func() {
				if err := srv.Serve(ln, srv.Handle); err != nil {
					log.Printf("serving %q: %v", listen, err)
				}
			}()
		case "unix+admin":
			path := u.Path
			if path == "" {
				path = config.DefaultUnixAdminPath
			}
			ln, err := net.Listen("unix", path)
			if err != nil {
				log.Fatalf("failed to start listener on %q: %v", listen, err)
			}
			ln = proxyProtoListener(ln, srv)
			// TODO: this is racy
			if err := os.Chmod(path, 0600); err != nil {
				log.Fatalf("failed to chmod Unix admin socket: %v", err)
			}
			go func() {
				if err := srv.Serve(ln, srv.HandleAdmin); err != nil {
					log.Printf("serving %q: %v", listen, err)
				}
			}()
		case "wss":
			if tlsCfg == nil {
				log.Fatalf("failed to listen on %q: missing TLS configuration", listen)
			}
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
				if err := httpSrv.ListenAndServeTLS("", ""); err != nil {
					log.Fatalf("serving %q: %v", listen, err)
				}
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
				if err := httpSrv.ListenAndServe(); err != nil {
					log.Fatalf("serving %q: %v", listen, err)
				}
			}()
		case "ident":
			if srv.Identd == nil {
				srv.Identd = identd.New()
			}

			host := u.Host
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = host + ":113"
			}
			ln, err := net.Listen("tcp", host)
			if err != nil {
				log.Fatalf("failed to start listener on %q: %v", listen, err)
			}
			ln = proxyProtoListener(ln, srv)
			ln = soju.NewRetryListener(ln)
			go func() {
				if err := srv.Identd.Serve(ln); err != nil {
					log.Printf("serving %q: %v", listen, err)
				}
			}()
		case "http+prometheus":
			if srv.MetricsRegistry == nil {
				srv.MetricsRegistry = prometheus.DefaultRegisterer
			}

			// Only allow localhost as listening host for security reasons.
			// Users can always explicitly setup reverse proxies if desirable.
			hostname, _, err := net.SplitHostPort(u.Host)
			if err != nil {
				log.Fatalf("invalid host in URI %q: %v", listen, err)
			} else if hostname != "localhost" {
				log.Fatalf("Prometheus listening host must be localhost")
			}

			metricsHandler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
				MaxRequestsInFlight: 10,
				Timeout:             10 * time.Second,
				EnableOpenMetrics:   true,
			})
			metricsHandler = promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, metricsHandler)

			httpSrv := http.Server{
				Addr:    u.Host,
				Handler: metricsHandler,
			}
			go func() {
				if err := httpSrv.ListenAndServe(); err != nil {
					log.Fatalf("serving %q: %v", listen, err)
				}
			}()
		case "http+pprof":
			// Only allow localhost as listening host for security reasons.
			// Users can always explicitly setup reverse proxies if desirable.
			hostname, _, err := net.SplitHostPort(u.Host)
			if err != nil {
				log.Fatalf("invalid host in URI %q: %v", listen, err)
			} else if hostname != "localhost" {
				log.Fatalf("pprof listening host must be localhost")
			}

			// net/http/pprof registers its handlers in http.DefaultServeMux
			httpSrv := http.Server{
				Addr:    u.Host,
				Handler: http.DefaultServeMux,
			}
			go func() {
				if err := httpSrv.ListenAndServe(); err != nil {
					log.Fatalf("serving %q: %v", listen, err)
				}
			}()
		default:
			log.Fatalf("failed to listen on %q: unsupported scheme", listen)
		}

		log.Printf("server listening on %q", listen)
	}

	if db, ok := db.(database.MetricsCollectorDatabase); ok && srv.MetricsRegistry != nil {
		if err := db.RegisterMetrics(srv.MetricsRegistry); err != nil {
			log.Fatalf("failed to register database metrics: %v", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			log.Print("reloading configuration")
			_, serverCfg, err := loadConfig()
			if err != nil {
				log.Printf("failed to reloading configuration: %v", err)
			} else {
				srv.SetConfig(serverCfg)
			}
		case syscall.SIGINT, syscall.SIGTERM:
			srv.Shutdown()
			return
		}
	}
}

func proxyProtoListener(ln net.Listener, srv *soju.Server) net.Listener {
	return &proxyproto.Listener{
		Listener: ln,
		Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
			tcpAddr, ok := upstream.(*net.TCPAddr)
			if !ok {
				return proxyproto.IGNORE, nil
			}
			if srv.Config().AcceptProxyIPs.Contains(tcpAddr.IP) {
				return proxyproto.USE, nil
			}
			return proxyproto.IGNORE, nil
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
}
