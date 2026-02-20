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
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"codeberg.org/emersion/soju"
	"codeberg.org/emersion/soju/auth"
	"codeberg.org/emersion/soju/config"
	"codeberg.org/emersion/soju/database"
	"codeberg.org/emersion/soju/fileupload"
	"codeberg.org/emersion/soju/identd"
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

	var iconURL, iconPath string
	if strings.Contains(raw.Icon, "://") {
		if u, err := url.Parse(raw.Icon); err != nil {
			return nil, nil, fmt.Errorf("invalid icon URL: %v", err)
		} else if u.Scheme != "https" {
			return nil, nil, fmt.Errorf("unsupported icon URL scheme: %v", u.Scheme)
		}
		iconURL = raw.Icon
	} else if raw.Icon != "" {
		if _, err := os.Stat(raw.Icon); err != nil {
			return nil, nil, fmt.Errorf("failed to load icon: %v", err)
		}
		iconPath = raw.Icon
	}

	var authenticator auth.Authenticator
	for _, authCfg := range raw.Auth {
		a, err := auth.New(authCfg.Driver, authCfg.Source)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create authenticator %v: %v", authCfg.Driver, err)
		}
		if a.Plain != nil {
			if authenticator.Plain != nil {
				return nil, nil, fmt.Errorf("failed to load authenticators: multiple plain authentication methods specified")
			}
			authenticator.Plain = a.Plain
		}
		if a.OAuthBearer != nil {
			if authenticator.OAuthBearer != nil {
				return nil, nil, fmt.Errorf("failed to load authenticators: multiple OAuth authentication methods specified")
			}
			authenticator.OAuthBearer = a.OAuthBearer
		}
	}
	if authenticator.OAuthBearer != nil && authenticator.Plain == nil {
		authenticator.Plain = auth.OAuthPlainAuthenticator{
			OAuthBearer: authenticator.OAuthBearer,
		}
	}

	if raw.TLS != nil {
		cert, err := tls.LoadX509KeyPair(raw.TLS.CertPath, raw.TLS.KeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load TLS certificate and key: %v", err)
		}
		tlsCert.Store(&cert)
	}

	var fileUploader fileupload.Uploader
	if raw.FileUpload != nil {
		var err error
		fileUploader, err = fileupload.New(raw.FileUpload.Driver, raw.FileUpload.Source)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create file uploader: %v", err)
		}
	}

	cfg := &soju.Config{
		BasicServer:  raw.BasicServer,
		IconURL:      iconURL,
		IconPath:     iconPath,
		MOTD:         motd,
		Auth:         &authenticator,
		FileUploader: fileUploader,
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

	db, err := database.Open(cfg.DB.Driver, cfg.DB.Source)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	var tlsCfg *tls.Config
	if cfg.TLS != nil {
		tlsCfg = &tls.Config{
			ClientAuth: tls.RequestClientCert,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return tlsCert.Load().(*tls.Certificate), nil
			},
		}
	}

	srv := soju.NewServer(db)
	srv.SetConfig(serverCfg)
	srv.Logger = soju.NewLogger(log.Writer(), debug)

	fileUploadHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := srv.Config()
		h := fileupload.Handler{
			Uploader:    cfg.FileUploader,
			DB:          db,
			Auth:        cfg.Auth,
			HTTPOrigins: cfg.HTTPOrigins,
		}
		h.ServeHTTP(w, r)
	})

	iconHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := srv.Config()
		if cfg.IconPath == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, cfg.IconPath)
	})

	httpMux := http.NewServeMux()
	httpMux.Handle("/socket", srv)
	httpMux.Handle("/uploads", fileUploadHandler)
	httpMux.Handle("/uploads/", fileUploadHandler)
	httpMux.Handle("/icon", iconHandler)

	var httpServers []*http.Server
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
			addr := withDefaultPort(u.Host, "6697")
			listenAndServeIRC(srv, listen, "tcp", addr, tlsCfg)
		case "irc":
			if u.Hostname() != "localhost" {
				log.Fatalf("Plain-text IRC listening host must be localhost unless marked as insecure")
			}
			fallthrough
		case "irc+insecure":
			addr := withDefaultPort(u.Host, "6667")
			listenAndServeIRC(srv, listen, "tcp", addr, nil)
		case "unix":
			path := u.Host + u.Path
			listenAndServeIRC(srv, listen, "unix", path, nil)
			if err := os.Chmod(path, 0775); err != nil {
				log.Printf("failed to chmod Unix IRC socket: %v", err)
			}
		case "unix+admin":
			path := u.Host + u.Path
			if path == "" {
				path = config.DefaultUnixAdminPath
			}
			listenAndServeAdmin(srv, listen, path)
			// TODO: this is racy
			if err := os.Chmod(path, 0600); err != nil {
				log.Fatalf("failed to chmod Unix admin socket: %v", err)
			}
		case "wss":
			if tlsCfg == nil {
				log.Fatalf("failed to listen on %q: missing TLS configuration", listen)
			}
			addr := withDefaultPort(u.Host, "https")
			httpSrv := listenAndServeHTTP(srv, listen, "tcp", addr, tlsCfg)
			httpServers = append(httpServers, httpSrv)
		case "ws":
			if u.Hostname() != "localhost" {
				log.Fatalf("Plain-text WebSocket listening host must be localhost unless marked as insecure")
			}
			fallthrough
		case "ws+insecure":
			addr := withDefaultPort(u.Host, "http")
			httpSrv := listenAndServeHTTP(srv, listen, "tcp", addr, nil)
			httpServers = append(httpServers, httpSrv)
		case "ws+unix":
			path := u.Host + u.Path
			httpSrv := listenAndServeHTTP(srv, listen, "unix", path, nil)
			if err := os.Chmod(path, 0775); err != nil {
				log.Printf("failed to chmod Unix WS socket: %v", err)
			}
			httpServers = append(httpServers, httpSrv)
		case "ident":
			if srv.Identd == nil {
				srv.Identd = identd.New()
			}
			addr := withDefaultPort(u.Host, "113")
			listenAndServeIdent(srv, "tcp", listen, addr)
		case "http+prometheus":
			// Only allow localhost as listening host for security reasons.
			hostname, _, err := net.SplitHostPort(u.Host)
			if err != nil {
				log.Fatalf("invalid host in URI %q: %v", listen, err)
			} else if hostname != "localhost" {
				log.Fatalf("Prometheus listening host must be localhost unless marked as insecure")
			}

			fallthrough
		case "http+insecure+prometheus":
			if srv.MetricsRegistry == nil {
				srv.MetricsRegistry = prometheus.DefaultRegisterer
			}

			metricsHandler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
				MaxRequestsInFlight: 10,
				Timeout:             10 * time.Second,
				EnableOpenMetrics:   true,
			})
			metricsHandler = promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, metricsHandler)

			httpSrv := listenAndServeHTTP(metricsHandler, listen, "tcp", u.Host, nil)
			httpServers = append(httpServers, httpSrv)
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
			httpSrv := listenAndServeHTTP(http.DefaultServeMux, listen, "tcp", u.Host, nil)
			httpServers = append(httpServers, httpSrv)
		case "https":
			if tlsCfg == nil {
				log.Fatalf("failed to listen on %q: missing TLS configuration", listen)
			}
			addr := withDefaultPort(u.Host, "https")
			httpSrv := listenAndServeHTTP(httpMux, listen, "tcp", addr, tlsCfg)
			httpServers = append(httpServers, httpSrv)
		case "http":
			if u.Hostname() != "localhost" {
				log.Fatalf("Plain-text HTTP listening host must be localhost unless marked as insecure")
			}
			fallthrough
		case "http+insecure":
			addr := withDefaultPort(u.Host, "http")
			httpSrv := listenAndServeHTTP(httpMux, listen, "tcp", addr, nil)
			httpServers = append(httpServers, httpSrv)
		case "http+unix":
			path := u.Host + u.Path
			httpSrv := listenAndServeHTTP(httpMux, listen, "unix", path, nil)
			if err := os.Chmod(path, 0775); err != nil {
				log.Printf("failed to chmod Unix HTTP socket: %v", err)
			}
			httpServers = append(httpServers, httpSrv)
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
			for _, httpSrv := range httpServers {
				if err := httpSrv.Close(); err != nil {
					log.Printf("failed to close HTTP server: %v", err)
				}
			}
			srv.Shutdown()
			return
		}
	}
}

func listenAndServeIRC(srv *soju.Server, label, network, addr string, tlsConfig *tls.Config) {
	lc := net.ListenConfig{
		KeepAlive: downstreamKeepAlive,
	}
	ln, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		log.Fatalf("failed to start TLS listener on %q: %v", label, err)
	}

	if tlsConfig != nil {
		ircsTLSConfig := tlsConfig.Clone()
		ircsTLSConfig.NextProtos = []string{"irc"}
		ln = tls.NewListener(ln, ircsTLSConfig)
	}
	ln = proxyProtoListener(ln, srv)

	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("serving %q: %v", label, err)
		}
	}()
}

func listenAndServeAdmin(srv *soju.Server, label, path string) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("failed to start listener on %q: %v", label, err)
	}

	ln = proxyProtoListener(ln, srv)

	go func() {
		if err := srv.ServeAdmin(ln); err != nil {
			log.Printf("serving %q: %v", label, err)
		}
	}()
}

func listenAndServeHTTP(h http.Handler, label, network, addr string, tlsConfig *tls.Config) *http.Server {
	ln, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalf("failed to start listener on %q: %v", label, err)
	}

	if tlsConfig != nil {
		httpsTLSConfig := tlsConfig.Clone()
		httpsTLSConfig.NextProtos = []string{"h2", "http/1.1"}
		ln = tls.NewListener(ln, httpsTLSConfig)
	}

	h = h2c.NewHandler(h, new(http2.Server))

	httpSrv := &http.Server{Handler: h}

	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("serving %q: %v", label, err)
		}
	}()

	return httpSrv
}

func listenAndServeIdent(srv *soju.Server, label, network, addr string) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalf("failed to start listener on %q: %v", label, err)
	}

	ln = proxyProtoListener(ln, srv)
	ln = soju.NewRetryListener(ln)

	go func() {
		if err := srv.Identd.Serve(ln); err != nil {
			log.Printf("serving %q: %v", label, err)
		}
	}()
}

func proxyProtoListener(ln net.Listener, srv *soju.Server) net.Listener {
	return &proxyproto.Listener{
		Listener: ln,
		Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
			switch upstream := upstream.(type) {
			case *net.TCPAddr:
				if srv.Config().AcceptProxyIPs.Contains(upstream.IP) {
					return proxyproto.USE, nil
				}
			case *net.UnixAddr:
				if srv.Config().AcceptProxyUnix {
					return proxyproto.USE, nil
				}
			}
			return proxyproto.IGNORE, nil
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func withDefaultPort(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr += ":" + port
	}
	return addr
}
