package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"gopkg.in/irc.v4"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"

	"codeberg.org/emersion/soju/config"
)

const usage = `usage: sojuctl [-config path] <command>
`

func init() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage)
	}
}

func run(ctx context.Context, cfg *config.Server, words []string) error {
	var path string
	for _, listen := range cfg.Listen {
		u, err := url.Parse(listen)
		if err != nil {
			continue
		}
		if u.Scheme != "unix+admin" {
			continue
		}
		path = u.Host + u.Path
		if path == "" {
			path = config.DefaultUnixAdminPath
		}
		break
	}
	if path == "" {
		return fmt.Errorf("no listen unix+admin directive found in config")
	}
	var d net.Dialer
	uc, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("dial %v: %v", path, err)
	}
	defer uc.Close()
	c := irc.NewConn(uc)
	if err := c.WriteMessage(&irc.Message{
		Command: "BOUNCERSERV",
		Params:  []string{quoteWords(words)},
	}); err != nil {
		return fmt.Errorf("write: %v", err)
	}
	for {
		m, err := c.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %v", err)
		}
		switch m.Command {
		case "PRIVMSG":
			fmt.Println(m.Trailing())
		case "BOUNCERSERV":
			if m.Param(0) == "OK" {
				return nil
			}
			fallthrough
		default:
			return errors.New(m.Trailing())
		}
	}
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", config.DefaultPath, "path to configuration file")
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

	ctx := context.Background()
	if err := run(ctx, cfg, flag.Args()); err != nil {
		log.Fatalln(err)
	}
}

func quoteWords(words []string) string {
	var s strings.Builder
	for _, word := range words {
		if s.Len() > 0 {
			s.WriteRune(' ')
		}
		s.WriteString(strconv.Quote(word))
	}
	return s.String()
}
