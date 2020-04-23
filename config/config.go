package config

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/google/shlex"
)

type TLS struct {
	CertPath, KeyPath string
}

type Server struct {
	Listen      []string
	Hostname    string
	TLS         *TLS
	SQLDriver   string
	SQLSource   string
	LogPath     string
	HTTPOrigins []string
}

func Defaults() *Server {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	return &Server{
		Hostname:  hostname,
		SQLDriver: "sqlite3",
		SQLSource: "soju.db",
	}
}

func Load(path string) (*Server, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return Parse(f)
}

func Parse(r io.Reader) (*Server, error) {
	scanner := bufio.NewScanner(r)

	var directives []directive
	for scanner.Scan() {
		words, err := shlex.Split(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("failed to parse config file: %v", err)
		} else if len(words) == 0 {
			continue
		}

		name, params := words[0], words[1:]
		directives = append(directives, directive{name, params})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	srv := Defaults()
	for _, d := range directives {
		switch d.Name {
		case "listen":
			var uri string
			if err := d.parseParams(&uri); err != nil {
				return nil, err
			}
			srv.Listen = append(srv.Listen, uri)
		case "hostname":
			if err := d.parseParams(&srv.Hostname); err != nil {
				return nil, err
			}
		case "tls":
			tls := &TLS{}
			if err := d.parseParams(&tls.CertPath, &tls.KeyPath); err != nil {
				return nil, err
			}
			srv.TLS = tls
		case "sql":
			if err := d.parseParams(&srv.SQLDriver, &srv.SQLSource); err != nil {
				return nil, err
			}
		case "log":
			if err := d.parseParams(&srv.LogPath); err != nil {
				return nil, err
			}
		case "http-origin":
			srv.HTTPOrigins = append(srv.HTTPOrigins, d.Params...)
		default:
			return nil, fmt.Errorf("unknown directive %q", d.Name)
		}
	}

	return srv, nil
}

type directive struct {
	Name   string
	Params []string
}

func (d *directive) parseParams(out ...*string) error {
	if len(d.Params) != len(out) {
		return fmt.Errorf("directive %q has wrong number of parameters: expected %v, got %v", d.Name, len(out), len(d.Params))
	}
	for i := range out {
		*out[i] = d.Params[i]
	}
	return nil
}
