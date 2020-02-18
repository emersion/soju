package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

type TLS struct {
	CertPath, KeyPath string
}

type Server struct {
	Addr     string
	Hostname string
	TLS      *TLS
}

func Defaults() *Server {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	return &Server{
		Addr:     ":6667",
		Hostname: hostname,
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
	p := parser{br: bufio.NewReader(r)}
	directives, err := p.file()
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	srv := Defaults()
	for _, d := range directives {
		switch d.Name {
		case "listen":
			if err := d.parseParams(&srv.Addr); err != nil {
				return nil, err
			}
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

type parser struct {
	br *bufio.Reader
}

func (p *parser) skipSpace() error {
	for {
		r, _, err := p.br.ReadRune()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if !unicode.IsSpace(r) || r == '\n' {
			p.br.UnreadRune()
			break
		}
	}
	return nil
}

func (p *parser) atom() (string, error) {
	var sb strings.Builder
	for {
		r, _, err := p.br.ReadRune()
		if err == io.EOF && sb.Len() > 0 {
			break
		} else if err != nil {
			return "", err
		}
		if unicode.IsSpace(r) {
			p.br.UnreadRune()
			if err := p.skipSpace(); err != nil {
				return "", err
			}
			break
		}
		sb.WriteRune(r)
	}
	return sb.String(), nil
}

func (p *parser) directive() (*directive, error) {
	name, err := p.atom()
	if err == io.EOF {
		return nil, io.EOF
	} else if err != nil {
		return nil, fmt.Errorf("failed to read directive name: %v", err)
	}

	var params []string
	for {
		r, _, err := p.br.ReadRune()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if r == '\n' {
			break
		}
		p.br.UnreadRune()

		param, err := p.atom()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to read directive param: %v", err)
		}
		params = append(params, param)
	}

	return &directive{name, params}, nil
}

func (p *parser) file() ([]directive, error) {
	var l []directive
	for {
		d, err := p.directive()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		l = append(l, *d)
	}
	return l, nil
}
