package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"unicode"

	"git.sr.ht/~emersion/soju/config"
	"git.sr.ht/~emersion/soju/database"
)

const usage = `usage: znc-import [options...] <znc config path>

Imports configuration from a ZNC file. Users and networks are merged if they
already exist in the soju database. ZNC settings overwrite existing soju
settings.

Options:

  -help             Show this help message
  -config <path>    Path to soju config file
  -user <username>  Limit import to username (may be specified multiple times)
  -network <name>   Limit import to network (may be specified multiple times)
`

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage)
	}
}

func main() {
	var configPath string
	users := make(map[string]bool)
	networks := make(map[string]bool)
	flag.StringVar(&configPath, "config", "", "path to configuration file")
	flag.Var((*stringSetFlag)(&users), "user", "")
	flag.Var((*stringSetFlag)(&networks), "network", "")
	flag.Parse()

	zncPath := flag.Arg(0)
	if zncPath == "" {
		flag.Usage()
		os.Exit(1)
	}

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

	db, err := database.Open(cfg.DB.Driver, cfg.DB.Source)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	f, err := os.Open(zncPath)
	if err != nil {
		log.Fatalf("failed to open ZNC configuration file: %v", err)
	}
	defer f.Close()

	zp := zncParser{bufio.NewReader(f), 1}
	root, err := zp.sectionBody("", "")
	if err != nil {
		log.Fatalf("failed to parse %q: line %v: %v", zncPath, zp.line, err)
	}

	l, err := db.ListUsers(ctx)
	if err != nil {
		log.Fatalf("failed to list users in DB: %v", err)
	}
	existingUsers := make(map[string]*database.User, len(l))
	for i, u := range l {
		existingUsers[u.Username] = &l[i]
	}

	usersCreated := 0
	usersImported := 0
	networksImported := 0
	channelsImported := 0
	root.ForEach("User", func(section *zncSection) {
		username := section.Name
		if len(users) > 0 && !users[username] {
			return
		}
		usersImported++

		u, ok := existingUsers[username]
		if ok {
			log.Printf("user %q: updating existing user", username)
		} else {
			// "!!" is an invalid crypt format, thus disables password auth
			u = &database.User{Username: username, Password: "!!"}
			usersCreated++
			log.Printf("user %q: creating new user", username)
		}

		u.Admin = section.Values.Get("Admin") == "true"

		if err := db.StoreUser(ctx, u); err != nil {
			log.Fatalf("failed to store user %q: %v", username, err)
		}
		userID := u.ID

		l, err := db.ListNetworks(ctx, userID)
		if err != nil {
			log.Fatalf("failed to list networks for user %q: %v", username, err)
		}
		existingNetworks := make(map[string]*database.Network, len(l))
		for i, n := range l {
			existingNetworks[n.GetName()] = &l[i]
		}

		nick := section.Values.Get("Nick")
		realname := section.Values.Get("RealName")
		ident := section.Values.Get("Ident")

		section.ForEach("Network", func(section *zncSection) {
			netName := section.Name
			if len(networks) > 0 && !networks[netName] {
				return
			}
			networksImported++

			logPrefix := fmt.Sprintf("user %q: network %q: ", username, netName)
			logger := log.New(os.Stderr, logPrefix, log.LstdFlags|log.Lmsgprefix)

			netNick := section.Values.Get("Nick")
			if netNick == "" {
				netNick = nick
			}
			netRealname := section.Values.Get("RealName")
			if netRealname == "" {
				netRealname = realname
			}
			netIdent := section.Values.Get("Ident")
			if netIdent == "" {
				netIdent = ident
			}

			for _, name := range section.Values["LoadModule"] {
				switch name {
				case "sasl":
					logger.Printf("warning: SASL credentials not imported")
				case "nickserv":
					logger.Printf("warning: NickServ credentials not imported")
				case "perform":
					logger.Printf("warning: \"perform\" plugin commands not imported")
				}
			}

			u, pass, err := importNetworkServer(section.Values.Get("Server"))
			if err != nil {
				logger.Fatalf("failed to import server %q: %v", section.Values.Get("Server"), err)
			}

			n, ok := existingNetworks[netName]
			if ok {
				logger.Printf("updating existing network")
			} else {
				n = &database.Network{Name: netName}
				logger.Printf("creating new network")
			}

			n.Addr = u.String()
			n.Nick = netNick
			n.Username = netIdent
			n.Realname = netRealname
			n.Pass = pass
			n.Enabled = section.Values.Get("IRCConnectEnabled") != "false"

			if err := db.StoreNetwork(ctx, userID, n); err != nil {
				logger.Fatalf("failed to store network: %v", err)
			}

			l, err := db.ListChannels(ctx, n.ID)
			if err != nil {
				logger.Fatalf("failed to list channels: %v", err)
			}
			existingChannels := make(map[string]*database.Channel, len(l))
			for i, ch := range l {
				existingChannels[ch.Name] = &l[i]
			}

			section.ForEach("Chan", func(section *zncSection) {
				chName := section.Name

				if section.Values.Get("Disabled") == "true" {
					logger.Printf("skipping import of disabled channel %q", chName)
					return
				}

				channelsImported++

				ch, ok := existingChannels[chName]
				if ok {
					logger.Printf("channel %q: updating existing channel", chName)
				} else {
					ch = &database.Channel{Name: chName}
					logger.Printf("channel %q: creating new channel", chName)
				}

				ch.Key = section.Values.Get("Key")
				ch.Detached = section.Values.Get("Detached") == "true"

				if err := db.StoreChannel(ctx, n.ID, ch); err != nil {
					logger.Printf("channel %q: failed to store channel: %v", chName, err)
				}
			})
		})
	})

	if err := db.Close(); err != nil {
		log.Printf("failed to close database: %v", err)
	}

	if usersCreated > 0 {
		log.Printf("warning: user passwords haven't been imported, please set them with `sojuctl change-password <username>`")
	}

	log.Printf("imported %v users, %v networks and %v channels", usersImported, networksImported, channelsImported)
}

func importNetworkServer(s string) (u *url.URL, pass string, err error) {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return nil, "", fmt.Errorf("expected space-separated host and port")
	}

	scheme := "irc+insecure"
	host := parts[0]
	port := parts[1]
	if strings.HasPrefix(port, "+") {
		port = port[1:]
		scheme = "ircs"
	}

	if len(parts) > 2 {
		pass = parts[2]
	}

	u = &url.URL{
		Scheme: scheme,
		Host:   host + ":" + port,
	}
	return u, pass, nil
}

type zncSection struct {
	Type     string
	Name     string
	Values   zncValues
	Children []zncSection
}

func (s *zncSection) ForEach(typ string, f func(*zncSection)) {
	for _, section := range s.Children {
		if section.Type == typ {
			f(&section)
		}
	}
}

type zncValues map[string][]string

func (zv zncValues) Get(k string) string {
	if len(zv[k]) == 0 {
		return ""
	}
	return zv[k][0]
}

type zncParser struct {
	br   *bufio.Reader
	line int
}

func (zp *zncParser) readByte() (byte, error) {
	b, err := zp.br.ReadByte()
	if b == '\n' {
		zp.line++
	}
	return b, err
}

func (zp *zncParser) readRune() (rune, int, error) {
	r, n, err := zp.br.ReadRune()
	if r == '\n' {
		zp.line++
	}
	return r, n, err
}

func (zp *zncParser) sectionBody(typ, name string) (*zncSection, error) {
	section := &zncSection{Type: typ, Name: name, Values: make(zncValues)}

Loop:
	for {
		if err := zp.skipSpace(); err != nil {
			return nil, err
		}

		b, err := zp.br.Peek(2)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		switch b[0] {
		case '<':
			if b[1] == '/' {
				break Loop
			} else {
				childType, childName, err := zp.sectionHeader()
				if err != nil {
					return nil, err
				}
				child, err := zp.sectionBody(childType, childName)
				if err != nil {
					return nil, err
				}
				if footerType, err := zp.sectionFooter(); err != nil {
					return nil, err
				} else if footerType != childType {
					return nil, fmt.Errorf("invalid section footer: expected type %q, got %q", childType, footerType)
				}
				section.Children = append(section.Children, *child)
			}
		case '/':
			if b[1] == '/' {
				if err := zp.skipComment(); err != nil {
					return nil, err
				}
				break
			}
			fallthrough
		default:
			k, v, err := zp.keyValuePair()
			if err != nil {
				return nil, err
			}
			section.Values[k] = append(section.Values[k], v)
		}
	}

	return section, nil
}

func (zp *zncParser) skipSpace() error {
	for {
		r, _, err := zp.readRune()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		if !unicode.IsSpace(r) {
			zp.br.UnreadRune()
			return nil
		}
	}
}

func (zp *zncParser) skipComment() error {
	if err := zp.expectRune('/'); err != nil {
		return err
	}
	if err := zp.expectRune('/'); err != nil {
		return err
	}

	for {
		b, err := zp.readByte()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		if b == '\n' {
			return nil
		}
	}
}

func (zp *zncParser) sectionHeader() (string, string, error) {
	if err := zp.expectRune('<'); err != nil {
		return "", "", err
	}
	typ, err := zp.readWord(' ')
	if err != nil {
		return "", "", err
	}
	name, err := zp.readWord('>')
	return typ, name, err
}

func (zp *zncParser) sectionFooter() (string, error) {
	if err := zp.expectRune('<'); err != nil {
		return "", err
	}
	if err := zp.expectRune('/'); err != nil {
		return "", err
	}
	return zp.readWord('>')
}

func (zp *zncParser) keyValuePair() (string, string, error) {
	k, err := zp.readWord('=')
	if err != nil {
		return "", "", err
	}
	v, err := zp.readWord('\n')
	return strings.TrimSpace(k), strings.TrimSpace(v), err
}

func (zp *zncParser) expectRune(expected rune) error {
	r, _, err := zp.readRune()
	if err != nil {
		return err
	} else if r != expected {
		return fmt.Errorf("expected %q, got %q", expected, r)
	}
	return nil
}

func (zp *zncParser) readWord(delim byte) (string, error) {
	var sb strings.Builder
	for {
		b, err := zp.readByte()
		if err != nil {
			return "", err
		}

		if b == delim {
			return sb.String(), nil
		}
		if b == '\n' {
			return "", fmt.Errorf("expected %q before newline", delim)
		}

		sb.WriteByte(b)
	}
}

type stringSetFlag map[string]bool

func (v *stringSetFlag) String() string {
	return fmt.Sprint(map[string]bool(*v))
}

func (v *stringSetFlag) Set(s string) error {
	(*v)[s] = true
	return nil
}
