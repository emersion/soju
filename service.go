package soju

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/irc.v3"
)

const serviceNick = "BouncerServ"
const serviceNickCM = "bouncerserv"
const serviceRealname = "soju bouncer service"

var servicePrefix = &irc.Prefix{
	Name: serviceNick,
	User: serviceNick,
	Host: serviceNick,
}

type serviceCommandSet map[string]*serviceCommand

type serviceCommand struct {
	usage    string
	desc     string
	handle   func(dc *downstreamConn, params []string) error
	children serviceCommandSet
	admin    bool
}

func sendServiceNOTICE(dc *downstreamConn, text string) {
	dc.SendMessage(&irc.Message{
		Prefix:  servicePrefix,
		Command: "NOTICE",
		Params:  []string{dc.nick, text},
	})
}

func sendServicePRIVMSG(dc *downstreamConn, text string) {
	dc.SendMessage(&irc.Message{
		Prefix:  servicePrefix,
		Command: "PRIVMSG",
		Params:  []string{dc.nick, text},
	})
}

func splitWords(s string) ([]string, error) {
	var words []string
	var lastWord strings.Builder
	escape := false
	prev := ' '
	wordDelim := ' '

	for _, r := range s {
		if escape {
			// last char was a backslash, write the byte as-is.
			lastWord.WriteRune(r)
			escape = false
		} else if r == '\\' {
			escape = true
		} else if wordDelim == ' ' && unicode.IsSpace(r) {
			// end of last word
			if !unicode.IsSpace(prev) {
				words = append(words, lastWord.String())
				lastWord.Reset()
			}
		} else if r == wordDelim {
			// wordDelim is either " or ', switch back to
			// space-delimited words.
			wordDelim = ' '
		} else if r == '"' || r == '\'' {
			if wordDelim == ' ' {
				// start of (double-)quoted word
				wordDelim = r
			} else {
				// either wordDelim is " and r is ' or vice-versa
				lastWord.WriteRune(r)
			}
		} else {
			lastWord.WriteRune(r)
		}

		prev = r
	}

	if !unicode.IsSpace(prev) {
		words = append(words, lastWord.String())
	}

	if wordDelim != ' ' {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	if escape {
		return nil, fmt.Errorf("unterminated backslash sequence")
	}

	return words, nil
}

func handleServicePRIVMSG(dc *downstreamConn, text string) {
	words, err := splitWords(text)
	if err != nil {
		sendServicePRIVMSG(dc, fmt.Sprintf(`error: failed to parse command: %v`, err))
		return
	}

	cmd, params, err := serviceCommands.Get(words)
	if err != nil {
		sendServicePRIVMSG(dc, fmt.Sprintf(`error: %v (type "help" for a list of commands)`, err))
		return
	}
	if cmd.admin && !dc.user.Admin {
		sendServicePRIVMSG(dc, fmt.Sprintf(`error: you must be an admin to use this command`))
		return
	}

	if cmd.handle == nil {
		if len(cmd.children) > 0 {
			var l []string
			appendServiceCommandSetHelp(cmd.children, words, dc.user.Admin, &l)
			sendServicePRIVMSG(dc, "available commands: "+strings.Join(l, ", "))
		} else {
			// Pretend the command does not exist if it has neither children nor handler.
			// This is obviously a bug but it is better to not die anyway.
			dc.logger.Printf("command without handler and subcommands invoked:", words[0])
			sendServicePRIVMSG(dc, fmt.Sprintf("command %q not found", words[0]))
		}
		return
	}

	if err := cmd.handle(dc, params); err != nil {
		sendServicePRIVMSG(dc, fmt.Sprintf("error: %v", err))
	}
}

func (cmds serviceCommandSet) Get(params []string) (*serviceCommand, []string, error) {
	if len(params) == 0 {
		return nil, nil, fmt.Errorf("no command specified")
	}

	name := params[0]
	params = params[1:]

	cmd, ok := cmds[name]
	if !ok {
		for k := range cmds {
			if !strings.HasPrefix(k, name) {
				continue
			}
			if cmd != nil {
				return nil, params, fmt.Errorf("command %q is ambiguous", name)
			}
			cmd = cmds[k]
		}
	}
	if cmd == nil {
		return nil, params, fmt.Errorf("command %q not found", name)
	}

	if len(params) == 0 || len(cmd.children) == 0 {
		return cmd, params, nil
	}
	return cmd.children.Get(params)
}

func (cmds serviceCommandSet) Names() []string {
	l := make([]string, 0, len(cmds))
	for name := range cmds {
		l = append(l, name)
	}
	sort.Strings(l)
	return l
}

var serviceCommands serviceCommandSet

func init() {
	serviceCommands = serviceCommandSet{
		"help": {
			usage:  "[command]",
			desc:   "print help message",
			handle: handleServiceHelp,
		},
		"network": {
			children: serviceCommandSet{
				"create": {
					usage:  "-addr <addr> [-name name] [-username username] [-pass pass] [-realname realname] [-nick nick] [-enabled enabled] [-connect-command command]...",
					desc:   "add a new network",
					handle: handleServiceNetworkCreate,
				},
				"status": {
					desc:   "show a list of saved networks and their current status",
					handle: handleServiceNetworkStatus,
				},
				"update": {
					usage:  "<name> [-addr addr] [-name name] [-username username] [-pass pass] [-realname realname] [-nick nick] [-enabled enabled] [-connect-command command]...",
					desc:   "update a network",
					handle: handleServiceNetworkUpdate,
				},
				"delete": {
					usage:  "<name>",
					desc:   "delete a network",
					handle: handleServiceNetworkDelete,
				},
			},
		},
		"certfp": {
			children: serviceCommandSet{
				"generate": {
					usage:  "[-key-type rsa|ecdsa|ed25519] [-bits N] <network name>",
					desc:   "generate a new self-signed certificate, defaults to using RSA-3072 key",
					handle: handleServiceCertfpGenerate,
				},
				"fingerprint": {
					usage:  "<network name>",
					desc:   "show fingerprints of certificate associated with the network",
					handle: handleServiceCertfpFingerprints,
				},
			},
		},
		"sasl": {
			children: serviceCommandSet{
				"set-plain": {
					usage:  "<network name> <username> <password>",
					desc:   "set SASL PLAIN credentials",
					handle: handleServiceSASLSetPlain,
				},
				"reset": {
					usage:  "<network name>",
					desc:   "disable SASL authentication and remove stored credentials",
					handle: handleServiceSASLReset,
				},
			},
		},
		"user": {
			children: serviceCommandSet{
				"create": {
					usage:  "-username <username> -password <password> [-realname <realname>] [-admin]",
					desc:   "create a new soju user",
					handle: handleUserCreate,
					admin:  true,
				},
				"update": {
					usage:  "[-password <password>] [-realname <realname>]",
					desc:   "update the current user",
					handle: handleUserUpdate,
				},
				"delete": {
					usage:  "<username>",
					desc:   "delete a user",
					handle: handleUserDelete,
					admin:  true,
				},
			},
		},
		"channel": {
			children: serviceCommandSet{
				"status": {
					usage:  "[-network name]",
					desc:   "show a list of saved channels and their current status",
					handle: handleServiceChannelStatus,
				},
				"update": {
					usage:  "<name> [-relay-detached <default|none|highlight|message>] [-reattach-on <default|none|highlight|message>] [-detach-after <duration>] [-detach-on <default|none|highlight|message>]",
					desc:   "update a channel",
					handle: handleServiceChannelUpdate,
				},
			},
		},
	}
}

func appendServiceCommandSetHelp(cmds serviceCommandSet, prefix []string, admin bool, l *[]string) {
	for _, name := range cmds.Names() {
		cmd := cmds[name]
		if cmd.admin && !admin {
			continue
		}
		words := append(prefix, name)
		if len(cmd.children) == 0 {
			s := strings.Join(words, " ")
			*l = append(*l, s)
		} else {
			appendServiceCommandSetHelp(cmd.children, words, admin, l)
		}
	}
}

func handleServiceHelp(dc *downstreamConn, params []string) error {
	if len(params) > 0 {
		cmd, rest, err := serviceCommands.Get(params)
		if err != nil {
			return err
		}
		words := params[:len(params)-len(rest)]

		if len(cmd.children) > 0 {
			var l []string
			appendServiceCommandSetHelp(cmd.children, words, dc.user.Admin, &l)
			sendServicePRIVMSG(dc, "available commands: "+strings.Join(l, ", "))
		} else {
			text := strings.Join(words, " ")
			if cmd.usage != "" {
				text += " " + cmd.usage
			}
			text += ": " + cmd.desc

			sendServicePRIVMSG(dc, text)
		}
	} else {
		var l []string
		appendServiceCommandSetHelp(serviceCommands, nil, dc.user.Admin, &l)
		sendServicePRIVMSG(dc, "available commands: "+strings.Join(l, ", "))
	}
	return nil
}

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.SetOutput(ioutil.Discard)
	return fs
}

type stringSliceFlag []string

func (v *stringSliceFlag) String() string {
	return fmt.Sprint([]string(*v))
}

func (v *stringSliceFlag) Set(s string) error {
	*v = append(*v, s)
	return nil
}

// stringPtrFlag is a flag value populating a string pointer. This allows to
// disambiguate between a flag that hasn't been set and a flag that has been
// set to an empty string.
type stringPtrFlag struct {
	ptr **string
}

func (f stringPtrFlag) String() string {
	if f.ptr == nil || *f.ptr == nil {
		return ""
	}
	return **f.ptr
}

func (f stringPtrFlag) Set(s string) error {
	*f.ptr = &s
	return nil
}

type boolPtrFlag struct {
	ptr **bool
}

func (f boolPtrFlag) String() string {
	if f.ptr == nil || *f.ptr == nil {
		return "<nil>"
	}
	return strconv.FormatBool(**f.ptr)
}

func (f boolPtrFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*f.ptr = &v
	return nil
}

type networkFlagSet struct {
	*flag.FlagSet
	Addr, Name, Nick, Username, Pass, Realname *string
	Enabled                                    *bool
	ConnectCommands                            []string
}

func newNetworkFlagSet() *networkFlagSet {
	fs := &networkFlagSet{FlagSet: newFlagSet()}
	fs.Var(stringPtrFlag{&fs.Addr}, "addr", "")
	fs.Var(stringPtrFlag{&fs.Name}, "name", "")
	fs.Var(stringPtrFlag{&fs.Nick}, "nick", "")
	fs.Var(stringPtrFlag{&fs.Username}, "username", "")
	fs.Var(stringPtrFlag{&fs.Pass}, "pass", "")
	fs.Var(stringPtrFlag{&fs.Realname}, "realname", "")
	fs.Var(boolPtrFlag{&fs.Enabled}, "enabled", "")
	fs.Var((*stringSliceFlag)(&fs.ConnectCommands), "connect-command", "")
	return fs
}

func (fs *networkFlagSet) update(network *Network) error {
	if fs.Addr != nil {
		if addrParts := strings.SplitN(*fs.Addr, "://", 2); len(addrParts) == 2 {
			scheme := addrParts[0]
			switch scheme {
			case "ircs", "irc+insecure", "unix":
			default:
				return fmt.Errorf("unknown scheme %q (supported schemes: ircs, irc+insecure, unix)", scheme)
			}
		}
		network.Addr = *fs.Addr
	}
	if fs.Name != nil {
		network.Name = *fs.Name
	}
	if fs.Nick != nil {
		network.Nick = *fs.Nick
	}
	if fs.Username != nil {
		network.Username = *fs.Username
	}
	if fs.Pass != nil {
		network.Pass = *fs.Pass
	}
	if fs.Realname != nil {
		network.Realname = *fs.Realname
	}
	if fs.Enabled != nil {
		network.Enabled = *fs.Enabled
	}
	if fs.ConnectCommands != nil {
		if len(fs.ConnectCommands) == 1 && fs.ConnectCommands[0] == "" {
			network.ConnectCommands = nil
		} else {
			for _, command := range fs.ConnectCommands {
				_, err := irc.ParseMessage(command)
				if err != nil {
					return fmt.Errorf("flag -connect-command must be a valid raw irc command string: %q: %v", command, err)
				}
			}
			network.ConnectCommands = fs.ConnectCommands
		}
	}
	return nil
}

func handleServiceNetworkCreate(dc *downstreamConn, params []string) error {
	fs := newNetworkFlagSet()
	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.Addr == nil {
		return fmt.Errorf("flag -addr is required")
	}

	record := &Network{
		Addr:    *fs.Addr,
		Nick:    dc.nick,
		Enabled: true,
	}
	if err := fs.update(record); err != nil {
		return err
	}

	network, err := dc.user.createNetwork(record)
	if err != nil {
		return fmt.Errorf("could not create network: %v", err)
	}

	sendServicePRIVMSG(dc, fmt.Sprintf("created network %q", network.GetName()))
	return nil
}

func handleServiceNetworkStatus(dc *downstreamConn, params []string) error {
	n := 0
	dc.user.forEachNetwork(func(net *network) {
		var statuses []string
		var details string
		if uc := net.conn; uc != nil {
			if dc.nick != uc.nick {
				statuses = append(statuses, "connected as "+uc.nick)
			} else {
				statuses = append(statuses, "connected")
			}
			details = fmt.Sprintf("%v channels", uc.channels.Len())
		} else if !net.Enabled {
			statuses = append(statuses, "disabled")
		} else {
			statuses = append(statuses, "disconnected")
			if net.lastError != nil {
				details = net.lastError.Error()
			}
		}

		if net == dc.network {
			statuses = append(statuses, "current")
		}

		name := net.GetName()
		if name != net.Addr {
			name = fmt.Sprintf("%v (%v)", name, net.Addr)
		}

		s := fmt.Sprintf("%v [%v]", name, strings.Join(statuses, ", "))
		if details != "" {
			s += ": " + details
		}
		sendServicePRIVMSG(dc, s)

		n++
	})

	if n == 0 {
		sendServicePRIVMSG(dc, `No network configured, add one with "network create".`)
	}

	return nil
}

func handleServiceNetworkUpdate(dc *downstreamConn, params []string) error {
	if len(params) < 1 {
		return fmt.Errorf("expected at least one argument")
	}

	fs := newNetworkFlagSet()
	if err := fs.Parse(params[1:]); err != nil {
		return err
	}

	net := dc.user.getNetwork(params[0])
	if net == nil {
		return fmt.Errorf("unknown network %q", params[0])
	}

	record := net.Network // copy network record because we'll mutate it
	if err := fs.update(&record); err != nil {
		return err
	}

	network, err := dc.user.updateNetwork(&record)
	if err != nil {
		return fmt.Errorf("could not update network: %v", err)
	}

	sendServicePRIVMSG(dc, fmt.Sprintf("updated network %q", network.GetName()))
	return nil
}

func handleServiceNetworkDelete(dc *downstreamConn, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}

	net := dc.user.getNetwork(params[0])
	if net == nil {
		return fmt.Errorf("unknown network %q", params[0])
	}

	if err := dc.user.deleteNetwork(net.ID); err != nil {
		return err
	}

	sendServicePRIVMSG(dc, fmt.Sprintf("deleted network %q", net.GetName()))
	return nil
}

func handleServiceCertfpGenerate(dc *downstreamConn, params []string) error {
	fs := newFlagSet()
	keyType := fs.String("key-type", "rsa", "key type to generate (rsa, ecdsa, ed25519)")
	bits := fs.Int("bits", 3072, "size of key to generate, meaningful only for RSA")

	if err := fs.Parse(params); err != nil {
		return err
	}

	if len(fs.Args()) != 1 {
		return errors.New("exactly one argument is required")
	}

	net := dc.user.getNetwork(fs.Arg(0))
	if net == nil {
		return fmt.Errorf("unknown network %q", fs.Arg(0))
	}

	var (
		privKey crypto.PrivateKey
		pubKey  crypto.PublicKey
	)
	switch *keyType {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, *bits)
		if err != nil {
			return err
		}
		privKey = key
		pubKey = key.Public()
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return err
		}
		privKey = key
		pubKey = key.Public()
	case "ed25519":
		var err error
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
	}

	// Using PKCS#8 allows easier extension for new key types.
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	// Lets make a fair assumption nobody will use the same cert for more than 20 years...
	notAfter := notBefore.Add(24 * time.Hour * 365 * 20)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "soju auto-generated certificate"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pubKey, privKey)
	if err != nil {
		return err
	}

	net.SASL.External.CertBlob = derBytes
	net.SASL.External.PrivKeyBlob = privKeyBytes
	net.SASL.Mechanism = "EXTERNAL"

	if err := dc.srv.db.StoreNetwork(dc.user.ID, &net.Network); err != nil {
		return err
	}

	sendServicePRIVMSG(dc, "certificate generated")

	sha1Sum := sha1.Sum(derBytes)
	sendServicePRIVMSG(dc, "SHA-1 fingerprint: "+hex.EncodeToString(sha1Sum[:]))
	sha256Sum := sha256.Sum256(derBytes)
	sendServicePRIVMSG(dc, "SHA-256 fingerprint: "+hex.EncodeToString(sha256Sum[:]))

	return nil
}

func handleServiceCertfpFingerprints(dc *downstreamConn, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}

	net := dc.user.getNetwork(params[0])
	if net == nil {
		return fmt.Errorf("unknown network %q", params[0])
	}

	sha1Sum := sha1.Sum(net.SASL.External.CertBlob)
	sendServicePRIVMSG(dc, "SHA-1 fingerprint: "+hex.EncodeToString(sha1Sum[:]))
	sha256Sum := sha256.Sum256(net.SASL.External.CertBlob)
	sendServicePRIVMSG(dc, "SHA-256 fingerprint: "+hex.EncodeToString(sha256Sum[:]))
	return nil
}

func handleServiceSASLSetPlain(dc *downstreamConn, params []string) error {
	if len(params) != 3 {
		return fmt.Errorf("expected exactly 3 arguments")
	}

	net := dc.user.getNetwork(params[0])
	if net == nil {
		return fmt.Errorf("unknown network %q", params[0])
	}

	net.SASL.Plain.Username = params[1]
	net.SASL.Plain.Password = params[2]
	net.SASL.Mechanism = "PLAIN"

	if err := dc.srv.db.StoreNetwork(dc.user.ID, &net.Network); err != nil {
		return err
	}

	sendServicePRIVMSG(dc, "credentials saved")
	return nil
}

func handleServiceSASLReset(dc *downstreamConn, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}

	net := dc.user.getNetwork(params[0])
	if net == nil {
		return fmt.Errorf("unknown network %q", params[0])
	}

	net.SASL.Plain.Username = ""
	net.SASL.Plain.Password = ""
	net.SASL.External.CertBlob = nil
	net.SASL.External.PrivKeyBlob = nil
	net.SASL.Mechanism = ""

	if err := dc.srv.db.StoreNetwork(dc.user.ID, &net.Network); err != nil {
		return err
	}

	sendServicePRIVMSG(dc, "credentials reset")
	return nil
}

func handleUserCreate(dc *downstreamConn, params []string) error {
	fs := newFlagSet()
	username := fs.String("username", "", "")
	password := fs.String("password", "", "")
	realname := fs.String("realname", "", "")
	admin := fs.Bool("admin", false, "")

	if err := fs.Parse(params); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("flag -username is required")
	}
	if *password == "" {
		return fmt.Errorf("flag -password is required")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	user := &User{
		Username: *username,
		Password: string(hashed),
		Realname: *realname,
		Admin:    *admin,
	}
	if _, err := dc.srv.createUser(user); err != nil {
		return fmt.Errorf("could not create user: %v", err)
	}

	sendServicePRIVMSG(dc, fmt.Sprintf("created user %q", *username))
	return nil
}

func handleUserUpdate(dc *downstreamConn, params []string) error {
	var password, realname *string
	fs := newFlagSet()
	fs.Var(stringPtrFlag{&password}, "password", "")
	fs.Var(stringPtrFlag{&realname}, "realname", "")

	if err := fs.Parse(params); err != nil {
		return err
	}

	// copy the user record because we'll mutate it
	record := dc.user.User

	if password != nil {
		hashed, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %v", err)
		}
		record.Password = string(hashed)
	}
	if realname != nil {
		record.Realname = *realname
	}

	if err := dc.user.updateUser(&record); err != nil {
		return err
	}

	sendServicePRIVMSG(dc, fmt.Sprintf("updated user %q", dc.user.Username))
	return nil
}

func handleUserDelete(dc *downstreamConn, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}
	username := params[0]

	u := dc.srv.getUser(username)
	if u == nil {
		return fmt.Errorf("unknown username %q", username)
	}

	u.stop()

	if err := dc.srv.db.DeleteUser(u.ID); err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	sendServicePRIVMSG(dc, fmt.Sprintf("deleted user %q", username))
	return nil
}

func handleServiceChannelStatus(dc *downstreamConn, params []string) error {
	var defaultNetworkName string
	if dc.network != nil {
		defaultNetworkName = dc.network.GetName()
	}

	fs := newFlagSet()
	networkName := fs.String("network", defaultNetworkName, "")

	if err := fs.Parse(params); err != nil {
		return err
	}

	n := 0

	sendNetwork := func(net *network) {
		var channels []*Channel
		for _, entry := range net.channels.innerMap {
			channels = append(channels, entry.value.(*Channel))
		}

		sort.Slice(channels, func(i, j int) bool {
			return strings.ReplaceAll(channels[i].Name, "#", "") <
				strings.ReplaceAll(channels[j].Name, "#", "")
		})

		for _, ch := range channels {
			var uch *upstreamChannel
			if net.conn != nil {
				uch = net.conn.channels.Value(ch.Name)
			}

			name := ch.Name
			if *networkName == "" {
				name += "/" + net.GetName()
			}

			var status string
			if uch != nil {
				status = "joined"
			} else if net.conn != nil {
				status = "parted"
			} else {
				status = "disconnected"
			}

			if ch.Detached {
				status += ", detached"
			}

			s := fmt.Sprintf("%v [%v]", name, status)
			sendServicePRIVMSG(dc, s)

			n++
		}
	}

	if *networkName == "" {
		dc.user.forEachNetwork(sendNetwork)
	} else {
		net := dc.user.getNetwork(*networkName)
		if net == nil {
			return fmt.Errorf("unknown network %q", *networkName)
		}
		sendNetwork(net)
	}

	if n == 0 {
		sendServicePRIVMSG(dc, "No channel configured.")
	}

	return nil
}

type channelFlagSet struct {
	*flag.FlagSet
	RelayDetached, ReattachOn, DetachAfter, DetachOn *string
}

func newChannelFlagSet() *channelFlagSet {
	fs := &channelFlagSet{FlagSet: newFlagSet()}
	fs.Var(stringPtrFlag{&fs.RelayDetached}, "relay-detached", "")
	fs.Var(stringPtrFlag{&fs.ReattachOn}, "reattach-on", "")
	fs.Var(stringPtrFlag{&fs.DetachAfter}, "detach-after", "")
	fs.Var(stringPtrFlag{&fs.DetachOn}, "detach-on", "")
	return fs
}

func (fs *channelFlagSet) update(channel *Channel) error {
	if fs.RelayDetached != nil {
		filter, err := parseFilter(*fs.RelayDetached)
		if err != nil {
			return err
		}
		channel.RelayDetached = filter
	}
	if fs.ReattachOn != nil {
		filter, err := parseFilter(*fs.ReattachOn)
		if err != nil {
			return err
		}
		channel.ReattachOn = filter
	}
	if fs.DetachAfter != nil {
		dur, err := time.ParseDuration(*fs.DetachAfter)
		if err != nil || dur < 0 {
			return fmt.Errorf("unknown duration for -detach-after %q (duration format: 0, 300s, 22h30m, ...)", *fs.DetachAfter)
		}
		channel.DetachAfter = dur
	}
	if fs.DetachOn != nil {
		filter, err := parseFilter(*fs.DetachOn)
		if err != nil {
			return err
		}
		channel.DetachOn = filter
	}
	return nil
}

func handleServiceChannelUpdate(dc *downstreamConn, params []string) error {
	if len(params) < 1 {
		return fmt.Errorf("expected at least one argument")
	}
	name := params[0]

	fs := newChannelFlagSet()
	if err := fs.Parse(params[1:]); err != nil {
		return err
	}

	uc, upstreamName, err := dc.unmarshalEntity(name)
	if err != nil {
		return fmt.Errorf("unknown channel %q", name)
	}

	ch := uc.network.channels.Value(upstreamName)
	if ch == nil {
		return fmt.Errorf("unknown channel %q", name)
	}

	if err := fs.update(ch); err != nil {
		return err
	}

	uc.updateChannelAutoDetach(upstreamName)

	if err := dc.srv.db.StoreChannel(uc.network.ID, ch); err != nil {
		return fmt.Errorf("failed to update channel: %v", err)
	}

	sendServicePRIVMSG(dc, fmt.Sprintf("updated channel %q", name))
	return nil
}
