package soju

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/irc.v4"

	"git.sr.ht/~emersion/soju/database"
)

const serviceNick = "BouncerServ"
const serviceNickCM = "bouncerserv"
const serviceRealname = "soju bouncer service"

// maxRSABits is the maximum number of RSA key bits used when generating a new
// private key.
const maxRSABits = 8192

var servicePrefix = &irc.Prefix{
	Name: serviceNick,
	User: serviceNick,
	Host: serviceNick,
}

type serviceContext struct {
	context.Context
	nick    string   // optional
	network *network // optional
	user    *user    // optional
	srv     *Server
	admin   bool
	print   func(string)
}

type serviceCommandSet map[string]*serviceCommand

type serviceCommand struct {
	usage    string
	desc     string
	handle   func(ctx *serviceContext, params []string) error
	children serviceCommandSet
	admin    bool
	global   bool
}

func sendServiceNOTICE(dc *downstreamConn, text string) {
	dc.SendMessage(context.TODO(), &irc.Message{
		Prefix:  servicePrefix,
		Command: "NOTICE",
		Params:  []string{dc.nick, text},
	})
}

func sendServicePRIVMSG(dc *downstreamConn, text string) {
	dc.SendMessage(context.TODO(), &irc.Message{
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

func handleServicePRIVMSG(ctx *serviceContext, text string) error {
	words, err := splitWords(text)
	if err != nil {
		return fmt.Errorf(`failed to parse command: %v`, err)
	}
	return handleServiceCommand(ctx, words)
}

func handleServiceCommand(ctx *serviceContext, words []string) error {
	cmd, params, err := serviceCommands.Get(words)
	if err != nil {
		return fmt.Errorf(`%v (type "help" for a list of commands)`, err)
	}
	if cmd.admin && !ctx.admin {
		return fmt.Errorf("you must be an admin to use this command")
	}
	if !cmd.global && ctx.user == nil {
		return fmt.Errorf("this command must be run as a user (try running with user run)")
	}

	if cmd.handle == nil {
		if len(cmd.children) > 0 {
			var l []string
			appendServiceCommandSetHelp(cmd.children, words, ctx.admin, ctx.user == nil, &l)
			ctx.print("available commands: " + strings.Join(l, ", "))
			return nil
		}
		// Pretend the command does not exist if it has neither children nor handler.
		// This is obviously a bug but it is better to not die anyway.
		var logger Logger
		if ctx.user != nil {
			logger = ctx.user.logger
		} else {
			logger = ctx.srv.Logger
		}
		logger.Printf("command without handler and subcommands invoked:", words[0])
		return fmt.Errorf("command %q not found", words[0])
	}

	return cmd.handle(ctx, params)
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
			global: true,
		},
		"network": {
			children: serviceCommandSet{
				"create": {
					usage:  "-addr <addr> [-name name] [-username username] [-pass pass] [-realname realname] [-certfp fingerprint] [-nick nick] [-auto-away auto-away] [-enabled enabled] [-connect-command command]...",
					desc:   "add a new network",
					handle: handleServiceNetworkCreate,
				},
				"status": {
					desc:   "show a list of saved networks and their current status",
					handle: handleServiceNetworkStatus,
				},
				"update": {
					usage:  "[name] [-addr addr] [-name name] [-username username] [-pass pass] [-realname realname] [-certfp fingerprint] [-nick nick] [-auto-away auto-away] [-enabled enabled] [-connect-command command]...",
					desc:   "update a network",
					handle: handleServiceNetworkUpdate,
				},
				"delete": {
					usage:  "[name]",
					desc:   "delete a network",
					handle: handleServiceNetworkDelete,
				},
				"quote": {
					usage:  "[name] <command>",
					desc:   "send a raw line to a network",
					handle: handleServiceNetworkQuote,
				},
			},
		},
		"certfp": {
			children: serviceCommandSet{
				"generate": {
					usage:  "[-key-type rsa|ecdsa|ed25519] [-bits N] [-network name]",
					desc:   "generate a new self-signed certificate, defaults to using RSA-3072 key",
					handle: handleServiceCertFPGenerate,
				},
				"fingerprint": {
					usage:  "[-network name]",
					desc:   "show fingerprints of certificate",
					handle: handleServiceCertFPFingerprints,
				},
			},
		},
		"sasl": {
			children: serviceCommandSet{
				"status": {
					usage:  "[-network name]",
					desc:   "show SASL status",
					handle: handleServiceSASLStatus,
				},
				"set-plain": {
					usage:  "[-network name] <username> <password>",
					desc:   "set SASL PLAIN credentials",
					handle: handleServiceSASLSetPlain,
				},
				"reset": {
					usage:  "[-network name]",
					desc:   "disable SASL authentication and remove stored credentials",
					handle: handleServiceSASLReset,
				},
			},
		},
		"user": {
			children: serviceCommandSet{
				"status": {
					desc:   "show a list of users and their current status",
					handle: handleUserStatus,
					admin:  true,
					global: true,
				},
				"create": {
					usage:  "-username <username> -password <password> [-disable-password] [-admin true|false] [-nick <nick>] [-realname <realname>] [-enabled true|false]",
					desc:   "create a new soju user",
					handle: handleUserCreate,
					admin:  true,
					global: true,
				},
				"update": {
					usage:  "[username] [-password <password>] [-disable-password] [-admin true|false] [-nick <nick>] [-realname <realname>] [-enabled true|false]",
					desc:   "update a user",
					handle: handleUserUpdate,
					global: true,
				},
				"delete": {
					usage:  "<username> [confirmation token]",
					desc:   "delete a user",
					handle: handleUserDelete,
					global: true,
				},
				"run": {
					usage:  "<username> <command>",
					desc:   "run a command as another user",
					handle: handleUserRun,
					admin:  true,
					global: true,
				},
			},
			global: true,
		},
		"channel": {
			children: serviceCommandSet{
				"status": {
					usage:  "[-network name]",
					desc:   "show a list of saved channels and their current status",
					handle: handleServiceChannelStatus,
				},
				"update": {
					usage:  "<name> [-detached <true|false>] [-relay-detached <default|none|highlight|message>] [-reattach-on <default|none|highlight|message>] [-detach-after <duration>] [-detach-on <default|none|highlight|message>]",
					desc:   "update a channel",
					handle: handleServiceChannelUpdate,
				},
				"delete": {
					usage:  "<name>",
					desc:   "delete a channel",
					handle: handleServiceChannelDelete,
				},
			},
		},
		"server": {
			children: serviceCommandSet{
				"status": {
					desc:   "show server statistics",
					handle: handleServiceServerStatus,
					admin:  true,
					global: true,
				},
				"notice": {
					usage:  "<notice>",
					desc:   "broadcast a notice to all connected bouncer users",
					handle: handleServiceServerNotice,
					admin:  true,
					global: true,
				},
			},
			admin: true,
		},
	}
}

func appendServiceCommandSetHelp(cmds serviceCommandSet, prefix []string, admin bool, global bool, l *[]string) {
	for _, name := range cmds.Names() {
		cmd := cmds[name]
		if cmd.admin && !admin {
			continue
		}
		if !cmd.global && global {
			continue
		}
		words := append(prefix, name)
		if len(cmd.children) == 0 {
			s := strings.Join(words, " ")
			*l = append(*l, s)
		} else {
			appendServiceCommandSetHelp(cmd.children, words, admin, global, l)
		}
	}
}

func handleServiceHelp(ctx *serviceContext, params []string) error {
	if len(params) > 0 {
		cmd, rest, err := serviceCommands.Get(params)
		if err != nil {
			return err
		}
		words := params[:len(params)-len(rest)]

		if len(cmd.children) > 0 {
			var l []string
			appendServiceCommandSetHelp(cmd.children, words, ctx.admin, ctx.user == nil, &l)
			ctx.print("available commands: " + strings.Join(l, ", "))
		} else {
			text := strings.Join(words, " ")
			if cmd.usage != "" {
				text += " " + cmd.usage
			}
			text += ": " + cmd.desc

			ctx.print(text)
		}
	} else {
		var l []string
		appendServiceCommandSetHelp(serviceCommands, nil, ctx.admin, ctx.user == nil, &l)
		ctx.print("available commands: " + strings.Join(l, ", "))
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

func getNetworkFromArg(ctx *serviceContext, params []string) (*network, []string, error) {
	name, params := popArg(params)
	if name == "" {
		if ctx.network == nil {
			return nil, params, fmt.Errorf("no network selected, a name argument is required")
		}
		return ctx.network, params, nil
	} else {
		net := ctx.user.getNetwork(name)
		if net == nil {
			return nil, params, fmt.Errorf("unknown network %q", name)
		}
		return net, params, nil
	}
}

type networkFlagSet struct {
	*flag.FlagSet
	Addr, Name, Nick, Username, Pass, Realname, CertFP *string
	AutoAway, Enabled                                  *bool
	ConnectCommands                                    []string
}

func newNetworkFlagSet() *networkFlagSet {
	fs := &networkFlagSet{FlagSet: newFlagSet()}
	fs.Var(stringPtrFlag{&fs.Addr}, "addr", "")
	fs.Var(stringPtrFlag{&fs.Name}, "name", "")
	fs.Var(stringPtrFlag{&fs.Nick}, "nick", "")
	fs.Var(stringPtrFlag{&fs.Username}, "username", "")
	fs.Var(stringPtrFlag{&fs.Pass}, "pass", "")
	fs.Var(stringPtrFlag{&fs.Realname}, "realname", "")
	fs.Var(stringPtrFlag{&fs.CertFP}, "certfp", "")
	fs.Var(boolPtrFlag{&fs.AutoAway}, "auto-away", "")
	fs.Var(boolPtrFlag{&fs.Enabled}, "enabled", "")
	fs.Var((*stringSliceFlag)(&fs.ConnectCommands), "connect-command", "")
	return fs
}

func (fs *networkFlagSet) update(network *database.Network) error {
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
		if *fs.Name == "*" {
			return fmt.Errorf("the network name %q is reserved for multi-upstream mode", *fs.Name)
		}
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
	if fs.CertFP != nil {
		certFP := strings.ToLower(strings.ReplaceAll(*fs.CertFP, ":", ""))
		if _, err := hex.DecodeString(certFP); err != nil {
			return fmt.Errorf("the certificate fingerprint must be hex-encoded")
		}
		if len(certFP) == 0 {
			network.CertFP = ""
		} else if len(certFP) == 64 {
			network.CertFP = "sha-256:" + certFP
		} else if len(certFP) == 128 {
			network.CertFP = "sha-512:" + certFP
		} else {
			return fmt.Errorf("the certificate fingerprint must be a SHA256 or SHA512 hash")
		}
	}
	if fs.AutoAway != nil {
		network.AutoAway = *fs.AutoAway
	}
	if fs.Enabled != nil {
		network.Enabled = *fs.Enabled
	}
	if fs.ConnectCommands != nil {
		if len(fs.ConnectCommands) == 1 && fs.ConnectCommands[0] == "" {
			network.ConnectCommands = nil
		} else {
			if len(fs.ConnectCommands) > 20 {
				return fmt.Errorf("too many -connect-command flags supplied")
			}
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

func handleServiceNetworkCreate(ctx *serviceContext, params []string) error {
	fs := newNetworkFlagSet()
	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}
	if fs.Addr == nil {
		return fmt.Errorf("flag -addr is required")
	}

	record := database.NewNetwork(*fs.Addr)
	if err := fs.update(record); err != nil {
		return err
	}

	network, err := ctx.user.createNetwork(ctx, record)
	if err != nil {
		return fmt.Errorf("could not create network: %v", err)
	}

	ctx.print(fmt.Sprintf("created network %q", network.GetName()))
	return nil
}

func handleServiceNetworkStatus(ctx *serviceContext, params []string) error {
	if len(params) != 0 {
		return fmt.Errorf("expected no argument")
	}

	n := 0
	for _, net := range ctx.user.networks {
		var statuses []string
		var details string
		if uc := net.conn; uc != nil {
			if ctx.nick != "" && ctx.nick != uc.nick {
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

		if net == ctx.network {
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
		ctx.print(s)

		n++
	}

	if n == 0 {
		ctx.print(`No network configured, add one with "network create".`)
	}

	return nil
}

func handleServiceNetworkUpdate(ctx *serviceContext, params []string) error {
	net, params, err := getNetworkFromArg(ctx, params)
	if err != nil {
		return err
	}

	fs := newNetworkFlagSet()
	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}

	record := net.Network // copy network record because we'll mutate it
	if err := fs.update(&record); err != nil {
		return err
	}

	network, err := ctx.user.updateNetwork(ctx, &record)
	if err != nil {
		return fmt.Errorf("could not update network: %v", err)
	}

	ctx.print(fmt.Sprintf("updated network %q", network.GetName()))
	return nil
}

func handleServiceNetworkDelete(ctx *serviceContext, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}
	net, params, err := getNetworkFromArg(ctx, params)
	if err != nil {
		return err
	}

	if err := ctx.user.deleteNetwork(ctx, net.ID); err != nil {
		return err
	}

	ctx.print(fmt.Sprintf("deleted network %q", net.GetName()))
	return nil
}

func handleServiceNetworkQuote(ctx *serviceContext, params []string) error {
	if len(params) != 1 && len(params) != 2 {
		return fmt.Errorf("expected one or two arguments")
	}

	raw := params[len(params)-1]
	params = params[:len(params)-1]

	net, params, err := getNetworkFromArg(ctx, params)
	if err != nil {
		return err
	}

	uc := net.conn
	if uc == nil {
		return fmt.Errorf("network %q is not currently connected", net.GetName())
	}

	m, err := irc.ParseMessage(raw)
	if err != nil {
		return fmt.Errorf("failed to parse command %q: %v", raw, err)
	}
	uc.SendMessage(ctx, m)

	ctx.print(fmt.Sprintf("sent command to %q", net.GetName()))
	return nil
}

func sendCertfpFingerprints(ctx *serviceContext, cert []byte) {
	sha1Sum := sha1.Sum(cert)
	ctx.print("SHA-1 fingerprint: " + hex.EncodeToString(sha1Sum[:]))
	sha256Sum := sha256.Sum256(cert)
	ctx.print("SHA-256 fingerprint: " + hex.EncodeToString(sha256Sum[:]))
	sha512Sum := sha512.Sum512(cert)
	ctx.print("SHA-512 fingerprint: " + hex.EncodeToString(sha512Sum[:]))
}

func getNetworkFromFlag(ctx *serviceContext, name string) (*network, error) {
	if name == "" {
		if ctx.network == nil {
			return nil, fmt.Errorf("no network selected, -network is required")
		}
		return ctx.network, nil
	} else {
		net := ctx.user.getNetwork(name)
		if net == nil {
			return nil, fmt.Errorf("unknown network %q", name)
		}
		return net, nil
	}
}

func handleServiceCertFPGenerate(ctx *serviceContext, params []string) error {
	fs := newFlagSet()
	netName := fs.String("network", "", "select a network")
	keyType := fs.String("key-type", "rsa", "key type to generate (rsa, ecdsa, ed25519)")
	bits := fs.Int("bits", 3072, "size of key to generate, meaningful only for RSA")

	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}

	if *bits <= 0 || *bits > maxRSABits {
		return fmt.Errorf("invalid value for -bits")
	}

	net, err := getNetworkFromFlag(ctx, *netName)
	if err != nil {
		return err
	}

	privKey, cert, err := generateCertFP(*keyType, *bits)
	if err != nil {
		return err
	}

	net.SASL.External.CertBlob = cert
	net.SASL.External.PrivKeyBlob = privKey
	net.SASL.Mechanism = "EXTERNAL"

	if err := ctx.srv.db.StoreNetwork(ctx, ctx.user.ID, &net.Network); err != nil {
		return err
	}

	ctx.print("certificate generated")
	sendCertfpFingerprints(ctx, cert)
	return nil
}

func handleServiceCertFPFingerprints(ctx *serviceContext, params []string) error {
	fs := newFlagSet()
	netName := fs.String("network", "", "select a network")

	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}

	net, err := getNetworkFromFlag(ctx, *netName)
	if err != nil {
		return err
	}

	if net.SASL.Mechanism != "EXTERNAL" {
		return fmt.Errorf("CertFP not set up")
	}

	sendCertfpFingerprints(ctx, net.SASL.External.CertBlob)
	return nil
}

func handleServiceSASLStatus(ctx *serviceContext, params []string) error {
	fs := newFlagSet()
	netName := fs.String("network", "", "select a network")

	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}

	net, err := getNetworkFromFlag(ctx, *netName)
	if err != nil {
		return err
	}

	switch net.SASL.Mechanism {
	case "PLAIN":
		ctx.print(fmt.Sprintf("SASL PLAIN enabled with username %q", net.SASL.Plain.Username))
	case "EXTERNAL":
		ctx.print("SASL EXTERNAL (CertFP) enabled")
	case "":
		ctx.print("SASL is disabled")
	}

	if uc := net.conn; uc != nil {
		if uc.account != "" {
			ctx.print(fmt.Sprintf("Authenticated on upstream network with account %q", uc.account))
		} else {
			ctx.print("Unauthenticated on upstream network")
		}
	} else {
		ctx.print("Disconnected from upstream network")
	}

	return nil
}

func handleServiceSASLSetPlain(ctx *serviceContext, params []string) error {
	fs := newFlagSet()
	netName := fs.String("network", "", "select a network")

	if err := fs.Parse(params); err != nil {
		return err
	}

	if fs.NArg() != 2 {
		return fmt.Errorf("expected exactly 2 arguments")
	}

	net, err := getNetworkFromFlag(ctx, *netName)
	if err != nil {
		return err
	}

	net.SASL.Plain.Username = fs.Arg(0)
	net.SASL.Plain.Password = fs.Arg(1)
	net.SASL.Mechanism = "PLAIN"

	if err := ctx.srv.db.StoreNetwork(ctx, ctx.user.ID, &net.Network); err != nil {
		return err
	}

	ctx.print("credentials saved")
	return nil
}

func handleServiceSASLReset(ctx *serviceContext, params []string) error {
	fs := newFlagSet()
	netName := fs.String("network", "", "select a network")

	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}

	net, err := getNetworkFromFlag(ctx, *netName)
	if err != nil {
		return err
	}

	net.SASL.Plain.Username = ""
	net.SASL.Plain.Password = ""
	net.SASL.External.CertBlob = nil
	net.SASL.External.PrivKeyBlob = nil
	net.SASL.Mechanism = ""

	if err := ctx.srv.db.StoreNetwork(ctx, ctx.user.ID, &net.Network); err != nil {
		return err
	}

	ctx.print("credentials reset")
	return nil
}

func handleUserStatus(ctx *serviceContext, params []string) error {
	if len(params) != 0 {
		return fmt.Errorf("expected no argument")
	}

	// Limit to a small amount of users to avoid sending
	// thousands of messages on large instances.
	users := make([]database.User, 0, 50)

	ctx.srv.lock.Lock()
	n := len(ctx.srv.users)
	for _, user := range ctx.srv.users {
		if len(users) == cap(users) {
			break
		}
		users = append(users, user.User)
	}
	ctx.srv.lock.Unlock()

	for _, user := range users {
		var attrs []string
		if user.Admin {
			attrs = append(attrs, "admin")
		}
		if !user.Enabled {
			attrs = append(attrs, "disabled")
		}

		line := user.Username
		if len(attrs) > 0 {
			line += " (" + strings.Join(attrs, ", ") + ")"
		}
		networks, err := ctx.srv.db.ListNetworks(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("could not get networks of user %q: %v", user.Username, err)
		}
		line += fmt.Sprintf(": %d networks", len(networks))
		ctx.print(line)
	}
	if n > len(users) {
		ctx.print(fmt.Sprintf("(%d more users omitted)", n-len(users)))
	}

	return nil
}

func handleUserCreate(ctx *serviceContext, params []string) error {
	fs := newFlagSet()
	username := fs.String("username", "", "")
	password := fs.String("password", "", "")
	disablePassword := fs.Bool("disable-password", false, "")
	nick := fs.String("nick", "", "")
	realname := fs.String("realname", "", "")
	admin := fs.Bool("admin", false, "")
	enabled := fs.Bool("enabled", true, "")

	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}
	if *username == "" {
		return fmt.Errorf("flag -username is required")
	}
	if *password != "" && *disablePassword {
		return fmt.Errorf("flags -password and -disable-password are mutually exclusive")
	}
	if *password == "" && !*disablePassword {
		return fmt.Errorf("flag -password is required")
	}

	user := database.NewUser(*username)
	user.Nick = *nick
	user.Realname = *realname
	user.Admin = *admin
	user.Enabled = *enabled
	if !*disablePassword {
		if err := user.SetPassword(*password); err != nil {
			return err
		}
	}
	if _, err := ctx.srv.createUser(ctx, user); err != nil {
		return fmt.Errorf("could not create user: %v", err)
	}

	ctx.print(fmt.Sprintf("created user %q", *username))
	return nil
}

func popArg(params []string) (string, []string) {
	if len(params) > 0 && !strings.HasPrefix(params[0], "-") {
		return params[0], params[1:]
	}
	return "", params
}

func handleUserUpdate(ctx *serviceContext, params []string) error {
	var password, nick, realname *string
	var admin, enabled *bool
	var disablePassword bool
	fs := newFlagSet()
	fs.Var(stringPtrFlag{&password}, "password", "")
	fs.BoolVar(&disablePassword, "disable-password", false, "")
	fs.Var(stringPtrFlag{&nick}, "nick", "")
	fs.Var(stringPtrFlag{&realname}, "realname", "")
	fs.Var(boolPtrFlag{&admin}, "admin", "")
	fs.Var(boolPtrFlag{&enabled}, "enabled", "")

	username, params := popArg(params)
	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}
	if username == "" && ctx.user == nil {
		return fmt.Errorf("cannot determine the user to update")
	}

	if password != nil && disablePassword {
		return fmt.Errorf("flags -password and -disable-password are mutually exclusive")
	}

	if username != "" && (ctx.user == nil || username != ctx.user.Username) {
		if !ctx.admin {
			return fmt.Errorf("you must be an admin to update other users")
		}
		if nick != nil {
			return fmt.Errorf("cannot update -nick of other user")
		}
		if realname != nil {
			return fmt.Errorf("cannot update -realname of other user")
		}

		var hashed *string
		if password != nil {
			var passwordRecord database.User
			if err := passwordRecord.SetPassword(*password); err != nil {
				return err
			}
			hashed = &passwordRecord.Password
		}
		if disablePassword {
			hashedStr := ""
			hashed = &hashedStr
		}

		u := ctx.srv.getUser(username)
		if u == nil {
			return fmt.Errorf("unknown username %q", username)
		}

		done := make(chan error, 1)
		event := eventUserUpdate{
			password: hashed,
			admin:    admin,
			enabled:  enabled,
			done:     done,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case u.events <- event:
		}
		// TODO: send context to the other side
		if err := <-done; err != nil {
			return err
		}

		ctx.print(fmt.Sprintf("updated user %q", username))
	} else {
		if admin != nil {
			return fmt.Errorf("cannot update -admin of own user")
		}
		if enabled != nil {
			return fmt.Errorf("cannot update -enabled of own user")
		}

		err := ctx.user.updateUser(ctx, func(record *database.User) error {
			if password != nil {
				if err := record.SetPassword(*password); err != nil {
					return err
				}
			}
			if disablePassword {
				record.Password = ""
			}
			if nick != nil {
				record.Nick = *nick
			}
			if realname != nil {
				record.Realname = *realname
			}
			return nil
		})
		if err != nil {
			return err
		}

		ctx.print(fmt.Sprintf("updated user %q", ctx.user.Username))
	}

	return nil
}

func handleUserDelete(ctx *serviceContext, params []string) error {
	if len(params) != 1 && len(params) != 2 {
		return fmt.Errorf("expected one or two arguments")
	}

	username := params[0]
	hashBytes := sha1.Sum([]byte(username))
	hash := fmt.Sprintf("%x", hashBytes[0:3])

	self := ctx.user != nil && ctx.user.Username == username

	if !ctx.admin && !self {
		return fmt.Errorf("only admins may delete other users")
	}

	u := ctx.srv.getUser(username)
	if u == nil {
		return fmt.Errorf("unknown username %q", username)
	}

	if len(params) < 2 {
		ctx.print(fmt.Sprintf(`To confirm user deletion, send "user delete %s %s"`, username, hash))
		return nil
	}

	if token := params[1]; token != hash {
		return fmt.Errorf("provided confirmation token doesn't match user")
	}

	var deleteCtx context.Context = ctx
	if self {
		ctx.print(fmt.Sprintf("Goodbye %s, deleting your account. There will be no further confirmation.", username))
		// We can't use ctx here, because it'll be cancelled once we close the
		// downstream connection
		deleteCtx = context.TODO()
	}

	if err := u.stop(deleteCtx); err != nil {
		return fmt.Errorf("failed to stop user: %v", err)
	}

	if err := ctx.srv.db.DeleteUser(deleteCtx, u.ID); err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	if !self {
		ctx.print(fmt.Sprintf("deleted user %q", username))
	}

	return nil
}

func handleUserRun(ctx *serviceContext, params []string) error {
	if len(params) < 2 {
		return fmt.Errorf("expected at least two arguments")
	}

	username := params[0]
	params = params[1:]
	if ctx.user != nil && username == ctx.user.Username {
		return handleServiceCommand(ctx, params)
	}

	u := ctx.srv.getUser(username)
	if u == nil {
		return fmt.Errorf("unknown username %q", username)
	}

	printCh := make(chan string, 1)
	retCh := make(chan error, 1)
	ev := eventUserRun{
		params: params,
		print:  printCh,
		ret:    retCh,
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case u.events <- ev:
	}
	for {
		select {
		case <-ctx.Done():
			// This handles a possible race condition:
			// - we send ev to u.events
			// - the user goroutine for u stops (because of a crash or user deletion)
			// - we would block on printCh
			// Quitting on ctx.Done() prevents us from blocking indefinitely
			// in case the event is never processed.
			// TODO: Properly fix this condition by flushing the u.events queue
			//       and running close(ev.print) in a defer
			return fmt.Errorf("timeout executing command")
		case text, ok := <-printCh:
			if ok {
				ctx.print(text)
			}
		case ret := <-retCh:
			return ret
		}
	}
}

func handleServiceChannelStatus(ctx *serviceContext, params []string) error {
	var defaultNetworkName string
	if ctx.network != nil {
		defaultNetworkName = ctx.network.GetName()
	}

	fs := newFlagSet()
	networkName := fs.String("network", defaultNetworkName, "")

	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}

	n := 0

	sendNetwork := func(net *network) {
		var channels []*database.Channel
		net.channels.ForEach(func(_ string, ch *database.Channel) {
			channels = append(channels, ch)
		})

		sort.Slice(channels, func(i, j int) bool {
			return strings.ReplaceAll(channels[i].Name, "#", "") <
				strings.ReplaceAll(channels[j].Name, "#", "")
		})

		for _, ch := range channels {
			var uch *upstreamChannel
			if net.conn != nil {
				uch = net.conn.channels.Get(ch.Name)
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
			ctx.print(s)

			n++
		}
	}

	if *networkName == "" {
		for _, net := range ctx.user.networks {
			sendNetwork(net)
		}
	} else {
		net := ctx.user.getNetwork(*networkName)
		if net == nil {
			return fmt.Errorf("unknown network %q", *networkName)
		}
		sendNetwork(net)
	}

	if n == 0 {
		ctx.print("No channel configured.")
	}

	return nil
}

func parseFilter(filter string) (database.MessageFilter, error) {
	switch filter {
	case "default":
		return database.FilterDefault, nil
	case "none":
		return database.FilterNone, nil
	case "highlight":
		return database.FilterHighlight, nil
	case "message":
		return database.FilterMessage, nil
	}
	return 0, fmt.Errorf("unknown filter: %q", filter)
}

type channelFlagSet struct {
	*flag.FlagSet
	Detached                                         *bool
	RelayDetached, ReattachOn, DetachAfter, DetachOn *string
}

func newChannelFlagSet() *channelFlagSet {
	fs := &channelFlagSet{FlagSet: newFlagSet()}
	fs.Var(boolPtrFlag{&fs.Detached}, "detached", "")
	fs.Var(stringPtrFlag{&fs.RelayDetached}, "relay-detached", "")
	fs.Var(stringPtrFlag{&fs.ReattachOn}, "reattach-on", "")
	fs.Var(stringPtrFlag{&fs.DetachAfter}, "detach-after", "")
	fs.Var(stringPtrFlag{&fs.DetachOn}, "detach-on", "")
	return fs
}

func (fs *channelFlagSet) update(channel *database.Channel) error {
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

func stripNetworkSuffix(ctx *serviceContext, name string) (string, *network, error) {
	if ctx.network != nil {
		return name, ctx.network, nil
	}

	l := strings.SplitN(name, "/", 2)
	if len(l) != 2 {
		return "", nil, fmt.Errorf("missing network name")
	}
	name = l[0]
	netName := l[1]

	for _, network := range ctx.user.networks {
		if netName == network.GetName() {
			return name, network, nil
		}
	}

	return "", nil, fmt.Errorf("unknown network %q", netName)
}

func handleServiceChannelUpdate(ctx *serviceContext, params []string) error {
	if len(params) < 1 {
		return fmt.Errorf("expected at least one argument")
	}
	name := params[0]

	fs := newChannelFlagSet()
	if err := fs.Parse(params[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument: %v", fs.Arg(0))
	}

	name, network, err := stripNetworkSuffix(ctx, name)
	if err != nil {
		return err
	}

	ch := network.channels.Get(name)
	if ch == nil {
		return fmt.Errorf("unknown channel %q", name)
	}

	if err := fs.update(ch); err != nil {
		return err
	}

	if fs.Detached != nil && *fs.Detached != ch.Detached {
		if *fs.Detached {
			network.detach(ch)
		} else {
			network.attach(ctx, ch)
		}
	}

	if network.conn != nil {
		network.conn.updateChannelAutoDetach(name)
	}

	if err := ctx.srv.db.StoreChannel(ctx, network.ID, ch); err != nil {
		return fmt.Errorf("failed to update channel: %v", err)
	}

	ctx.print(fmt.Sprintf("updated channel %q", name))
	return nil
}

func handleServiceChannelDelete(ctx *serviceContext, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}
	name := params[0]

	name, network, err := stripNetworkSuffix(ctx, name)
	if err != nil {
		return err
	}

	if err := network.deleteChannel(ctx, name); err != nil {
		return fmt.Errorf("failed to delete channel: %v", err)
	}

	if uc := network.conn; uc != nil && uc.channels.Has(name) {
		uc.SendMessage(ctx, &irc.Message{
			Command: "PART",
			Params:  []string{name},
		})
	}

	ctx.print(fmt.Sprintf("deleted channel %q", name))
	return nil
}

func handleServiceServerStatus(ctx *serviceContext, params []string) error {
	if len(params) != 0 {
		return fmt.Errorf("expected no argument")
	}

	dbStats, err := ctx.srv.db.Stats(ctx)
	if err != nil {
		return err
	}
	serverStats := ctx.srv.Stats()
	ctx.print(fmt.Sprintf("%v/%v users, %v downstreams, %v upstreams, %v networks, %v channels", serverStats.Users, dbStats.Users, serverStats.Downstreams, serverStats.Upstreams, dbStats.Networks, dbStats.Channels))
	return nil
}

func handleServiceServerNotice(ctx *serviceContext, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}
	text := params[0]

	var logger Logger
	if ctx.user != nil {
		logger = ctx.user.logger
	} else {
		logger = ctx.srv.Logger
	}
	logger.Printf("broadcasting bouncer-wide NOTICE: %v", text)

	broadcastMsg := &irc.Message{
		Prefix:  servicePrefix,
		Command: "NOTICE",
		Params:  []string{"$" + ctx.srv.Config().Hostname, text},
	}
	var err error
	sent := 0
	total := 0
	ctx.srv.forEachUser(func(u *user) {
		total++
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case u.events <- eventBroadcast{broadcastMsg}:
			sent++
		}
	})

	logger.Printf("broadcast bouncer-wide NOTICE to %v/%v downstreams", sent, total)
	ctx.print(fmt.Sprintf("sent to %v/%v downstream connections", sent, total))

	return err
}
