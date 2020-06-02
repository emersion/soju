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
	"strings"
	"time"

	"github.com/google/shlex"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/irc.v3"
)

const serviceNick = "BouncerServ"

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

func handleServicePRIVMSG(dc *downstreamConn, text string) {
	words, err := shlex.Split(text)
	if err != nil {
		sendServicePRIVMSG(dc, fmt.Sprintf("error: failed to parse command: %v", err))
		return
	}

	cmd, params, err := serviceCommands.Get(words)
	if err != nil {
		sendServicePRIVMSG(dc, fmt.Sprintf(`error: %v (type "help" for a list of commands)`, err))
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
					usage:  "-addr <addr> [-name name] [-username username] [-pass pass] [-realname realname] [-nick nick] [-connect-command command]...",
					desc:   "add a new network",
					handle: handleServiceCreateNetwork,
				},
				"status": {
					desc:   "show a list of saved networks and their current status",
					handle: handleServiceNetworkStatus,
				},
				"update": {
					usage: "[-addr addr] [-name name] [-username username] [-pass pass] [-realname realname] [-nick nick] [-connect-command command]...",
					desc:  "update a network",
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
				"reset": {
					usage:  "<network name>",
					desc:   "disable SASL EXTERNAL authentication and remove stored certificate",
					handle: handleServiceCertfpReset,
				},
			},
		},
		"change-password": {
			usage:  "<new password>",
			desc:   "change your password",
			handle: handlePasswordChange,
		},
	}
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

	if err := dc.srv.db.StoreNetwork(net.Username, &net.Network); err != nil {
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

func handleServiceCertfpReset(dc *downstreamConn, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}

	net := dc.user.getNetwork(params[0])
	if net == nil {
		return fmt.Errorf("unknown network %q", params[0])
	}

	net.SASL.External.CertBlob = nil
	net.SASL.External.PrivKeyBlob = nil

	if net.SASL.Mechanism == "EXTERNAL" {
		net.SASL.Mechanism = ""
	}
	if err := dc.srv.db.StoreNetwork(dc.user.Username, &net.Network); err != nil {
		return err
	}

	sendServicePRIVMSG(dc, "certificate reset")
	return nil
}

func appendServiceCommandSetHelp(cmds serviceCommandSet, prefix []string, l *[]string) {
	for name, cmd := range cmds {
		words := append(prefix, name)
		if len(cmd.children) == 0 {
			s := strings.Join(words, " ")
			*l = append(*l, s)
		} else {
			appendServiceCommandSetHelp(cmd.children, words, l)
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
			appendServiceCommandSetHelp(cmd.children, words, &l)
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
		appendServiceCommandSetHelp(serviceCommands, nil, &l)
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
	if *f.ptr == nil {
		return ""
	}
	return **f.ptr
}

func (f stringPtrFlag) Set(s string) error {
	*f.ptr = &s
	return nil
}

type networkFlagSet struct {
	*flag.FlagSet
	Addr, Name, Nick, Username, Pass, Realname *string
	ConnectCommands []string
}

func newNetworkFlagSet() *networkFlagSet {
	fs := &networkFlagSet{FlagSet: newFlagSet()}
	fs.Var(stringPtrFlag{&fs.Addr}, "addr", "")
	fs.Var(stringPtrFlag{&fs.Name}, "name", "")
	fs.Var(stringPtrFlag{&fs.Nick}, "nick", "")
	fs.Var(stringPtrFlag{&fs.Username}, "username", "")
	fs.Var(stringPtrFlag{&fs.Pass}, "pass", "")
	fs.Var(stringPtrFlag{&fs.Realname}, "realname", "")
	fs.Var((*stringSliceFlag)(&fs.ConnectCommands), "connect-command", "")
	return fs
}

func (fs *networkFlagSet) update(network *Network) error {
	if fs.Addr != nil {
		if addrParts := strings.SplitN(*fs.Addr, "://", 2); len(addrParts) == 2 {
			scheme := addrParts[0]
			switch scheme {
			case "ircs", "irc+insecure":
			default:
				return fmt.Errorf("unknown scheme %q (supported schemes: ircs, irc+insecure)", scheme)
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

func handleServiceCreateNetwork(dc *downstreamConn, params []string) error {
	fs := newNetworkFlagSet()
	if err := fs.Parse(params); err != nil {
		return err
	}
	if fs.Addr == nil {
		return fmt.Errorf("flag -addr is required")
	}

	record := &Network{
		Addr: *fs.Addr,
		Nick: dc.nick,
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
	dc.user.forEachNetwork(func(net *network) {
		var statuses []string
		var details string
		if uc := net.conn; uc != nil {
			if dc.nick != uc.nick {
				statuses = append(statuses, "connected as "+uc.nick)
			} else {
				statuses = append(statuses, "connected")
			}
			details = fmt.Sprintf("%v channels", len(uc.channels))
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
	})
	return nil
}

func handleServiceNetworkUpdate(dc *downstreamConn, params []string) error {
	if len(params) < 1 {
		return fmt.Errorf("expected exactly one argument")
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

func handlePasswordChange(dc *downstreamConn, params []string) error {
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(params[0]), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	if err := dc.user.updatePassword(string(hashed)); err != nil {
		return err
	}

	sendServicePRIVMSG(dc, "password updated")
	return nil
}
