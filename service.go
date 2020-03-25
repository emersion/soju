package soju

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/google/shlex"
	"gopkg.in/irc.v3"
)

const serviceNick = "BouncerServ"

type serviceCommandSet map[string]*serviceCommand

type serviceCommand struct {
	usage    string
	desc     string
	handle   func(dc *downstreamConn, params []string) error
	children serviceCommandSet
}

func sendServicePRIVMSG(dc *downstreamConn, text string) {
	dc.SendMessage(&irc.Message{
		Prefix:  &irc.Prefix{Name: serviceNick},
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
					usage:  "-addr <addr> [-name name] [-username username] [-pass pass] [-realname realname] [-nick nick]",
					desc:   "add a new network",
					handle: handleServiceCreateNetwork,
				},
				"status": {
					desc:   "show a list of saved networks and their current status",
					handle: handleServiceNetworkStatus,
				},
			},
		},
	}
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

func handleServiceCreateNetwork(dc *downstreamConn, params []string) error {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.SetOutput(ioutil.Discard)
	addr := fs.String("addr", "", "")
	name := fs.String("name", "", "")
	username := fs.String("username", "", "")
	pass := fs.String("pass", "", "")
	realname := fs.String("realname", "", "")
	nick := fs.String("nick", "", "")

	if err := fs.Parse(params); err != nil {
		return err
	}
	if *addr == "" {
		return fmt.Errorf("flag -addr is required")
	}

	if *nick == "" {
		*nick = dc.nick
	}

	var err error
	network, err := dc.user.createNetwork(&Network{
		Addr:     *addr,
		Name:     *name,
		Username: *username,
		Pass:     *pass,
		Realname: *realname,
		Nick:     *nick,
	})
	if err != nil {
		return fmt.Errorf("could not create network: %v", err)
	}

	sendServicePRIVMSG(dc, fmt.Sprintf("created network %s successfully", network.GetName()))
	return nil
}

func handleServiceNetworkStatus(dc *downstreamConn, params []string) error {
	dc.user.forEachNetwork(func(net *network) {
		var statuses []string
		var details string
		if uc := net.upstream(); uc != nil {
			statuses = append(statuses, "connected as "+uc.nick)
			details = fmt.Sprintf("%v channels", len(uc.channels))
		} else {
			statuses = append(statuses, "disconnected")
		}

		if net == dc.network {
			statuses = append(statuses, "current")
		}

		s := fmt.Sprintf("%v (%v) [%v]", net.GetName(), net.Addr, strings.Join(statuses, ", "))
		if details != "" {
			s += ": " + details
		}
		sendServicePRIVMSG(dc, s)
	})
	return nil
}
