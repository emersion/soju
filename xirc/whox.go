package xirc

import (
	"gopkg.in/irc.v4"

	"fmt"
	"strings"
)

// whoxFields is the list of all WHOX field letters, by order of appearance in
// RPL_WHOSPCRPL messages.
var whoxFields = []byte("tcuihsnfdlaor")

type WHOXInfo struct {
	Token    string
	Username string
	Hostname string
	Server   string
	Nickname string
	Flags    string
	Account  string
	Realname string
}

func (info *WHOXInfo) get(k byte) string {
	switch k {
	case 't':
		return info.Token
	case 'c':
		return "*"
	case 'u':
		return info.Username
	case 'i':
		return "255.255.255.255"
	case 'h':
		return info.Hostname
	case 's':
		return info.Server
	case 'n':
		return info.Nickname
	case 'f':
		return info.Flags
	case 'd':
		return "0"
	case 'l': // idle time
		return "0"
	case 'a':
		account := "0" // WHOX uses "0" to mean "no account"
		if info.Account != "" && info.Account != "*" {
			account = info.Account
		}
		return account
	case 'o':
		return "0"
	case 'r':
		return info.Realname
	}
	return ""
}

func (info *WHOXInfo) set(k byte, v string) {
	switch k {
	case 't':
		info.Token = v
	case 'u':
		info.Username = v
	case 'h':
		info.Hostname = v
	case 's':
		info.Server = v
	case 'n':
		info.Nickname = v
	case 'f':
		info.Flags = v
	case 'a':
		info.Account = v
	case 'r':
		info.Realname = v
	}
}

func GenerateWHOXReply(prefix *irc.Prefix, nick, fields string, info *WHOXInfo) *irc.Message {
	if fields == "" {
		return &irc.Message{
			Prefix:  prefix,
			Command: irc.RPL_WHOREPLY,
			Params:  []string{nick, "*", info.Username, info.Hostname, info.Server, info.Nickname, info.Flags, "0 " + info.Realname},
		}
	}

	fieldSet := make(map[byte]bool)
	for i := 0; i < len(fields); i++ {
		fieldSet[fields[i]] = true
	}

	var values []string
	for _, field := range whoxFields {
		if !fieldSet[field] {
			continue
		}
		values = append(values, info.get(field))
	}

	return &irc.Message{
		Prefix:  prefix,
		Command: RPL_WHOSPCRPL,
		Params:  append([]string{nick}, values...),
	}
}

func ParseWHOXOptions(options string) (fields, whoxToken string) {
	optionsParts := strings.SplitN(options, "%", 2)
	// TODO: add support for WHOX flags in optionsParts[0]
	if len(optionsParts) == 2 {
		optionsParts := strings.SplitN(optionsParts[1], ",", 2)
		fields = strings.ToLower(optionsParts[0])
		if len(optionsParts) == 2 && strings.Contains(fields, "t") {
			whoxToken = optionsParts[1]
		}
	}
	return fields, whoxToken
}

func ParseWHOXReply(msg *irc.Message, fields string) (*WHOXInfo, error) {
	if msg.Command != RPL_WHOSPCRPL {
		return nil, fmt.Errorf("invalid WHOX reply %q", msg.Command)
	} else if len(msg.Params) == 0 {
		return nil, fmt.Errorf("invalid RPL_WHOSPCRPL: no params")
	}

	fieldSet := make(map[byte]bool)
	for i := 0; i < len(fields); i++ {
		fieldSet[fields[i]] = true
	}

	var info WHOXInfo
	values := msg.Params[1:]
	for _, field := range whoxFields {
		if !fieldSet[field] {
			continue
		}

		if len(values) == 0 {
			return nil, fmt.Errorf("invalid RPL_WHOSPCRPL: missing value for field %q", string(field))
		}

		info.set(field, values[0])
		values = values[1:]
	}

	return &info, nil
}
