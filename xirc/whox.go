package xirc

import (
	"gopkg.in/irc.v3"
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

func (info *WHOXInfo) get(field byte) string {
	switch field {
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
