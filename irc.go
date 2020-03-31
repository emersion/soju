package soju

import (
	"fmt"
	"strings"

	"gopkg.in/irc.v3"
)

const (
	rpl_statsping     = "246"
	rpl_localusers    = "265"
	rpl_globalusers   = "266"
	rpl_creationtime  = "329"
	rpl_topicwhotime  = "333"
	err_invalidcapcmd = "410"
)

type userModes string

func (ms userModes) Has(c byte) bool {
	return strings.IndexByte(string(ms), c) >= 0
}

func (ms *userModes) Add(c byte) {
	if !ms.Has(c) {
		*ms += userModes(c)
	}
}

func (ms *userModes) Del(c byte) {
	i := strings.IndexByte(string(*ms), c)
	if i >= 0 {
		*ms = (*ms)[:i] + (*ms)[i+1:]
	}
}

func (ms *userModes) Apply(s string) error {
	var plusMinus byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '+', '-':
			plusMinus = c
		default:
			switch plusMinus {
			case '+':
				ms.Add(c)
			case '-':
				ms.Del(c)
			default:
				return fmt.Errorf("malformed modestring %q: missing plus/minus", s)
			}
		}
	}
	return nil
}

type channelModeType byte

// standard channel mode types, as explained in https://modern.ircdocs.horse/#mode-message
const (
	// modes that add or remove an address to or from a list
	modeTypeA channelModeType = iota
	// modes that change a setting on a channel, and must always have a parameter
	modeTypeB
	// modes that change a setting on a channel, and must have a parameter when being set, and no parameter when being unset
	modeTypeC
	// modes that change a setting on a channel, and must not have a parameter
	modeTypeD
)

var stdChannelModes = map[byte]channelModeType{
	'b': modeTypeA, // ban list
	'e': modeTypeA, // ban exception list
	'I': modeTypeA, // invite exception list
	'k': modeTypeB, // channel key
	'l': modeTypeC, // channel user limit
	'i': modeTypeD, // channel is invite-only
	'm': modeTypeD, // channel is moderated
	'n': modeTypeD, // channel has no external messages
	's': modeTypeD, // channel is secret
	't': modeTypeD, // channel has protected topic
}

type channelModes map[byte]string

func (cm channelModes) Apply(modeTypes map[byte]channelModeType, modeStr string, arguments ...string) error {
	nextArgument := 0
	var plusMinus byte
	for i := 0; i < len(modeStr); i++ {
		mode := modeStr[i]
		if mode == '+' || mode == '-' {
			plusMinus = mode
			continue
		}
		if plusMinus != '+' && plusMinus != '-' {
			return fmt.Errorf("malformed modestring %q: missing plus/minus", modeStr)
		}

		mt, ok := modeTypes[mode]
		if !ok {
			continue
		}
		if mt == modeTypeB || (mt == modeTypeC && plusMinus == '+') {
			if plusMinus == '+' {
				var argument string
				// some sentitive arguments (such as channel keys) can be omitted for privacy
				// (this will only happen for RPL_CHANNELMODEIS, never for MODE messages)
				if nextArgument < len(arguments) {
					argument = arguments[nextArgument]
				}
				cm[mode] = argument
			} else {
				delete(cm, mode)
			}
			nextArgument++
		} else if mt == modeTypeC || mt == modeTypeD {
			if plusMinus == '+' {
				cm[mode] = ""
			} else {
				delete(cm, mode)
			}
		}
	}
	return nil
}

func (cm channelModes) Format() (modeString string, parameters []string) {
	var modesWithValues strings.Builder
	var modesWithoutValues strings.Builder
	parameters = make([]string, 0, 16)
	for mode, value := range cm {
		if value != "" {
			modesWithValues.WriteString(string(mode))
			parameters = append(parameters, value)
		} else {
			modesWithoutValues.WriteString(string(mode))
		}
	}
	modeString = "+" + modesWithValues.String() + modesWithoutValues.String()
	return
}

const stdChannelTypes = "#&+!"

type channelStatus byte

const (
	channelPublic  channelStatus = '='
	channelSecret  channelStatus = '@'
	channelPrivate channelStatus = '*'
)

func parseChannelStatus(s string) (channelStatus, error) {
	if len(s) > 1 {
		return 0, fmt.Errorf("invalid channel status %q: more than one character", s)
	}
	switch cs := channelStatus(s[0]); cs {
	case channelPublic, channelSecret, channelPrivate:
		return cs, nil
	default:
		return 0, fmt.Errorf("invalid channel status %q: unknown status", s)
	}
}

type membership struct {
	Mode   byte
	Prefix byte
}

var stdMemberships = []membership{
	{'q', '~'}, // founder
	{'a', '&'}, // protected
	{'o', '@'}, // operator
	{'h', '%'}, // halfop
	{'v', '+'}, // voice
}

func (m *membership) String() string {
	if m == nil {
		return ""
	}
	return string(m.Prefix)
}

func parseMessageParams(msg *irc.Message, out ...*string) error {
	if len(msg.Params) < len(out) {
		return newNeedMoreParamsError(msg.Command)
	}
	for i := range out {
		if out[i] != nil {
			*out[i] = msg.Params[i]
		}
	}
	return nil
}

type batch struct {
	Type   string
	Params []string
	Outer  *batch // if not-nil, this batch is nested in Outer
	Label  string
}

// The server-time layout, as defined in the IRCv3 spec.
const serverTimeLayout = "2006-01-02T15:04:05.000Z"
