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

const (
	modeTypeA channelModeType = iota
	modeTypeB
	modeTypeC
	modeTypeD
)

var stdChannelModes = map[byte]channelModeType{
	'b': modeTypeA,
	'e': modeTypeA,
	'I': modeTypeA,
	'k': modeTypeB,
	'l': modeTypeC,
	'i': modeTypeD,
	'm': modeTypeD,
	'n': modeTypeD,
	's': modeTypeD,
	't': modeTypeD,
}

func ApplyChannelModes(modeTypes map[byte]channelModeType, modes map[byte]string, modeStr string, arguments ...string) error {
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
				var param string
				if len(arguments) <= nextArgument {
					// some sentitive arguments (such as channel keys) can be omitted for privacy
					// this will only happen for RPL_CHANNELMODEIS, never for MODE messages
					param = ""
				} else {
					param = arguments[nextArgument]
				}
				modes[mode] = param
			} else {
				delete(modes, mode)
			}
			nextArgument++
		} else if mt == modeTypeC || mt == modeTypeD {
			if plusMinus == '+' {
				modes[mode] = ""
			} else {
				delete(modes, mode)
			}
		}
	}
	return nil
}

func ChannelModeString(modes map[byte]string) (modeString string, parameters []string) {
	var modesWithValues strings.Builder
	var modesWithoutValues strings.Builder
	parameters = make([]string, 0, 16)
	for mode, value := range modes {
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
	{'q', '~'},
	{'a', '&'},
	{'o', '@'},
	{'h', '%'},
	{'v', '+'},
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
