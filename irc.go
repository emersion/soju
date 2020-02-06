package jounce

import (
	"fmt"
	"strings"
)

const (
	rpl_localusers   = "265"
	rpl_globalusers  = "266"
	rpl_topicwhotime = "333"
)

type modeSet string

func (ms modeSet) Has(c byte) bool {
	return strings.IndexByte(string(ms), c) >= 0
}

func (ms *modeSet) Add(c byte) {
	if !ms.Has(c) {
		*ms += modeSet(c)
	}
}

func (ms *modeSet) Del(c byte) {
	i := strings.IndexByte(string(*ms), c)
	if i >= 0 {
		*ms = (*ms)[:i] + (*ms)[i+1:]
	}
}

func (ms *modeSet) Apply(s string) error {
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

type membership byte

const (
	membershipFounder   membership = '~'
	membershipProtected membership = '&'
	membershipOperator  membership = '@'
	membershipHalfOp    membership = '%'
	membershipVoice     membership = '+'
)

const stdMembershipPrefixes = "~&@%+"

func parseMembershipPrefix(s string) (prefix membership, nick string) {
	// TODO: any prefix from PREFIX RPL_ISUPPORT
	if strings.IndexByte(stdMembershipPrefixes, s[0]) >= 0 {
		return membership(s[0]), s[1:]
	} else {
		return 0, s
	}
}
