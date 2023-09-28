// Package xirc contains an extended IRC library.
package xirc

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/irc.v4"
)

const (
	maxMessageLength = 512
	maxMessageParams = 15
)

const MaxSASLLength = 400

const (
	RPL_STATSPING     = "246"
	RPL_LOCALUSERS    = "265"
	RPL_GLOBALUSERS   = "266"
	RPL_WHOISCERTFP   = "276"
	RPL_WHOISREGNICK  = "307"
	RPL_WHOISSPECIAL  = "320"
	RPL_CREATIONTIME  = "329"
	RPL_WHOISACCOUNT  = "330"
	RPL_TOPICWHOTIME  = "333"
	RPL_WHOISTEXT     = "337"
	RPL_WHOISACTUALLY = "338"
	RPL_WHOSPCRPL     = "354"
	RPL_WHOISHOST     = "378"
	RPL_WHOISMODES    = "379"
	RPL_VISIBLEHOST   = "396"
	ERR_UNKNOWNERROR  = "400"
	ERR_INVALIDCAPCMD = "410"
	RPL_WHOISSECURE   = "671"

	// https://ircv3.net/specs/extensions/bot-mode
	RPL_WHOISBOT = "335"
)

// The server-time layout, as defined in the IRCv3 spec.
const ServerTimeLayout = "2006-01-02T15:04:05.000Z"

// FormatServerTime formats a time with the server-time layout.
func FormatServerTime(t time.Time) string {
	return t.UTC().Format(ServerTimeLayout)
}

// ParseCTCPMessage parses a CTCP message. CTCP is defined in
// https://tools.ietf.org/html/draft-oakley-irc-ctcp-02
func ParseCTCPMessage(msg *irc.Message) (cmd string, params string, ok bool) {
	if (msg.Command != "PRIVMSG" && msg.Command != "NOTICE") || len(msg.Params) < 2 {
		return "", "", false
	}
	text := msg.Params[1]

	if !strings.HasPrefix(text, "\x01") {
		return "", "", false
	}
	text = strings.Trim(text, "\x01")

	words := strings.SplitN(text, " ", 2)
	cmd = strings.ToUpper(words[0])
	if len(words) > 1 {
		params = words[1]
	}

	return cmd, params, true
}

type ChannelStatus byte

const (
	ChannelPublic  ChannelStatus = '='
	ChannelSecret  ChannelStatus = '@'
	ChannelPrivate ChannelStatus = '*'
)

func ParseChannelStatus(s string) (ChannelStatus, error) {
	if len(s) > 1 {
		return 0, fmt.Errorf("invalid channel status %q: more than one character", s)
	}
	switch cs := ChannelStatus(s[0]); cs {
	case ChannelPublic, ChannelSecret, ChannelPrivate:
		return cs, nil
	default:
		return 0, fmt.Errorf("invalid channel status %q: unknown status", s)
	}
}

// Membership is a channel member rank.
type Membership struct {
	Mode   byte
	Prefix byte
}

// MembershipSet is a set of memberships sorted by descending rank.
type MembershipSet []Membership

func (ms *MembershipSet) Add(availableMemberships []Membership, newMembership Membership) {
	l := *ms
	i := 0
	for _, availableMembership := range availableMemberships {
		if i >= len(l) {
			break
		}
		if l[i] == availableMembership {
			if availableMembership == newMembership {
				// we already have this membership
				return
			}
			i++
			continue
		}
		if availableMembership == newMembership {
			break
		}
	}
	// insert newMembership at i
	l = append(l, Membership{})
	copy(l[i+1:], l[i:])
	l[i] = newMembership
	*ms = l
}

func (ms *MembershipSet) Remove(membership Membership) {
	l := *ms
	for i, m := range l {
		if m == membership {
			*ms = append(l[:i], l[i+1:]...)
			return
		}
	}
}
