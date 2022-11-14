package soju

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/irc.v4"

	"git.sr.ht/~emersion/soju/database"
	"git.sr.ht/~emersion/soju/xirc"
)

// TODO: generalize and move helpers to the xirc package

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

// applyChannelModes parses a mode string and mode arguments from a MODE message,
// and applies the corresponding channel mode and user membership changes on that channel.
//
// If ch.modes is nil, channel modes are not updated.
func applyChannelModes(ch *upstreamChannel, modeStr string, arguments []string) error {
	nextArgument := 0
	var plusMinus byte
outer:
	for i := 0; i < len(modeStr); i++ {
		mode := modeStr[i]
		if mode == '+' || mode == '-' {
			plusMinus = mode
			continue
		}
		if plusMinus != '+' && plusMinus != '-' {
			return fmt.Errorf("malformed modestring %q: missing plus/minus", modeStr)
		}

		for _, membership := range ch.conn.availableMemberships {
			if membership.Mode == mode {
				if nextArgument >= len(arguments) {
					return fmt.Errorf("malformed modestring %q: missing mode argument for %c%c", modeStr, plusMinus, mode)
				}
				member := arguments[nextArgument]
				m := ch.Members.Get(member)
				if m != nil {
					if plusMinus == '+' {
						m.Add(ch.conn.availableMemberships, membership)
					} else {
						// TODO: for upstreams without multi-prefix, query the user modes again
						m.Remove(membership)
					}
				}
				nextArgument++
				continue outer
			}
		}

		mt, ok := ch.conn.availableChannelModes[mode]
		if !ok {
			continue
		}
		if mt == modeTypeA {
			nextArgument++
		} else if mt == modeTypeB || (mt == modeTypeC && plusMinus == '+') {
			if plusMinus == '+' {
				var argument string
				// some sentitive arguments (such as channel keys) can be omitted for privacy
				// (this will only happen for RPL_CHANNELMODEIS, never for MODE messages)
				if nextArgument < len(arguments) {
					argument = arguments[nextArgument]
				}
				if ch.modes != nil {
					ch.modes[mode] = argument
				}
			} else {
				delete(ch.modes, mode)
			}
			nextArgument++
		} else if mt == modeTypeC || mt == modeTypeD {
			if plusMinus == '+' {
				if ch.modes != nil {
					ch.modes[mode] = ""
				}
			} else {
				delete(ch.modes, mode)
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

var stdMemberships = []xirc.Membership{
	{'q', '~'}, // founder
	{'a', '&'}, // protected
	{'o', '@'}, // operator
	{'h', '%'}, // halfop
	{'v', '+'}, // voice
}

func formatMemberPrefix(ms xirc.MembershipSet, dc *downstreamConn) string {
	if !dc.caps.IsEnabled("multi-prefix") {
		if len(ms) == 0 {
			return ""
		}
		return string(ms[0].Prefix)
	}
	prefixes := make([]byte, len(ms))
	for i, m := range ms {
		prefixes[i] = m.Prefix
	}
	return string(prefixes)
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

func copyClientTags(tags irc.Tags) irc.Tags {
	t := make(irc.Tags, len(tags))
	for k, v := range tags {
		if strings.HasPrefix(k, "+") {
			t[k] = v
		}
	}
	return t
}

type casemapping func(string) string

func casemapNone(name string) string {
	return name
}

// CasemapASCII of name is the canonical representation of name according to the
// ascii casemapping.
func casemapASCII(name string) string {
	nameBytes := []byte(name)
	for i, r := range nameBytes {
		if 'A' <= r && r <= 'Z' {
			nameBytes[i] = r + 'a' - 'A'
		}
	}
	return string(nameBytes)
}

// casemapRFC1459 of name is the canonical representation of name according to the
// rfc1459 casemapping.
func casemapRFC1459(name string) string {
	nameBytes := []byte(name)
	for i, r := range nameBytes {
		if 'A' <= r && r <= 'Z' {
			nameBytes[i] = r + 'a' - 'A'
		} else if r == '{' {
			nameBytes[i] = '['
		} else if r == '}' {
			nameBytes[i] = ']'
		} else if r == '\\' {
			nameBytes[i] = '|'
		} else if r == '~' {
			nameBytes[i] = '^'
		}
	}
	return string(nameBytes)
}

// casemapRFC1459Strict of name is the canonical representation of name
// according to the rfc1459-strict casemapping.
func casemapRFC1459Strict(name string) string {
	nameBytes := []byte(name)
	for i, r := range nameBytes {
		if 'A' <= r && r <= 'Z' {
			nameBytes[i] = r + 'a' - 'A'
		} else if r == '{' {
			nameBytes[i] = '['
		} else if r == '}' {
			nameBytes[i] = ']'
		} else if r == '\\' {
			nameBytes[i] = '|'
		}
	}
	return string(nameBytes)
}

func parseCasemappingToken(tokenValue string) (casemap casemapping, ok bool) {
	switch tokenValue {
	case "ascii":
		casemap = casemapASCII
	case "rfc1459":
		casemap = casemapRFC1459
	case "rfc1459-strict":
		casemap = casemapRFC1459Strict
	default:
		return nil, false
	}
	return casemap, true
}

func partialCasemap(higher casemapping, name string) string {
	nameFullyCM := []byte(higher(name))
	nameBytes := []byte(name)
	for i, r := range nameBytes {
		if !('A' <= r && r <= 'Z') && !('a' <= r && r <= 'z') {
			nameBytes[i] = nameFullyCM[i]
		}
	}
	return string(nameBytes)
}

type casemapMap struct {
	m       map[string]casemapEntry
	casemap casemapping
}

type casemapEntry struct {
	originalKey string
	value       interface{}
}

func newCasemapMap() casemapMap {
	return casemapMap{
		m:       make(map[string]casemapEntry),
		casemap: casemapNone,
	}
}

func (cm *casemapMap) Has(name string) bool {
	_, ok := cm.m[cm.casemap(name)]
	return ok
}

func (cm *casemapMap) Len() int {
	return len(cm.m)
}

func (cm *casemapMap) get(name string) interface{} {
	entry, ok := cm.m[cm.casemap(name)]
	if !ok {
		return nil
	}
	return entry.value
}

func (cm *casemapMap) set(name string, value interface{}) {
	nameCM := cm.casemap(name)
	entry, ok := cm.m[nameCM]
	if !ok {
		cm.m[nameCM] = casemapEntry{
			originalKey: name,
			value:       value,
		}
		return
	}
	entry.value = value
	cm.m[nameCM] = entry
}

func (cm *casemapMap) Del(name string) {
	delete(cm.m, cm.casemap(name))
}

func (cm *casemapMap) SetCasemapping(newCasemap casemapping) {
	cm.casemap = newCasemap
	m := make(map[string]casemapEntry, len(cm.m))
	for _, entry := range cm.m {
		m[cm.casemap(entry.originalKey)] = entry
	}
	cm.m = m
}

type upstreamChannelCasemapMap struct{ casemapMap }

func (cm *upstreamChannelCasemapMap) Get(name string) *upstreamChannel {
	if v := cm.get(name); v == nil {
		return nil
	} else {
		return v.(*upstreamChannel)
	}
}

func (cm *upstreamChannelCasemapMap) Set(uch *upstreamChannel) {
	cm.set(uch.Name, uch)
}

func (cm *upstreamChannelCasemapMap) ForEach(f func(*upstreamChannel)) {
	for _, entry := range cm.m {
		f(entry.value.(*upstreamChannel))
	}
}

type channelCasemapMap struct{ casemapMap }

func (cm *channelCasemapMap) Get(name string) *database.Channel {
	if v := cm.get(name); v == nil {
		return nil
	} else {
		return v.(*database.Channel)
	}
}

func (cm *channelCasemapMap) Set(ch *database.Channel) {
	cm.set(ch.Name, ch)
}

func (cm *channelCasemapMap) ForEach(f func(*database.Channel)) {
	for _, entry := range cm.m {
		f(entry.value.(*database.Channel))
	}
}

type membershipsCasemapMap struct{ casemapMap }

func (cm *membershipsCasemapMap) Get(name string) *xirc.MembershipSet {
	if v := cm.get(name); v == nil {
		return nil
	} else {
		return v.(*xirc.MembershipSet)
	}
}

func (cm *membershipsCasemapMap) Set(name string, ms *xirc.MembershipSet) {
	cm.set(name, ms)
}

func (cm *membershipsCasemapMap) ForEach(f func(string, *xirc.MembershipSet)) {
	for _, entry := range cm.m {
		f(entry.originalKey, entry.value.(*xirc.MembershipSet))
	}
}

type deliveredCasemapMap struct{ casemapMap }

func (cm *deliveredCasemapMap) Get(name string) deliveredClientMap {
	if v := cm.get(name); v == nil {
		return nil
	} else {
		return v.(deliveredClientMap)
	}
}

func (cm *deliveredCasemapMap) Set(name string, m deliveredClientMap) {
	cm.set(name, m)
}

func (cm *deliveredCasemapMap) ForEach(f func(string, deliveredClientMap)) {
	for _, entry := range cm.m {
		f(entry.originalKey, entry.value.(deliveredClientMap))
	}
}

type monitorCasemapMap struct{ casemapMap }

func (cm *monitorCasemapMap) Get(name string) (online bool) {
	if v := cm.get(name); v == nil {
		return false
	} else {
		return v.(bool)
	}
}

func (cm *monitorCasemapMap) Set(name string, online bool) {
	cm.set(name, online)
}

func (cm *monitorCasemapMap) ForEach(f func(name string, online bool)) {
	for _, entry := range cm.m {
		f(entry.originalKey, entry.value.(bool))
	}
}

type casemapSet struct{ casemapMap }

func (cs *casemapSet) Add(name string) {
	cs.set(name, nil)
}

func isWordBoundary(r rune) bool {
	switch r {
	case '-', '_', '|': // inspired from weechat.look.highlight_regex
		return false
	default:
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	}
}

func isHighlight(text, nick string) bool {
	for {
		i := strings.Index(text, nick)
		if i < 0 {
			return false
		}

		left, _ := utf8.DecodeLastRuneInString(text[:i])
		right, _ := utf8.DecodeRuneInString(text[i+len(nick):])
		if isWordBoundary(left) && isWordBoundary(right) {
			return true
		}

		text = text[i+len(nick):]
	}
}

// parseChatHistoryBound parses the given CHATHISTORY parameter as a bound.
// The zero time is returned on error.
func parseChatHistoryBound(param string) time.Time {
	parts := strings.SplitN(param, "=", 2)
	if len(parts) != 2 {
		return time.Time{}
	}
	switch parts[0] {
	case "timestamp":
		timestamp, err := time.Parse(xirc.ServerTimeLayout, parts[1])
		if err != nil {
			return time.Time{}
		}
		return timestamp
	default:
		return time.Time{}
	}
}

func isNumeric(cmd string) bool {
	if len(cmd) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if cmd[i] < '0' || cmd[i] > '9' {
			return false
		}
	}
	return true
}
