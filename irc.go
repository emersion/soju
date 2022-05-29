package soju

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/irc.v3"

	"git.sr.ht/~emersion/soju/database"
	"git.sr.ht/~emersion/soju/xirc"
)

// TODO: generalize and move helpers to the xirc package

const maxSASLLength = 400

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
//
// needMarshaling is a list of indexes of mode arguments that represent entities
// that must be marshaled when sent downstream.
func applyChannelModes(ch *upstreamChannel, modeStr string, arguments []string) (needMarshaling map[int]struct{}, err error) {
	needMarshaling = make(map[int]struct{}, len(arguments))
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
			return nil, fmt.Errorf("malformed modestring %q: missing plus/minus", modeStr)
		}

		for _, membership := range ch.conn.availableMemberships {
			if membership.Mode == mode {
				if nextArgument >= len(arguments) {
					return nil, fmt.Errorf("malformed modestring %q: missing mode argument for %c%c", modeStr, plusMinus, mode)
				}
				member := arguments[nextArgument]
				m := ch.Members.Value(member)
				if m != nil {
					if plusMinus == '+' {
						m.Add(ch.conn.availableMemberships, membership)
					} else {
						// TODO: for upstreams without multi-prefix, query the user modes again
						m.Remove(membership)
					}
				}
				needMarshaling[nextArgument] = struct{}{}
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
	return needMarshaling, nil
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

// memberships always sorted by descending membership rank
type memberships []membership

func (m *memberships) Add(availableMemberships []membership, newMembership membership) {
	l := *m
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
	l = append(l, membership{})
	copy(l[i+1:], l[i:])
	l[i] = newMembership
	*m = l
}

func (m *memberships) Remove(oldMembership membership) {
	l := *m
	for i, currentMembership := range l {
		if currentMembership == oldMembership {
			*m = append(l[:i], l[i+1:]...)
			return
		}
	}
}

func (m memberships) Format(dc *downstreamConn) string {
	if !dc.caps.IsEnabled("multi-prefix") {
		if len(m) == 0 {
			return ""
		}
		return string(m[0].Prefix)
	}
	prefixes := make([]byte, len(m))
	for i, membership := range m {
		prefixes[i] = membership.Prefix
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

type batch struct {
	Type   string
	Params []string
	Outer  *batch // if not-nil, this batch is nested in Outer
	Label  string
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
	innerMap map[string]casemapEntry
	casemap  casemapping
}

type casemapEntry struct {
	originalKey string
	value       interface{}
}

func newCasemapMap(size int) casemapMap {
	return casemapMap{
		innerMap: make(map[string]casemapEntry, size),
		casemap:  casemapNone,
	}
}

func (cm *casemapMap) OriginalKey(name string) (key string, ok bool) {
	entry, ok := cm.innerMap[cm.casemap(name)]
	if !ok {
		return "", false
	}
	return entry.originalKey, true
}

func (cm *casemapMap) Has(name string) bool {
	_, ok := cm.innerMap[cm.casemap(name)]
	return ok
}

func (cm *casemapMap) Len() int {
	return len(cm.innerMap)
}

func (cm *casemapMap) SetValue(name string, value interface{}) {
	nameCM := cm.casemap(name)
	entry, ok := cm.innerMap[nameCM]
	if !ok {
		cm.innerMap[nameCM] = casemapEntry{
			originalKey: name,
			value:       value,
		}
		return
	}
	entry.value = value
	cm.innerMap[nameCM] = entry
}

func (cm *casemapMap) Delete(name string) {
	delete(cm.innerMap, cm.casemap(name))
}

func (cm *casemapMap) SetCasemapping(newCasemap casemapping) {
	cm.casemap = newCasemap
	newInnerMap := make(map[string]casemapEntry, len(cm.innerMap))
	for _, entry := range cm.innerMap {
		newInnerMap[cm.casemap(entry.originalKey)] = entry
	}
	cm.innerMap = newInnerMap
}

type upstreamChannelCasemapMap struct{ casemapMap }

func (cm *upstreamChannelCasemapMap) Value(name string) *upstreamChannel {
	entry, ok := cm.innerMap[cm.casemap(name)]
	if !ok {
		return nil
	}
	return entry.value.(*upstreamChannel)
}

type channelCasemapMap struct{ casemapMap }

func (cm *channelCasemapMap) Value(name string) *database.Channel {
	entry, ok := cm.innerMap[cm.casemap(name)]
	if !ok {
		return nil
	}
	return entry.value.(*database.Channel)
}

type membershipsCasemapMap struct{ casemapMap }

func (cm *membershipsCasemapMap) Value(name string) *memberships {
	entry, ok := cm.innerMap[cm.casemap(name)]
	if !ok {
		return nil
	}
	return entry.value.(*memberships)
}

type deliveredCasemapMap struct{ casemapMap }

func (cm *deliveredCasemapMap) Value(name string) deliveredClientMap {
	entry, ok := cm.innerMap[cm.casemap(name)]
	if !ok {
		return nil
	}
	return entry.value.(deliveredClientMap)
}

type monitorCasemapMap struct{ casemapMap }

func (cm *monitorCasemapMap) Value(name string) (online bool) {
	entry, ok := cm.innerMap[cm.casemap(name)]
	if !ok {
		return false
	}
	return entry.value.(bool)
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

// whoxFields is the list of all WHOX field letters, by order of appearance in
// RPL_WHOSPCRPL messages.
var whoxFields = []byte("tcuihsnfdlaor")

type whoxInfo struct {
	Token    string
	Username string
	Hostname string
	Server   string
	Nickname string
	Flags    string
	Account  string
	Realname string
}

func (info *whoxInfo) get(field byte) string {
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

func generateWHOXReply(prefix *irc.Prefix, nick, fields string, info *whoxInfo) *irc.Message {
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
		Command: xirc.RPL_WHOSPCRPL,
		Params:  append([]string{nick}, values...),
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
