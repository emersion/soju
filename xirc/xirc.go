// Package xirc contains an extended IRC library.
package xirc

import (
	"strings"
	"time"

	"gopkg.in/irc.v3"
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
