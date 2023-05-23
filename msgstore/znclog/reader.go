package znclog

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/irc.v4"

	"git.sr.ht/~emersion/soju/database"
	"git.sr.ht/~emersion/soju/xirc"
)

var timestampPrefixLen = len("[01:02:03] ")

func UnmarshalLine(line string, user *database.User, network *database.Network, entity string, ref time.Time, events bool) (*irc.Message, time.Time, error) {
	var hour, minute, second int
	_, err := fmt.Sscanf(line, "[%02d:%02d:%02d] ", &hour, &minute, &second)
	if err != nil || len(line) < timestampPrefixLen {
		return nil, time.Time{}, fmt.Errorf("malformed timestamp prefix: %v", err)
	}
	line = line[timestampPrefixLen:]

	var cmd string
	var prefix *irc.Prefix
	var params []string
	if events && strings.HasPrefix(line, "*** ") {
		parts := strings.SplitN(line[4:], " ", 2)
		if len(parts) != 2 {
			return nil, time.Time{}, nil
		}
		switch parts[0] {
		case "Joins:", "Parts:", "Quits:":
			args := strings.SplitN(parts[1], " ", 3)
			if len(args) < 2 {
				return nil, time.Time{}, nil
			}
			nick := args[0]
			mask := strings.TrimSuffix(strings.TrimPrefix(args[1], "("), ")")
			maskParts := strings.SplitN(mask, "@", 2)
			if len(maskParts) != 2 {
				return nil, time.Time{}, nil
			}
			prefix = &irc.Prefix{
				Name: nick,
				User: maskParts[0],
				Host: maskParts[1],
			}
			var reason string
			if len(args) > 2 {
				reason = strings.TrimSuffix(strings.TrimPrefix(args[2], "("), ")")
			}
			switch parts[0] {
			case "Joins:":
				cmd = "JOIN"
				params = []string{entity}
			case "Parts:":
				cmd = "PART"
				if reason != "" {
					params = []string{entity, reason}
				} else {
					params = []string{entity}
				}
			case "Quits:":
				cmd = "QUIT"
				if reason != "" {
					params = []string{reason}
				}
			}
		default:
			nick := parts[0]
			rem := parts[1]
			if r := strings.TrimPrefix(rem, "is now known as "); r != rem {
				cmd = "NICK"
				prefix = &irc.Prefix{
					Name: nick,
				}
				params = []string{r}
			} else if r := strings.TrimPrefix(rem, "was kicked by "); r != rem {
				args := strings.SplitN(r, " ", 2)
				if len(args) != 2 {
					return nil, time.Time{}, nil
				}
				cmd = "KICK"
				prefix = &irc.Prefix{
					Name: args[0],
				}
				reason := strings.TrimSuffix(strings.TrimPrefix(args[1], "("), ")")
				params = []string{entity, nick}
				if reason != "" {
					params = append(params, reason)
				}
			} else if r := strings.TrimPrefix(rem, "changes topic to "); r != rem {
				cmd = "TOPIC"
				prefix = &irc.Prefix{
					Name: nick,
				}
				topic := strings.TrimSuffix(strings.TrimPrefix(r, "'"), "'")
				params = []string{entity, topic}
			} else if r := strings.TrimPrefix(rem, "sets mode: "); r != rem {
				cmd = "MODE"
				prefix = &irc.Prefix{
					Name: nick,
				}
				params = append([]string{entity}, strings.Split(r, " ")...)
			} else {
				return nil, time.Time{}, nil
			}
		}
	} else {
		var sender, text string
		if strings.HasPrefix(line, "<") {
			cmd = "PRIVMSG"
			parts := strings.SplitN(line[1:], "> ", 2)
			if len(parts) != 2 {
				return nil, time.Time{}, nil
			}
			sender, text = parts[0], parts[1]
		} else if strings.HasPrefix(line, "-") {
			cmd = "NOTICE"
			parts := strings.SplitN(line[1:], "- ", 2)
			if len(parts) != 2 {
				return nil, time.Time{}, nil
			}
			sender, text = parts[0], parts[1]
		} else if strings.HasPrefix(line, "* ") {
			cmd = "PRIVMSG"
			parts := strings.SplitN(line[2:], " ", 2)
			if len(parts) != 2 {
				return nil, time.Time{}, nil
			}
			sender, text = parts[0], "\x01ACTION "+parts[1]+"\x01"
		} else {
			return nil, time.Time{}, nil
		}

		prefix = &irc.Prefix{Name: sender}
		if entity == sender {
			// This is a direct message from a user to us. We don't store own
			// our nickname in the logs, so grab it from the network settings.
			// Not very accurate since this may not match our nick at the time
			// the message was received, but we can't do a lot better.
			entity = database.GetNick(user, network)
		}
		params = []string{entity, text}
	}

	year, month, day := ref.Date()
	t := time.Date(year, month, day, hour, minute, second, 0, time.Local)

	msg := &irc.Message{
		Tags: map[string]string{
			"time": xirc.FormatServerTime(t),
		},
		Prefix:  prefix,
		Command: cmd,
		Params:  params,
	}
	return msg, t, nil
}
