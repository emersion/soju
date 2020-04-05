package soju

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/irc.v3"
)

type messageLogger struct {
	conn   *upstreamConn
	entity string

	filename string
	file     *os.File
}

func newMessageLogger(uc *upstreamConn, entity string) *messageLogger {
	return &messageLogger{
		conn:   uc,
		entity: entity,
	}
}

func (ml *messageLogger) Append(msg *irc.Message) error {
	s := formatMessage(msg)
	if s == "" {
		return nil
	}

	// TODO: parse time from msg.Tags["time"], if available

	// TODO: enforce maximum open file handles (LRU cache of file handles)
	// TODO: handle non-monotonic clock behaviour
	now := time.Now()
	year, month, day := now.Date()
	filename := fmt.Sprintf("%04d-%02d-%02d.log", year, month, day)
	if ml.filename != filename {
		if ml.file != nil {
			ml.file.Close()
		}

		// TODO: handle/forbid network/entity names with illegal path characters
		dir := filepath.Join(ml.conn.srv.LogPath, ml.conn.user.Username, ml.conn.network.GetName(), ml.entity)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create logs directory %q: %v", dir, err)
		}

		path := filepath.Join(dir, filename)
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open log file %q: %v", path, err)
		}

		ml.filename = filename
		ml.file = f
	}

	_, err := fmt.Fprintf(ml.file, "[%02d:%02d:%02d] %s\n", now.Hour(), now.Minute(), now.Second(), s)
	if err != nil {
		return fmt.Errorf("failed to log message to %q: %v", ml.filename, err)
	}
	return nil
}

func (ml *messageLogger) Close() error {
	if ml.file == nil {
		return nil
	}
	return ml.file.Close()
}

// formatMessage formats a message log line. It assumes a well-formed IRC
// message.
func formatMessage(msg *irc.Message) string {
	switch strings.ToUpper(msg.Command) {
	case "NICK":
		return fmt.Sprintf("*** %s is now known as %s", msg.Prefix.Name, msg.Params[0])
	case "JOIN":
		return fmt.Sprintf("*** Joins: %s (%s@%s)", msg.Prefix.Name, msg.Prefix.User, msg.Prefix.Host)
	case "PART":
		var reason string
		if len(msg.Params) > 1 {
			reason = msg.Params[1]
		}
		return fmt.Sprintf("*** Parts: %s (%s@%s) (%s)", msg.Prefix.Name, msg.Prefix.User, msg.Prefix.Host, reason)
	case "KICK":
		nick := msg.Params[1]
		var reason string
		if len(msg.Params) > 2 {
			reason = msg.Params[2]
		}
		return fmt.Sprintf("*** %s was kicked by %s (%s)", nick, msg.Prefix.Name, reason)
	case "QUIT":
		var reason string
		if len(msg.Params) > 0 {
			reason = msg.Params[0]
		}
		return fmt.Sprintf("*** Quits: %s (%s@%s) (%s)", msg.Prefix.Name, msg.Prefix.User, msg.Prefix.Host, reason)
	case "MODE":
		return fmt.Sprintf("*** %s sets mode: %s", msg.Prefix.Name, strings.Join(msg.Params[1:], " "))
	case "PRIVMSG", "NOTICE":
		return fmt.Sprintf("<%s> %s", msg.Prefix.Name, msg.Params[1])
	default:
		return ""
	}
}
