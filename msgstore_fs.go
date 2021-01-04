package soju

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/irc.v3"
)

const fsMessageStoreMaxTries = 100

var escapeFilename = strings.NewReplacer("/", "-", "\\", "-")

// fsMessageStore is a per-user on-disk store for IRC messages.
type fsMessageStore struct {
	root string

	files map[string]*os.File // indexed by entity
}

func newFSMessageStore(root, username string) *fsMessageStore {
	return &fsMessageStore{
		root:  filepath.Join(root, escapeFilename.Replace(username)),
		files: make(map[string]*os.File),
	}
}

func (ms *fsMessageStore) logPath(network *network, entity string, t time.Time) string {
	year, month, day := t.Date()
	filename := fmt.Sprintf("%04d-%02d-%02d.log", year, month, day)
	return filepath.Join(ms.root, escapeFilename.Replace(network.GetName()), escapeFilename.Replace(entity), filename)
}

func parseMsgID(s string) (network, entity string, t time.Time, offset int64, err error) {
	var year, month, day int
	_, err = fmt.Sscanf(s, "%s %s %04d-%02d-%02d %d", &network, &entity, &year, &month, &day, &offset)
	if err != nil {
		return "", "", time.Time{}, 0, fmt.Errorf("invalid message ID: %v", err)
	}
	t = time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.Local)
	return network, entity, t, offset, nil
}

func formatMsgID(network, entity string, t time.Time, offset int64) string {
	year, month, day := t.Date()
	return fmt.Sprintf("%s %s %04d-%02d-%02d %d", network, entity, year, month, day, offset)
}

// nextMsgID queries the message ID for the next message to be written to f.
func nextMsgID(network *network, entity string, t time.Time, f *os.File) (string, error) {
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return "", err
	}
	return formatMsgID(network.GetName(), entity, t, offset), nil
}

func (ms *fsMessageStore) LastMsgID(network *network, entity string, t time.Time) (string, error) {
	p := ms.logPath(network, entity, t)
	fi, err := os.Stat(p)
	if os.IsNotExist(err) {
		return formatMsgID(network.GetName(), entity, t, -1), nil
	} else if err != nil {
		return "", err
	}
	return formatMsgID(network.GetName(), entity, t, fi.Size()-1), nil
}

func (ms *fsMessageStore) Append(network *network, entity string, msg *irc.Message) (string, error) {
	s := formatMessage(msg)
	if s == "" {
		return "", nil
	}

	var t time.Time
	if tag, ok := msg.Tags["time"]; ok {
		var err error
		t, err = time.Parse(serverTimeLayout, string(tag))
		if err != nil {
			return "", fmt.Errorf("failed to parse message time tag: %v", err)
		}
		t = t.In(time.Local)
	} else {
		t = time.Now()
	}

	// TODO: enforce maximum open file handles (LRU cache of file handles)
	f := ms.files[entity]

	// TODO: handle non-monotonic clock behaviour
	path := ms.logPath(network, entity, t)
	if f == nil || f.Name() != path {
		if f != nil {
			f.Close()
		}

		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", fmt.Errorf("failed to create message logs directory %q: %v", dir, err)
		}

		var err error
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return "", fmt.Errorf("failed to open message log file %q: %v", path, err)
		}

		ms.files[entity] = f
	}

	msgID, err := nextMsgID(network, entity, t, f)
	if err != nil {
		return "", fmt.Errorf("failed to generate message ID: %v", err)
	}

	_, err = fmt.Fprintf(f, "[%02d:%02d:%02d] %s\n", t.Hour(), t.Minute(), t.Second(), s)
	if err != nil {
		return "", fmt.Errorf("failed to log message to %q: %v", f.Name(), err)
	}

	return msgID, nil
}

func (ms *fsMessageStore) Close() error {
	var closeErr error
	for _, f := range ms.files {
		if err := f.Close(); err != nil {
			closeErr = fmt.Errorf("failed to close message store: %v", err)
		}
	}
	return closeErr
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
	case "TOPIC":
		var topic string
		if len(msg.Params) > 1 {
			topic = msg.Params[1]
		}
		return fmt.Sprintf("*** %s changes topic to '%s'", msg.Prefix.Name, topic)
	case "MODE":
		return fmt.Sprintf("*** %s sets mode: %s", msg.Prefix.Name, strings.Join(msg.Params[1:], " "))
	case "NOTICE":
		return fmt.Sprintf("-%s- %s", msg.Prefix.Name, msg.Params[1])
	case "PRIVMSG":
		if cmd, params, ok := parseCTCPMessage(msg); ok && cmd == "ACTION" {
			return fmt.Sprintf("* %s %s", msg.Prefix.Name, params)
		} else {
			return fmt.Sprintf("<%s> %s", msg.Prefix.Name, msg.Params[1])
		}
	default:
		return ""
	}
}

func parseMessage(line, entity string, ref time.Time) (*irc.Message, time.Time, error) {
	var hour, minute, second int
	_, err := fmt.Sscanf(line, "[%02d:%02d:%02d] ", &hour, &minute, &second)
	if err != nil {
		return nil, time.Time{}, err
	}
	line = line[11:]

	var cmd, sender, text string
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

	year, month, day := ref.Date()
	t := time.Date(year, month, day, hour, minute, second, 0, time.Local)

	msg := &irc.Message{
		Tags: map[string]irc.TagValue{
			"time": irc.TagValue(t.UTC().Format(serverTimeLayout)),
		},
		Prefix:  &irc.Prefix{Name: sender},
		Command: cmd,
		Params:  []string{entity, text},
	}
	return msg, t, nil
}

func (ms *fsMessageStore) parseMessagesBefore(network *network, entity string, ref time.Time, limit int, afterOffset int64) ([]*irc.Message, error) {
	path := ms.logPath(network, entity, ref)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	historyRing := make([]*irc.Message, limit)
	cur := 0

	sc := bufio.NewScanner(f)

	if afterOffset >= 0 {
		if _, err := f.Seek(afterOffset, io.SeekStart); err != nil {
			return nil, nil
		}
		sc.Scan() // skip till next newline
	}

	for sc.Scan() {
		msg, t, err := parseMessage(sc.Text(), entity, ref)
		if err != nil {
			return nil, err
		} else if msg == nil {
			continue
		} else if !t.Before(ref) {
			break
		}

		historyRing[cur%limit] = msg
		cur++
	}
	if sc.Err() != nil {
		return nil, sc.Err()
	}

	n := limit
	if cur < limit {
		n = cur
	}
	start := (cur - n + limit) % limit

	if start+n <= limit { // ring doesnt wrap
		return historyRing[start : start+n], nil
	} else { // ring wraps
		history := make([]*irc.Message, n)
		r := copy(history, historyRing[start:])
		copy(history[r:], historyRing[:n-r])
		return history, nil
	}
}

func (ms *fsMessageStore) parseMessagesAfter(network *network, entity string, ref time.Time, limit int) ([]*irc.Message, error) {
	path := ms.logPath(network, entity, ref)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var history []*irc.Message
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(history) < limit {
		msg, t, err := parseMessage(sc.Text(), entity, ref)
		if err != nil {
			return nil, err
		} else if msg == nil || !t.After(ref) {
			continue
		}

		history = append(history, msg)
	}
	if sc.Err() != nil {
		return nil, sc.Err()
	}

	return history, nil
}

func (ms *fsMessageStore) LoadBeforeTime(network *network, entity string, t time.Time, limit int) ([]*irc.Message, error) {
	history := make([]*irc.Message, limit)
	remaining := limit
	tries := 0
	for remaining > 0 && tries < fsMessageStoreMaxTries {
		buf, err := ms.parseMessagesBefore(network, entity, t, remaining, -1)
		if err != nil {
			return nil, err
		}
		if len(buf) == 0 {
			tries++
		} else {
			tries = 0
		}
		copy(history[remaining-len(buf):], buf)
		remaining -= len(buf)
		year, month, day := t.Date()
		t = time.Date(year, month, day, 0, 0, 0, 0, t.Location()).Add(-1)
	}

	return history[remaining:], nil
}

func (ms *fsMessageStore) LoadAfterTime(network *network, entity string, t time.Time, limit int) ([]*irc.Message, error) {
	var history []*irc.Message
	remaining := limit
	tries := 0
	now := time.Now()
	for remaining > 0 && tries < fsMessageStoreMaxTries && t.Before(now) {
		buf, err := ms.parseMessagesAfter(network, entity, t, remaining)
		if err != nil {
			return nil, err
		}
		if len(buf) == 0 {
			tries++
		} else {
			tries = 0
		}
		history = append(history, buf...)
		remaining -= len(buf)
		year, month, day := t.Date()
		t = time.Date(year, month, day+1, 0, 0, 0, 0, t.Location())
	}
	return history, nil
}

func truncateDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

func (ms *fsMessageStore) LoadLatestID(network *network, entity, id string, limit int) ([]*irc.Message, error) {
	var afterTime time.Time
	var afterOffset int64
	if id != "" {
		var idNet, idEntity string
		var err error
		idNet, idEntity, afterTime, afterOffset, err = parseMsgID(id)
		if err != nil {
			return nil, err
		}
		if idNet != network.GetName() || idEntity != entity {
			return nil, fmt.Errorf("cannot find message ID: message ID doesn't match network/entity")
		}
	}

	history := make([]*irc.Message, limit)
	t := time.Now()
	remaining := limit
	tries := 0
	for remaining > 0 && tries < fsMessageStoreMaxTries && !truncateDay(t).Before(afterTime) {
		var offset int64 = -1
		if afterOffset >= 0 && truncateDay(t).Equal(afterTime) {
			offset = afterOffset
		}

		buf, err := ms.parseMessagesBefore(network, entity, t, remaining, offset)
		if err != nil {
			return nil, err
		}
		if len(buf) == 0 {
			tries++
		} else {
			tries = 0
		}
		copy(history[remaining-len(buf):], buf)
		remaining -= len(buf)
		year, month, day := t.Date()
		t = time.Date(year, month, day, 0, 0, 0, 0, t.Location()).Add(-1)
	}

	return history[remaining:], nil
}
