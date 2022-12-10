package msgstore

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"git.sr.ht/~sircmpwn/go-bare"
	"gopkg.in/irc.v4"

	"git.sr.ht/~emersion/soju/database"
	"git.sr.ht/~emersion/soju/xirc"
)

const (
	fsMessageStoreMaxFiles = 20
	fsMessageStoreMaxTries = 100
)

func EscapeFilename(unsafe string) (safe string) {
	if unsafe == "." {
		return "-"
	} else if unsafe == ".." {
		return "--"
	} else {
		return strings.NewReplacer("/", "-", "\\", "-").Replace(unsafe)
	}
}

type date struct {
	Year, Month, Day int
}

func newDate(t time.Time) date {
	year, month, day := t.Date()
	return date{year, int(month), day}
}

func (d date) Time() time.Time {
	return time.Date(d.Year, time.Month(d.Month), d.Day, 0, 0, 0, 0, time.Local)
}

type fsMsgID struct {
	Date   date
	Offset bare.Int
}

func (fsMsgID) msgIDType() msgIDType {
	return msgIDFS
}

func parseFSMsgID(s string) (netID int64, entity string, t time.Time, offset int64, err error) {
	var id fsMsgID
	netID, entity, err = ParseMsgID(s, &id)
	if err != nil {
		return 0, "", time.Time{}, 0, err
	}
	return netID, entity, id.Date.Time(), int64(id.Offset), nil
}

func formatFSMsgID(netID int64, entity string, t time.Time, offset int64) string {
	id := fsMsgID{
		Date:   newDate(t),
		Offset: bare.Int(offset),
	}
	return formatMsgID(netID, entity, &id)
}

type fsMessageStoreFile struct {
	*os.File
	lastUse time.Time
}

// fsMessageStore is a per-user on-disk store for IRC messages.
//
// It mimicks the ZNC log layout and format. See the ZNC source:
// https://github.com/znc/znc/blob/master/modules/log.cpp
type fsMessageStore struct {
	root string
	user *database.User

	// Write-only files used by Append
	files map[string]*fsMessageStoreFile // indexed by entity
}

var (
	_ Store              = (*fsMessageStore)(nil)
	_ ChatHistoryStore   = (*fsMessageStore)(nil)
	_ SearchStore        = (*fsMessageStore)(nil)
	_ RenameNetworkStore = (*fsMessageStore)(nil)
)

func IsFSStore(store Store) bool {
	_, ok := store.(*fsMessageStore)
	return ok
}

func NewFSStore(root string, user *database.User) *fsMessageStore {
	return &fsMessageStore{
		root:  filepath.Join(root, EscapeFilename(user.Username)),
		user:  user,
		files: make(map[string]*fsMessageStoreFile),
	}
}

func (ms *fsMessageStore) logPath(network *database.Network, entity string, t time.Time) string {
	year, month, day := t.Date()
	filename := fmt.Sprintf("%04d-%02d-%02d.log", year, month, day)
	return filepath.Join(ms.root, EscapeFilename(network.GetName()), EscapeFilename(entity), filename)
}

// nextMsgID queries the message ID for the next message to be written to f.
func nextFSMsgID(network *database.Network, entity string, t time.Time, f *os.File) (string, error) {
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return "", fmt.Errorf("failed to query next FS message ID: %v", err)
	}
	return formatFSMsgID(network.ID, entity, t, offset), nil
}

func (ms *fsMessageStore) LastMsgID(network *database.Network, entity string, t time.Time) (string, error) {
	p := ms.logPath(network, entity, t)
	fi, err := os.Stat(p)
	if os.IsNotExist(err) {
		return formatFSMsgID(network.ID, entity, t, -1), nil
	} else if err != nil {
		return "", fmt.Errorf("failed to query last FS message ID: %v", err)
	}
	return formatFSMsgID(network.ID, entity, t, fi.Size()-1), nil
}

func (ms *fsMessageStore) Append(network *database.Network, entity string, msg *irc.Message) (string, error) {
	s := formatMessage(msg)
	if s == "" {
		return "", nil
	}

	var t time.Time
	if tag, ok := msg.Tags["time"]; ok {
		var err error
		t, err = time.Parse(xirc.ServerTimeLayout, string(tag))
		if err != nil {
			return "", fmt.Errorf("failed to parse message time tag: %v", err)
		}
		t = t.In(time.Local)
	} else {
		t = time.Now()
	}

	f := ms.files[entity]

	// TODO: handle non-monotonic clock behaviour
	path := ms.logPath(network, entity, t)
	if f == nil || f.Name() != path {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return "", fmt.Errorf("failed to create message logs directory %q: %v", dir, err)
		}

		ff, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			return "", fmt.Errorf("failed to open message log file %q: %v", path, err)
		}

		if f != nil {
			f.Close()
		}
		f = &fsMessageStoreFile{File: ff}
		ms.files[entity] = f
	}

	f.lastUse = time.Now()

	if len(ms.files) > fsMessageStoreMaxFiles {
		entities := make([]string, 0, len(ms.files))
		for name := range ms.files {
			entities = append(entities, name)
		}
		sort.Slice(entities, func(i, j int) bool {
			a, b := entities[i], entities[j]
			return ms.files[a].lastUse.Before(ms.files[b].lastUse)
		})
		entities = entities[0 : len(entities)-fsMessageStoreMaxFiles]
		for _, name := range entities {
			ms.files[name].Close()
			delete(ms.files, name)
		}
	}

	msgID, err := nextFSMsgID(network, entity, t, f.File)
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
		if cmd, params, ok := xirc.ParseCTCPMessage(msg); ok && cmd == "ACTION" {
			return fmt.Sprintf("* %s %s", msg.Prefix.Name, params)
		} else {
			return fmt.Sprintf("<%s> %s", msg.Prefix.Name, msg.Params[1])
		}
	default:
		return ""
	}
}

func (ms *fsMessageStore) parseMessage(line string, network *database.Network, entity string, ref time.Time, events bool) (*irc.Message, time.Time, error) {
	return FSParseMessage(line, ms.user, network, entity, ref, events)
}

func FSParseMessage(line string, user *database.User, network *database.Network, entity string, ref time.Time, events bool) (*irc.Message, time.Time, error) {
	var hour, minute, second int
	_, err := fmt.Sscanf(line, "[%02d:%02d:%02d] ", &hour, &minute, &second)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("malformed timestamp prefix: %v", err)
	}
	line = line[11:]

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

func (ms *fsMessageStore) parseMessagesBefore(ref time.Time, end time.Time, options *LoadMessageOptions, afterOffset int64, selector func(m *irc.Message) bool) ([]*irc.Message, error) {
	path := ms.logPath(options.Network, options.Entity, ref)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to parse messages before ref: %v", err)
	}
	defer f.Close()

	historyRing := make([]*irc.Message, options.Limit)
	cur := 0

	sc := bufio.NewScanner(f)

	if afterOffset >= 0 {
		if _, err := f.Seek(afterOffset, io.SeekStart); err != nil {
			return nil, nil
		}
		sc.Scan() // skip till next newline
	}

	for sc.Scan() {
		msg, t, err := ms.parseMessage(sc.Text(), options.Network, options.Entity, ref, options.Events)
		if err != nil {
			return nil, err
		} else if msg == nil || !t.After(end) {
			continue
		} else if !t.Before(ref) {
			break
		}
		if selector != nil && !selector(msg) {
			continue
		}

		historyRing[cur%options.Limit] = msg
		cur++
	}
	if sc.Err() != nil {
		return nil, fmt.Errorf("failed to parse messages before ref: scanner error: %v", sc.Err())
	}

	n := options.Limit
	if cur < options.Limit {
		n = cur
	}
	start := (cur - n + options.Limit) % options.Limit

	if start+n <= options.Limit { // ring doesnt wrap
		return historyRing[start : start+n], nil
	} else { // ring wraps
		history := make([]*irc.Message, n)
		r := copy(history, historyRing[start:])
		copy(history[r:], historyRing[:n-r])
		return history, nil
	}
}

func (ms *fsMessageStore) parseMessagesAfter(ref time.Time, end time.Time, options *LoadMessageOptions, selector func(m *irc.Message) bool) ([]*irc.Message, error) {
	path := ms.logPath(options.Network, options.Entity, ref)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to parse messages after ref: %v", err)
	}
	defer f.Close()

	var history []*irc.Message
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(history) < options.Limit {
		msg, t, err := ms.parseMessage(sc.Text(), options.Network, options.Entity, ref, options.Events)
		if err != nil {
			return nil, err
		} else if msg == nil || !t.After(ref) {
			continue
		} else if !t.Before(end) {
			break
		}
		if selector != nil && !selector(msg) {
			continue
		}

		history = append(history, msg)
	}
	if sc.Err() != nil {
		return nil, fmt.Errorf("failed to parse messages after ref: scanner error: %v", sc.Err())
	}

	return history, nil
}

func (ms *fsMessageStore) getBeforeTime(ctx context.Context, start time.Time, end time.Time, options *LoadMessageOptions, selector func(m *irc.Message) bool) ([]*irc.Message, error) {
	if start.IsZero() {
		start = time.Now()
	} else {
		start = start.In(time.Local)
	}
	end = end.In(time.Local)
	messages := make([]*irc.Message, options.Limit)
	remaining := options.Limit
	tries := 0
	for remaining > 0 && tries < fsMessageStoreMaxTries && end.Before(start) {
		parseOptions := *options
		parseOptions.Limit = remaining
		buf, err := ms.parseMessagesBefore(start, end, &parseOptions, -1, selector)
		if err != nil {
			return nil, err
		}
		if len(buf) == 0 {
			tries++
		} else {
			tries = 0
		}
		copy(messages[remaining-len(buf):], buf)
		remaining -= len(buf)
		year, month, day := start.Date()
		start = time.Date(year, month, day, 0, 0, 0, 0, start.Location()).Add(-1)

		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	return messages[remaining:], nil
}

func (ms *fsMessageStore) LoadBeforeTime(ctx context.Context, start time.Time, end time.Time, options *LoadMessageOptions) ([]*irc.Message, error) {
	return ms.getBeforeTime(ctx, start, end, options, nil)
}

func (ms *fsMessageStore) getAfterTime(ctx context.Context, start time.Time, end time.Time, options *LoadMessageOptions, selector func(m *irc.Message) bool) ([]*irc.Message, error) {
	start = start.In(time.Local)
	if end.IsZero() {
		end = time.Now()
	} else {
		end = end.In(time.Local)
	}
	var messages []*irc.Message
	remaining := options.Limit
	tries := 0
	for remaining > 0 && tries < fsMessageStoreMaxTries && start.Before(end) {
		parseOptions := *options
		parseOptions.Limit = remaining
		buf, err := ms.parseMessagesAfter(start, end, &parseOptions, selector)
		if err != nil {
			return nil, err
		}
		if len(buf) == 0 {
			tries++
		} else {
			tries = 0
		}
		messages = append(messages, buf...)
		remaining -= len(buf)
		year, month, day := start.Date()
		start = time.Date(year, month, day+1, 0, 0, 0, 0, start.Location())

		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return messages, nil
}

func (ms *fsMessageStore) LoadAfterTime(ctx context.Context, start time.Time, end time.Time, options *LoadMessageOptions) ([]*irc.Message, error) {
	return ms.getAfterTime(ctx, start, end, options, nil)
}

func (ms *fsMessageStore) LoadLatestID(ctx context.Context, id string, options *LoadMessageOptions) ([]*irc.Message, error) {
	var afterTime time.Time
	var afterOffset int64
	if id != "" {
		var idNet int64
		var idEntity string
		var err error
		idNet, idEntity, afterTime, afterOffset, err = parseFSMsgID(id)
		if err != nil {
			return nil, err
		}
		if idNet != options.Network.ID || idEntity != options.Entity {
			return nil, fmt.Errorf("cannot find message ID: message ID doesn't match network/entity")
		}
	}

	history := make([]*irc.Message, options.Limit)
	t := time.Now()
	remaining := options.Limit
	tries := 0
	for remaining > 0 && tries < fsMessageStoreMaxTries && !truncateDay(t).Before(afterTime) {
		var offset int64 = -1
		if afterOffset >= 0 && truncateDay(t).Equal(afterTime) {
			offset = afterOffset
		}

		parseOptions := *options
		parseOptions.Limit = remaining
		buf, err := ms.parseMessagesBefore(t, time.Time{}, &parseOptions, offset, nil)
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

		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	return history[remaining:], nil
}

func (ms *fsMessageStore) ListTargets(ctx context.Context, network *database.Network, start, end time.Time, limit int, events bool) ([]ChatHistoryTarget, error) {
	start = start.In(time.Local)
	end = end.In(time.Local)
	rootPath := filepath.Join(ms.root, EscapeFilename(network.GetName()))
	root, err := os.Open(rootPath)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// The returned targets are escaped, and there is no way to un-escape
	// TODO: switch to ReadDir (Go 1.16+)
	targetNames, err := root.Readdirnames(0)
	root.Close()
	if err != nil {
		return nil, err
	}

	var targets []ChatHistoryTarget
	for _, target := range targetNames {
		// target is already escaped here
		targetPath := filepath.Join(rootPath, target)
		targetDir, err := os.Open(targetPath)
		if err != nil {
			return nil, err
		}

		entries, err := targetDir.Readdir(0)
		targetDir.Close()
		if err != nil {
			return nil, err
		}

		// We use mtime here, which may give imprecise or incorrect results
		var t time.Time
		for _, entry := range entries {
			if entry.ModTime().After(t) {
				t = entry.ModTime()
			}
		}

		// The timestamps we get from logs have second granularity
		t = truncateSecond(t)

		// Filter out targets that don't fullfil the time bounds
		if !isTimeBetween(t, start, end) {
			continue
		}

		targets = append(targets, ChatHistoryTarget{
			Name:          target,
			LatestMessage: t,
		})

		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// Sort targets by latest message time, backwards or forwards depending on
	// the order of the time bounds
	sort.Slice(targets, func(i, j int) bool {
		t1, t2 := targets[i].LatestMessage, targets[j].LatestMessage
		if start.Before(end) {
			return t1.Before(t2)
		} else {
			return !t1.Before(t2)
		}
	})

	// Truncate the result if necessary
	if len(targets) > limit {
		targets = targets[:limit]
	}

	return targets, nil
}

func (ms *fsMessageStore) Search(ctx context.Context, network *database.Network, opts *SearchMessageOptions) ([]*irc.Message, error) {
	text := strings.ToLower(opts.Text)
	selector := func(m *irc.Message) bool {
		if opts.From != "" && m.Name != opts.From {
			return false
		}
		if text != "" && !strings.Contains(strings.ToLower(m.Params[1]), text) {
			return false
		}
		return true
	}
	loadOptions := LoadMessageOptions{
		Network: network,
		Entity:  opts.In,
		Limit:   opts.Limit,
	}
	if !opts.Start.IsZero() {
		return ms.getAfterTime(ctx, opts.Start, opts.End, &loadOptions, selector)
	} else {
		return ms.getBeforeTime(ctx, opts.End, opts.Start, &loadOptions, selector)
	}
}

func (ms *fsMessageStore) RenameNetwork(oldNet, newNet *database.Network) error {
	oldDir := filepath.Join(ms.root, EscapeFilename(oldNet.GetName()))
	newDir := filepath.Join(ms.root, EscapeFilename(newNet.GetName()))
	// Avoid loosing data by overwriting an existing directory
	if _, err := os.Stat(newDir); err == nil {
		return fmt.Errorf("destination %q already exists", newDir)
	}
	return os.Rename(oldDir, newDir)
}

func truncateDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

func truncateSecond(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, t.Hour(), t.Minute(), t.Second(), 0, t.Location())
}

func isTimeBetween(t, start, end time.Time) bool {
	if end.Before(start) {
		end, start = start, end
	}
	return start.Before(t) && t.Before(end)
}
