package soju

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/irc.v3"
)

// messageStore is a per-user store for IRC messages.
type messageStore interface {
	Close() error
	// LastMsgID queries the last message ID for the given network, entity and
	// date. The message ID returned may not refer to a valid message, but can be
	// used in history queries.
	LastMsgID(network *network, entity string, t time.Time) (string, error)
	LoadBeforeTime(network *network, entity string, t time.Time, limit int) ([]*irc.Message, error)
	LoadAfterTime(network *network, entity string, t time.Time, limit int) ([]*irc.Message, error)
	LoadLatestID(network *network, entity, id string, limit int) ([]*irc.Message, error)
	Append(network *network, entity string, msg *irc.Message) (id string, err error)
}

func formatMsgID(netID int64, entity, extra string) string {
	return fmt.Sprintf("%v %v %v", netID, entity, extra)
}

func parseMsgID(s string) (netID int64, entity, extra string, err error) {
	l := strings.SplitN(s, " ", 3)
	if len(l) != 3 {
		return 0, "", "", fmt.Errorf("invalid message ID %q: expected 3 fields", s)
	}
	netID, err = strconv.ParseInt(l[0], 10, 64)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid message ID %q: %v", s, err)
	}
	return netID, l[1], l[2], nil
}
