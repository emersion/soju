package soju

import (
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
