package msgstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"git.sr.ht/~sircmpwn/go-bare"
	"gopkg.in/irc.v4"

	"git.sr.ht/~emersion/soju/database"
)

type LoadMessageOptions struct {
	Network *database.Network
	Entity  string
	Limit   int
	Events  bool
}

// Store is a per-user store for IRC messages.
type Store interface {
	Close() error
	// LastMsgID queries the last message ID for the given network, entity and
	// date. The message ID returned may not refer to a valid message, but can be
	// used in history queries.
	LastMsgID(network *database.Network, entity string, t time.Time) (string, error)
	// LoadLatestID queries the latest non-event messages for the given network,
	// entity and date, up to a count of limit messages, sorted from oldest to newest.
	LoadLatestID(ctx context.Context, id string, options *LoadMessageOptions) ([]*irc.Message, error)
	Append(network *database.Network, entity string, msg *irc.Message) (id string, err error)
}

type ChatHistoryTarget struct {
	Name          string
	LatestMessage time.Time
}

// ChatHistoryStore is a message store that supports chat history operations.
type ChatHistoryStore interface {
	Store

	// ListTargets lists channels and nicknames by time of the latest message.
	// It returns up to limit targets, starting from start and ending on end,
	// both excluded. end may be before or after start.
	// If events is false, only PRIVMSG/NOTICE messages are considered.
	ListTargets(ctx context.Context, network *database.Network, start, end time.Time, limit int, events bool) ([]ChatHistoryTarget, error)
	// LoadBeforeTime loads up to limit messages before start down to end. The
	// returned messages must be between and excluding the provided bounds.
	// end is before start.
	// If events is false, only PRIVMSG/NOTICE messages are considered.
	LoadBeforeTime(ctx context.Context, start, end time.Time, options *LoadMessageOptions) ([]*irc.Message, error)
	// LoadAfterTime loads up to limit messages after start up to end. The
	// returned messages must be between and excluding the provided bounds.
	// end is after start.
	// If events is false, only PRIVMSG/NOTICE messages are considered.
	LoadAfterTime(ctx context.Context, start, end time.Time, options *LoadMessageOptions) ([]*irc.Message, error)
}

type SearchMessageOptions struct {
	Start time.Time
	End   time.Time
	Limit int
	From  string
	In    string
	Text  string
}

// SearchStore is a message store that supports server-side search operations.
type SearchStore interface {
	Store

	// Search returns messages matching the specified options.
	Search(ctx context.Context, network *database.Network, options *SearchMessageOptions) ([]*irc.Message, error)
}

// RenameNetworkStore is a message store which needs to be notified of network
// name changes.
type RenameNetworkStore interface {
	Store

	RenameNetwork(oldNet, newNet *database.Network) error
}

type msgIDType uint

const (
	msgIDNone msgIDType = iota
	msgIDMemory
	msgIDFS
	msgIDDB
)

const msgIDVersion uint = 0

type msgIDHeader struct {
	Version uint
	Network bare.Int
	Target  string
	Type    msgIDType
}

type msgIDBody interface {
	msgIDType() msgIDType
}

func formatMsgID(netID int64, target string, body msgIDBody) string {
	var buf bytes.Buffer
	w := bare.NewWriter(&buf)

	header := msgIDHeader{
		Version: msgIDVersion,
		Network: bare.Int(netID),
		Target:  target,
		Type:    body.msgIDType(),
	}
	if err := bare.MarshalWriter(w, &header); err != nil {
		panic(err)
	}
	if err := bare.MarshalWriter(w, body); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func ParseMsgID(s string, body msgIDBody) (netID int64, target string, err error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, "", fmt.Errorf("invalid internal message ID: %v", err)
	}

	r := bare.NewReader(bytes.NewReader(b))

	var header msgIDHeader
	if err := bare.UnmarshalBareReader(r, &header); err != nil {
		return 0, "", fmt.Errorf("invalid internal message ID: %v", err)
	}

	if header.Version != msgIDVersion {
		return 0, "", fmt.Errorf("invalid internal message ID: got version %v, want %v", header.Version, msgIDVersion)
	}

	if body != nil {
		typ := body.msgIDType()
		if header.Type != typ {
			return 0, "", fmt.Errorf("invalid internal message ID: got type %v, want %v", header.Type, typ)
		}

		if err := bare.UnmarshalBareReader(r, body); err != nil {
			return 0, "", fmt.Errorf("invalid internal message ID: %v", err)
		}
	}

	return int64(header.Network), header.Target, nil
}
