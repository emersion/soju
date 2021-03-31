package soju

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"time"

	"git.sr.ht/~sircmpwn/go-bare"
	"gopkg.in/irc.v3"
)

// messageStore is a per-user store for IRC messages.
type messageStore interface {
	Close() error
	// LastMsgID queries the last message ID for the given network, entity and
	// date. The message ID returned may not refer to a valid message, but can be
	// used in history queries.
	LastMsgID(network *network, entity string, t time.Time) (string, error)
	LoadLatestID(network *network, entity, id string, limit int) ([]*irc.Message, error)
	Append(network *network, entity string, msg *irc.Message) (id string, err error)
}

// chatHistoryMessageStore is a message store that supports chat history
// operations.
type chatHistoryMessageStore interface {
	messageStore

	LoadBeforeTime(network *network, entity string, t time.Time, limit int) ([]*irc.Message, error)
	LoadAfterTime(network *network, entity string, t time.Time, limit int) ([]*irc.Message, error)
}

type msgIDType uint

const (
	msgIDNone msgIDType = iota
	msgIDMemory
	msgIDFS
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

func parseMsgID(s string, body msgIDBody) (netID int64, target string, err error) {
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
