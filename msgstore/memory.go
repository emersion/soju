package msgstore

import (
	"context"
	"fmt"
	"time"

	"git.sr.ht/~sircmpwn/go-bare"
	"gopkg.in/irc.v4"

	"git.sr.ht/~emersion/soju/database"
)

const messageRingBufferCap = 4096

type memoryMsgID struct {
	Seq bare.Uint
}

func (memoryMsgID) msgIDType() msgIDType {
	return msgIDMemory
}

func parseMemoryMsgID(s string) (netID int64, entity string, seq uint64, err error) {
	var id memoryMsgID
	netID, entity, err = ParseMsgID(s, &id)
	if err != nil {
		return 0, "", 0, err
	}
	return netID, entity, uint64(id.Seq), nil
}

func formatMemoryMsgID(netID int64, entity string, seq uint64) string {
	id := memoryMsgID{bare.Uint(seq)}
	return formatMsgID(netID, entity, &id)
}

type ringBufferKey struct {
	networkID int64
	entity    string
}

func IsMemoryStore(store Store) bool {
	_, ok := store.(*memoryMessageStore)
	return ok
}

type memoryMessageStore struct {
	buffers map[ringBufferKey]*messageRingBuffer
}

var _ Store = (*memoryMessageStore)(nil)

func NewMemoryStore() *memoryMessageStore {
	return &memoryMessageStore{
		buffers: make(map[ringBufferKey]*messageRingBuffer),
	}
}

func (ms *memoryMessageStore) Close() error {
	ms.buffers = nil
	return nil
}

func (ms *memoryMessageStore) get(network *database.Network, entity string) *messageRingBuffer {
	k := ringBufferKey{networkID: network.ID, entity: entity}
	if rb, ok := ms.buffers[k]; ok {
		return rb
	}
	rb := newMessageRingBuffer(messageRingBufferCap)
	ms.buffers[k] = rb
	return rb
}

func (ms *memoryMessageStore) LastMsgID(network *database.Network, entity string, t time.Time) (string, error) {
	var seq uint64
	k := ringBufferKey{networkID: network.ID, entity: entity}
	if rb, ok := ms.buffers[k]; ok {
		seq = rb.cur
	}
	return formatMemoryMsgID(network.ID, entity, seq), nil
}

func (ms *memoryMessageStore) Append(network *database.Network, entity string, msg *irc.Message) (string, error) {
	switch msg.Command {
	case "PRIVMSG", "NOTICE":
		// Only append these messages, because LoadLatestID shouldn't return
		// other kinds of message.
	default:
		return "", nil
	}

	k := ringBufferKey{networkID: network.ID, entity: entity}
	rb, ok := ms.buffers[k]
	if !ok {
		rb = newMessageRingBuffer(messageRingBufferCap)
		ms.buffers[k] = rb
	}

	seq := rb.Append(msg)
	return formatMemoryMsgID(network.ID, entity, seq), nil
}

func (ms *memoryMessageStore) LoadLatestID(ctx context.Context, id string, options *LoadMessageOptions) ([]*irc.Message, error) {
	if options.Events {
		return nil, fmt.Errorf("events are unsupported for memory message store")
	}

	_, _, seq, err := parseMemoryMsgID(id)
	if err != nil {
		return nil, err
	}

	k := ringBufferKey{networkID: options.Network.ID, entity: options.Entity}
	rb, ok := ms.buffers[k]
	if !ok {
		return nil, nil
	}

	return rb.LoadLatestSeq(seq, options.Limit)
}

type messageRingBuffer struct {
	buf []*irc.Message
	cur uint64
}

func newMessageRingBuffer(capacity int) *messageRingBuffer {
	return &messageRingBuffer{
		buf: make([]*irc.Message, capacity),
		cur: 1,
	}
}

func (rb *messageRingBuffer) cap() uint64 {
	return uint64(len(rb.buf))
}

func (rb *messageRingBuffer) Append(msg *irc.Message) uint64 {
	seq := rb.cur
	i := int(seq % rb.cap())
	rb.buf[i] = msg
	rb.cur++
	return seq
}

func (rb *messageRingBuffer) LoadLatestSeq(seq uint64, limit int) ([]*irc.Message, error) {
	if seq > rb.cur {
		return nil, fmt.Errorf("loading messages from sequence number (%v) greater than current (%v)", seq, rb.cur)
	} else if seq == rb.cur {
		return nil, nil
	}

	// The query excludes the message with the sequence number seq
	diff := rb.cur - seq - 1
	if diff > rb.cap() {
		// We dropped diff - cap entries
		diff = rb.cap()
	}
	if int(diff) > limit {
		diff = uint64(limit)
	}

	l := make([]*irc.Message, int(diff))
	for i := 0; i < int(diff); i++ {
		j := int((rb.cur - diff + uint64(i)) % rb.cap())
		l[i] = rb.buf[j]
	}

	return l, nil
}
