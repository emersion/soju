package jounce

import (
	"gopkg.in/irc.v3"
)

// Ring implements a single producer, multiple consumer ring buffer. The ring
// buffer size is fixed. The ring buffer is stored in memory.
type Ring struct {
	buffer   []*irc.Message
	cap, cur uint64

	consumers []RingConsumer
}

func NewRing(capacity int) *Ring {
	return &Ring{
		buffer: make([]*irc.Message, capacity),
		cap:    uint64(capacity),
	}
}

func (r *Ring) Produce(msg *irc.Message) {
	i := int(r.cur % r.cap)
	r.buffer[i] = msg
	r.cur++
}

func (r *Ring) Consumer() *RingConsumer {
	return &RingConsumer{
		ring: r,
		cur:  0, // r.cur
	}
}

type RingConsumer struct {
	ring *Ring
	cur  uint64
}

func (rc *RingConsumer) Diff() uint64 {
	if rc.cur > rc.ring.cur {
		panic("jounce: consumer cursor greater than producer cursor")
	}
	return rc.ring.cur - rc.cur
}

func (rc *RingConsumer) Peek() *irc.Message {
	diff := rc.Diff()
	if diff == 0 {
		return nil
	}
	if diff > rc.ring.cap {
		// Consumer drops diff - cap entries
		rc.cur = rc.ring.cur - rc.ring.cap
	}
	i := int(rc.cur % rc.ring.cap)
	msg := rc.ring.buffer[i]
	if msg == nil {
		panic("jounce: unexpected nil ring buffer entry")
	}
	return msg
}

func (rc *RingConsumer) Consume() *irc.Message {
	msg := rc.Peek()
	if msg != nil {
		rc.cur++
	}
	return msg
}
