package soju

import (
	"fmt"

	"gopkg.in/irc.v3"
)

// Ring implements a single producer, multiple consumer ring buffer. The ring
// buffer size is fixed. The ring buffer is stored in memory.
type Ring struct {
	buffer []*irc.Message
	cap    uint64

	cur       uint64
	consumers []*RingConsumer
	closed    bool
}

// NewRing creates a new ring buffer.
func NewRing(capacity int) *Ring {
	return &Ring{
		buffer: make([]*irc.Message, capacity),
		cap:    uint64(capacity),
	}
}

// Produce appends a new message to the ring buffer.
func (r *Ring) Produce(msg *irc.Message) {
	if r.closed {
		panic("soju: Ring.Produce called after Close")
	}

	i := int(r.cur % r.cap)
	r.buffer[i] = msg
	r.cur++
}

func (r *Ring) Close() {
	if r.closed {
		panic("soju: Ring.Close called twice")
	}

	r.closed = true
}

// NewConsumer creates a new ring buffer consumer.
//
// If seq is nil, the consumer will get messages starting from the last
// producer message. If seq is non-nil, the consumer will get messages starting
// from the specified history sequence number (see RingConsumer.Close).
//
// The consumer can only be used from a single goroutine.
func (r *Ring) NewConsumer(seq *uint64) *RingConsumer {
	consumer := &RingConsumer{ring: r}

	if seq != nil {
		consumer.cur = *seq
	} else {
		consumer.cur = r.cur
	}
	r.consumers = append(r.consumers, consumer)

	return consumer
}

// RingConsumer is a ring buffer consumer.
type RingConsumer struct {
	ring   *Ring
	cur    uint64
	closed bool
}

// diff returns the number of pending messages. It assumes the Ring is locked.
func (rc *RingConsumer) diff() uint64 {
	if rc.cur > rc.ring.cur {
		panic(fmt.Sprintf("soju: consumer cursor (%v) greater than producer cursor (%v)", rc.cur, rc.ring.cur))
	}
	return rc.ring.cur - rc.cur
}

// Peek returns the next pending message if any without consuming it. A nil
// message is returned if no message is available.
func (rc *RingConsumer) Peek() *irc.Message {
	if rc.closed {
		panic("soju: RingConsumer.Peek called after Close")
	}

	diff := rc.diff()
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
		panic(fmt.Sprintf("soju: unexpected nil ring buffer entry at index %v", i))
	}
	return msg
}

// Consume consumes and returns the next pending message. A nil message is
// returned if no message is available.
func (rc *RingConsumer) Consume() *irc.Message {
	msg := rc.Peek()
	if msg != nil {
		rc.cur++
	}
	return msg
}

// Close stops consuming messages. The consumer channel will be closed. The
// current history sequence number is returned. It can be provided later as an
// argument to Ring.NewConsumer to resume the message stream.
func (rc *RingConsumer) Close() uint64 {
	for i := range rc.ring.consumers {
		if rc.ring.consumers[i] == rc {
			rc.ring.consumers = append(rc.ring.consumers[:i], rc.ring.consumers[i+1:]...)
			break
		}
	}

	rc.closed = true
	return rc.cur
}
