package jounce

import (
	"sync"

	"gopkg.in/irc.v3"
)

// Ring implements a single producer, multiple consumer ring buffer. The ring
// buffer size is fixed. The ring buffer is stored in memory.
type Ring struct {
	buffer []*irc.Message
	cap    uint64

	lock      sync.Mutex
	cur       uint64
	consumers []*RingConsumer
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
	r.lock.Lock()
	defer r.lock.Unlock()

	i := int(r.cur % r.cap)
	r.buffer[i] = msg
	r.cur++

	for _, consumer := range r.consumers {
		select {
		case consumer.ch <- struct{}{}:
			// This space is intentionally left blank
		default:
			// The channel already has a pending item
		}
	}
}

// NewConsumer creates a new ring buffer consumer.
//
// If seq is nil, the consumer will get messages starting from the last
// producer message. If seq is non-nil, the consumer will get messages starting
// from the specified history sequence number (see RingConsumer.Close).
//
// The returned channel yields a value each time the consumer has a new message
// available. Consume should be called to drain the consumer.
//
// The consumer can only be used from a single goroutine.
func (r *Ring) NewConsumer(seq *uint64) (*RingConsumer, <-chan struct{}) {
	consumer := &RingConsumer{
		ring: r,
		ch:   make(chan struct{}, 1),
	}

	r.lock.Lock()
	if seq != nil {
		consumer.cur = *seq
	} else {
		consumer.cur = r.cur
	}
	if consumer.diff() > 0 {
		consumer.ch <- struct{}{}
	}
	r.consumers = append(r.consumers, consumer)
	r.lock.Unlock()

	return consumer, consumer.ch
}

// RingConsumer is a ring buffer consumer.
type RingConsumer struct {
	ring   *Ring
	cur    uint64
	ch     chan struct{}
	closed bool
}

// diff returns the number of pending messages. It assumes the Ring is locked.
func (rc *RingConsumer) diff() uint64 {
	if rc.cur > rc.ring.cur {
		panic("jounce: consumer cursor greater than producer cursor")
	}
	return rc.ring.cur - rc.cur
}

// Peek returns the next pending message if any without consuming it. A nil
// message is returned if no message is available.
func (rc *RingConsumer) Peek() *irc.Message {
	if rc.closed {
		panic("jounce: RingConsumer.Peek called after Close")
	}

	rc.ring.lock.Lock()
	defer rc.ring.lock.Unlock()

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
		panic("jounce: unexpected nil ring buffer entry")
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
	rc.ring.lock.Lock()
	for i := range rc.ring.consumers {
		if rc.ring.consumers[i] == rc {
			rc.ring.consumers = append(rc.ring.consumers[:i], rc.ring.consumers[i+1:]...)
			break
		}
	}
	rc.ring.lock.Unlock()

	close(rc.ch)
	rc.closed = true
	return rc.cur
}
