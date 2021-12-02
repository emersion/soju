package soju

import (
	"math/rand"
	"time"
)

// backoffer implements a simple exponential backoff.
type backoffer struct {
	min, max, jitter time.Duration
	n                int64
}

func newBackoffer(min, max, jitter time.Duration) *backoffer {
	return &backoffer{min: min, max: max, jitter: jitter}
}

func (b *backoffer) Reset() {
	b.n = 0
}

func (b *backoffer) Next() time.Duration {
	if b.n == 0 {
		b.n = 1
		return 0
	}

	d := time.Duration(b.n) * b.min
	if d > b.max {
		d = b.max
	} else {
		b.n *= 2
	}

	if b.jitter != 0 {
		d += time.Duration(rand.Int63n(int64(b.jitter)))
	}

	return d
}
