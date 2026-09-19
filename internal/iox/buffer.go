package iox

import (
	"bytes"
	"io"
)

// LimitedBuffer is an [io.Writer] that retains at most a configured number of
// bytes in memory.
//
// After the limit is exceeded, LimitedBuffer records the overflow and silently
// discards the excess while continuing to report complete successful writes.
// This allows it to collect bounded output from a child process without
// blocking that process or turning an oversized response into a broken-pipe
// error.
type LimitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

var _ io.Writer = (*LimitedBuffer)(nil)

// NewLimitedBuffer returns a LimitedBuffer that retains at most limit bytes.
// It panics if limit is negative.
func NewLimitedBuffer(limit int) *LimitedBuffer {
	if limit < 0 {
		panic("internal: negative LimitedBuffer limit")
	}
	return &LimitedBuffer{limit: limit}
}

// Write retains as much of contents as fits within the configured limit.
// It always reports the entire input as written and returns a nil error.
func (b *LimitedBuffer) Write(contents []byte) (int, error) {
	written := len(contents)
	remaining := b.limit - b.buffer.Len()
	if len(contents) <= remaining {
		_, _ = b.buffer.Write(contents)
		return written, nil
	}
	if remaining > 0 {
		_, _ = b.buffer.Write(contents[:remaining])
	}
	b.overflow = true
	return written, nil
}

// Bytes returns the portion of the input retained by the buffer.
func (b *LimitedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

// Overflow reports whether any input was discarded because it exceeded the
// configured limit.
func (b *LimitedBuffer) Overflow() bool {
	return b.overflow
}
