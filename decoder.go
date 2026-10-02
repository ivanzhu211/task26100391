package syslogevidence

import (
	"errors"
	"fmt"
)

// Result is one decoded outcome: either a message or an error, never both.
type Result struct {
	Message *Message
	Err     error
}

// Decoder consumes arbitrary byte chunks of length-counted frames and
// delivers one Result per frame via the Emit callback. A frame is
// "<decimal length><SP><body of exactly length bytes>".
type Decoder struct {
	emit   func(Result)
	buf    []byte
	closed bool
	failed bool
}

// NewDecoder creates a Decoder that delivers one result per frame to emit.
func NewDecoder(emit func(Result)) *Decoder {
	return &Decoder{emit: emit}
}

// Write feeds a chunk of framed input. Chunks may split frames at any byte
// and may contain multiple complete frames. Results are emitted
// synchronously, one per complete frame.
func (d *Decoder) Write(p []byte) error {
	if d.closed {
		return errors.New("write after close")
	}
	if d.failed {
		return errors.New("decoder is in failed state")
	}
	d.buf = append(d.buf, p...)
	for {
		n, headerLen, ok, err := scanFrameHeader(d.buf)
		if err != nil {
			d.failed = true
			d.emit(Result{Err: err})
			return err
		}
		if !ok {
			return nil // need more bytes
		}
		if len(d.buf) < headerLen+n {
			return nil // body not fully arrived yet
		}
		body := d.buf[headerLen : headerLen+n]
		msg, perr := ParseMessage(body)
		if perr != nil {
			d.emit(Result{Err: fmt.Errorf("invalid message body: %w", perr)})
		} else {
			d.emit(Result{Message: msg})
		}
		d.buf = d.buf[headerLen+n:]
	}
}

// Close signals end of input. If a frame is incomplete, a terminal error
// result is emitted; results already delivered remain valid. Ending exactly
// on a frame boundary is not an error.
func (d *Decoder) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	if len(d.buf) > 0 {
		d.emit(Result{Err: fmt.Errorf("input ended with %d bytes of an incomplete frame", len(d.buf))})
	}
	return nil
}

// scanFrameHeader parses "<digits><SP>" at the start of buf. ok is false
// when more bytes are needed to decide.
func scanFrameHeader(buf []byte) (length int, headerLen int, ok bool, err error) {
	for i, b := range buf {
		if b == ' ' {
			if i == 0 {
				return 0, 0, false, errors.New("empty frame length")
			}
			n := 0
			for _, d := range buf[:i] {
				n = n*10 + int(d-'0')
				if n > 1<<30 {
					return 0, 0, false, errors.New("frame length too large")
				}
			}
			return n, i + 1, true, nil
		}
		if b < '0' || b > '9' {
			return 0, 0, false, fmt.Errorf("invalid byte 0x%02x in frame length", b)
		}
	}
	return 0, 0, false, nil
}
