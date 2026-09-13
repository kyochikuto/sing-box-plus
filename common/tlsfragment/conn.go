package tf

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

type Conn struct {
	net.Conn
	tcpConn            *net.TCPConn
	ctx                context.Context
	packetCounter      uint64
	packets            option.IntRange
	length             option.IntRange
	interval           option.IntRange
	maxSplits          uint16
	firstPacketWritten bool
}

func NewConn(ctx context.Context, conn net.Conn, packets option.IntRange, length option.IntRange, interval option.IntRange, maxSplits uint16) *Conn {
	tcpConn, _ := N.UnwrapReader(conn).(*net.TCPConn)
	if maxSplits == 0 {
		maxSplits = 517
	}
	if length.Min == 0 && length.Max == 0 {
		length.Min, length.Max = 1, 517
	}
	return &Conn{
		Conn:      conn,
		tcpConn:   tcpConn,
		ctx:       ctx,
		packets:   packets,
		length:    length,
		interval:  interval,
		maxSplits: maxSplits,
	}
}

// isTLSClientHello returns true if b looks like a TLS ClientHello record.
func isTLSClientHello(b []byte) bool {
	return len(b) > 5 && b[0] == 22
}

// sleepWithContext sleeps for d, but returns early if ctx is cancelled.
// Returns ctx.Err() if cancelled, nil otherwise.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// tlsHandshakeHeaderLen is the size of the TLS handshake sub-header
// (1-byte type + 3-byte length) that must always land in the first fragment.
const tlsHandshakeHeaderLen = 4

// writeTLSFragmented handles TLS-aware fragmentation of a ClientHello record.
//
// TLS record fragmentation (RFC 5246) allows splitting the handshake
// payload across multiple TLSPlaintext records, but each record's payload is
// still part of a single handshake message whose 4-byte sub-header
// (HandshakeType + 3-byte length) must arrive intact in the first fragment so
// the peer can frame the reassembled message. Splitting that header across
// records causes most TLS stacks to abort with an "unexpected message" alert.
//
// Rule enforced here:
//
//	first fragment payload  ≥  tlsHandshakeHeaderLen (4 bytes)
//	every subsequent fragment ≥ 1 byte
func (c *Conn) writeTLSFragmented(b []byte) (int, error) {
	recordLen := 5 + (int(b[3])<<8 | int(b[4]))
	if len(b) < recordLen {
		// Truncated or already-fragmented record — send as-is.
		return c.Conn.Write(b)
	}

	data := b[5:recordLen] // raw handshake payload (type + 3-len + body)

	// Nothing to fragment if the payload is tiny.
	if len(data) <= tlsHandshakeHeaderLen {
		return c.Conn.Write(b)
	}

	if c.tcpConn != nil {
		if err := c.tcpConn.SetNoDelay(true); err != nil {
			return 0, err
		}
		defer c.tcpConn.SetNoDelay(false) //nolint:errcheck
	}

	// Pre-allocate a reusable TLS record header; only bytes [3:5] change.
	hdr := make([]byte, 5)
	copy(hdr[:3], b[:3]) // content type (22) + legacy version

	// When interval == 0 we batch all fragments into a single Write.
	var batch []byte
	if c.interval.Max == 0 {
		batch = make([]byte, 0, recordLen)
	}

	writeFragment := func(payload []byte) error {
		l := len(payload)
		hdr[3] = byte(l >> 8)
		hdr[4] = byte(l)

		if c.interval.Max == 0 {
			batch = append(batch, hdr...)
			batch = append(batch, payload...)
			return nil
		}

		frag := make([]byte, 5+l)
		copy(frag[:5], hdr)
		copy(frag[5:], payload)
		_, err := c.Conn.Write(frag)
		return err
	}

	var splitCount uint16
	for from := 0; from < len(data); {
		// The first fragment must carry at least the 4-byte handshake sub-header
		// so the peer can frame the reassembled handshake message.
		minSize := 1
		if from == 0 {
			minSize = tlsHandshakeHeaderLen
		}

		size := max(c.length.Random(), minSize)

		to := from + size
		splitCount++

		if to > len(data) || (c.maxSplits > 0 && splitCount >= c.maxSplits) {
			to = len(data)
		}

		if err := writeFragment(data[from:to]); err != nil {
			return from, err
		}

		from = to

		if from < len(data) && c.interval.Max > 0 {
			interval := time.Duration(c.interval.Random()) * time.Millisecond
			if err := sleepWithContext(c.ctx, interval); err != nil {
				return from, err
			}
		}
	}

	if batch != nil {
		if _, err := c.Conn.Write(batch); err != nil {
			return 0, err
		}
	}

	// Forward any data that followed the TLS record in the same Write call.
	if len(b) > recordLen {
		n, err := c.Conn.Write(b[recordLen:])
		if err != nil {
			return recordLen + n, err
		}
	}

	return len(b), nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	// Increment first so WriterReplaceable stays consistent.
	c.packetCounter++

	// TLS-only mode: fragment only the very first packet if it is a ClientHello.
	if c.packets.Min == 0 && c.packets.Max == 1 {
		if c.packetCounter == 1 && isTLSClientHello(b) {
			n, err = c.writeTLSFragmented(b)
		} else {
			n, err = c.Conn.Write(b)
		}
		if !c.firstPacketWritten && err == nil {
			c.firstPacketWritten = true
		}
		return
	}

	// Pass-through when outside the configured packet range.
	if c.packets.Min != 0 &&
		(c.packetCounter < uint64(c.packets.Min) || c.packetCounter > uint64(c.packets.Max)) {
		return c.Conn.Write(b)
	}

	// Generic (non-TLS-aware) fragmentation.
	var splitCount uint16
	for from := 0; from < len(b); {
		to := from + c.length.Random()
		splitCount++

		if to > len(b) || (c.maxSplits > 0 && splitCount >= c.maxSplits) {
			to = len(b)
		}

		written, werr := c.Conn.Write(b[from:to])
		from += written
		if werr != nil {
			return from, werr
		}

		if from < len(b) {
			interval := time.Duration(c.interval.Random()) * time.Millisecond
			if err := sleepWithContext(c.ctx, interval); err != nil {
				return from, err
			}
		}
	}

	return len(b), nil
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	switch c.packets.Max {
	case 0:
		// No fragmentation configured at all.
		return true
	case 1:
		// TLS-only mode: replaceable once the first packet has been handled.
		return c.firstPacketWritten
	default:
		// Range mode: replaceable only outside the active fragmentation window.
		return c.packetCounter < uint64(c.packets.Min) || c.packetCounter > uint64(c.packets.Max)
	}
}

func (c *Conn) Upstream() any {
	return c.Conn
}
