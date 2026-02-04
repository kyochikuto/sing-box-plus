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
	tcpConn       *net.TCPConn
	ctx           context.Context
	packetCounter uint64
	packets       option.IntRange
	length        option.IntRange
	interval      option.IntRange
	maxSplits     uint16
}

func NewConn(conn net.Conn, ctx context.Context, packets option.IntRange, length option.IntRange, interval option.IntRange, maxSplits uint16) *Conn {
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

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.length.Max == 0 {
		return c.Conn.Write(b)
	}

	c.packetCounter++

	if c.packets.Min == 0 && c.packets.Max == 1 {
		if c.packetCounter != 1 || len(b) <= 5 || b[0] != 22 {
			return c.Conn.Write(b)
		}

		// Parse TLS record length
		recordLen := 5 + (int(b[3])<<8 | int(b[4]))
		if len(b) < recordLen {
			// Maybe already fragmented somehow
			return c.Conn.Write(b)
		}

		// Enable TCP_NODELAY for immediate sending
		if c.tcpConn != nil {
			err = c.tcpConn.SetNoDelay(true)
			if err != nil {
				return
			}
			defer c.tcpConn.SetNoDelay(false)
		}

		// Extract the handshake data (without the 5-byte header)
		data := b[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		var splitCount uint16

		for from := 0; ; {
			// Calculate fragment size
			to := from + c.length.Random()
			splitCount++

			// Check if we've reached the end or max splits
			if to > len(data) || (c.maxSplits > 0 && splitCount >= c.maxSplits) {
				to = len(data)
			}

			l := to - from

			// Ensure buffer is large enough
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}

			// Build TLS record: copy header, update length, add fragment data
			copy(buff[:3], b[:3]) // Copy record type and version
			copy(buff[5:], data[from:to])
			from = to

			// Update record length in header
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)

			// If interval is 0, combine all fragments
			if c.interval.Max == 0 {
				hello = append(hello, buff[:5+l]...)
			} else {
				// Write fragment immediately
				_, err = c.Conn.Write(buff[:5+l])
				if err != nil {
					return 0, err
				}
				// Add delay between fragments (except after the last one)
				if from < len(data) {
					interval := time.Duration(c.interval.Random()) * time.Millisecond
					time.Sleep(interval)
				}
			}

			// Check if we've processed all data
			if from >= len(data) {
				// Write combined hello if we were buffering (intervalMax == 0)
				if len(hello) > 0 {
					_, err = c.Conn.Write(hello)
					if err != nil {
						return 0, err
					}
				}

				// Write any remaining data after the TLS record
				if len(b) > recordLen {
					n, err = c.Conn.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}

				return len(b), nil
			}
		}
	}

	// Check if this packet should be fragmented based on packet count
	if c.packets.Min != 0 && (c.packetCounter < uint64(c.packets.Min) || c.packetCounter > uint64(c.packets.Max)) {
		return c.Conn.Write(b)
	}

	// Fragment the packet (non-TLS-aware fragmentation)
	var splitCount uint16

	for from := 0; ; {
		to := from + c.length.Random()
		splitCount++

		if to > len(b) || (c.maxSplits > 0 && splitCount >= c.maxSplits) {
			to = len(b)
		}

		n, err := c.Conn.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}

		// Add delay between fragments
		if from < len(b) {
			time.Sleep(time.Duration(c.interval.Random()) * time.Millisecond)
		}

		if from >= len(b) {
			return from, nil
		}
	}
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return c.packets.Min != 0 && (c.packetCounter < uint64(c.packets.Min) || c.packetCounter > uint64(c.packets.Max))
}

func (c *Conn) Upstream() any {
	return c.Conn
}
