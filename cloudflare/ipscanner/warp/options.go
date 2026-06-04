package warp

import (
	"net/netip"
	"time"
)

type WarpScannerOptions struct {
	MaxRTT   time.Duration
	V4       bool
	V6       bool
	CidrList []netip.Prefix
	Port     uint16
}
