package ipscanner

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/sing-box/cloudflare/ipscanner/engine"
	"github.com/sagernet/sing-box/cloudflare/ipscanner/statute"
	"github.com/sagernet/sing-box/cloudflare/ipscanner/warp"
)

type IPInfo = statute.IPInfo

type IPScanner struct {
	options statute.ScannerOptions
	log     *slog.Logger
	engine  *engine.Engine
}

var googlev6DNSAddr80 = netip.MustParseAddrPort("[2001:4860:4860::8888]:80")

func NewScanner(options ...Option) *IPScanner {
	p := &IPScanner{
		options: statute.ScannerOptions{
			UseIPv4:           true,
			UseIPv6:           true,
			CidrList:          statute.DefaultCFRanges(),
			Logger:            slog.Default(),
			WarpPresharedKey:  "",
			WarpPeerPublicKey: "",
			WarpPrivateKey:    "",
			IPQueueSize:       8,
			MaxDesirableRTT:   500 * time.Millisecond,
			IPQueueTTL:        30 * time.Second,
		},
		log: slog.Default(),
	}

	for _, option := range options {
		option(p)
	}

	return p
}

type Option func(*IPScanner)

func WithUseIPv4(useIPv4 bool) Option {
	return func(i *IPScanner) {
		i.options.UseIPv4 = useIPv4
	}
}

func WithUseIPv6(useIPv6 bool) Option {
	return func(i *IPScanner) {
		i.options.UseIPv6 = useIPv6
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(i *IPScanner) {
		i.log = logger
		i.options.Logger = logger
	}
}

func WithCidrList(cidrList []netip.Prefix) Option {
	return func(i *IPScanner) {
		i.options.CidrList = cidrList
	}
}

func WithIPQueueSize(size int) Option {
	return func(i *IPScanner) {
		i.options.IPQueueSize = size
	}
}

func WithMaxDesirableRTT(threshold time.Duration) Option {
	return func(i *IPScanner) {
		i.options.MaxDesirableRTT = threshold
	}
}

func WithIPQueueTTL(ttl time.Duration) Option {
	return func(i *IPScanner) {
		i.options.IPQueueTTL = ttl
	}
}

func WithWarpPrivateKey(privateKey string) Option {
	return func(i *IPScanner) {
		i.options.WarpPrivateKey = privateKey
	}
}

func WithWarpPeerPublicKey(peerPublicKey string) Option {
	return func(i *IPScanner) {
		i.options.WarpPeerPublicKey = peerPublicKey
	}
}

func WithWarpPreSharedKey(presharedKey string) Option {
	return func(i *IPScanner) {
		i.options.WarpPresharedKey = presharedKey
	}
}

func WithPort(port uint16) Option {
	return func(i *IPScanner) {
		i.options.Port = port
	}
}

// run engine and in case of new event call onChange callback also if it gets canceled with context
// cancel all operations

func (i *IPScanner) Run(ctx context.Context) {
	if !i.options.UseIPv4 && !i.options.UseIPv6 {
		i.log.Error("Fatal: both IPv4 and IPv6 are disabled, nothing to do")
		return
	}
	i.engine = engine.NewScannerEngine(&i.options)
	go i.engine.Run(ctx)
}

func (i *IPScanner) GetAvailableIPs() []statute.IPInfo {
	if i.engine != nil {
		return i.engine.GetAvailableIPs(false)
	}
	return nil
}

func findMinRTT(ipInfos []statute.IPInfo) (statute.IPInfo, error) {
	if len(ipInfos) == 0 {
		return statute.IPInfo{}, errors.New("list is empty")
	}

	minRTTInfo := ipInfos[0]
	for _, ipInfo := range ipInfos[1:] {
		if ipInfo.RTT < minRTTInfo.RTT {
			minRTTInfo = ipInfo
		}
	}

	return minRTTInfo, nil
}

func CanConnectIPv6(remoteAddr netip.AddrPort) bool {
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := dialer.Dial("tcp6", remoteAddr.String())
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func RunWarpScan(ctx context.Context, opts warp.WarpScannerOptions) (result statute.IPInfo, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	scanner := NewScanner(
		WithLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))),
		WithWarpPrivateKey("yGXeX7gMyUIZmK5QIgC7+XX5USUSskQvBYiQ6LdkiXI="),
		WithWarpPeerPublicKey("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="),
		WithUseIPv4(opts.V4),
		WithUseIPv6(CanConnectIPv6(googlev6DNSAddr80)),
		WithMaxDesirableRTT(opts.MaxRTT),
		WithCidrList(opts.CidrList),
		WithPort(opts.Port),
		WithIPQueueSize(0xffff),
	)

	scanner.Run(ctx)

	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	var ipList []statute.IPInfo
	seen := make(map[string]bool) // Deduplication map

	for {
		newIPs := scanner.GetAvailableIPs()
		for _, ip := range newIPs {
			key := ip.AddrPort.String() // Uniquely identifies an IP:port pair
			if !seen[key] {
				ipList = append(ipList, ip)
				seen[key] = true
			}
		}

		if len(ipList) >= 1 {
			bestIp, err := findMinRTT(ipList)
			if err != nil {
				return statute.IPInfo{}, err
			}
			return bestIp, nil
		}

		select {
		case <-ctx.Done():
			// Context is done - canceled externally
			return statute.IPInfo{}, errors.New("user canceled the operation or the operation timed out")
		case <-t.C:
			// Keep looping, waiting for new results
		}
	}
}
