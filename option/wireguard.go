package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type WireGuardEndpointOptions struct {
	System     bool                             `json:"system,omitempty"`
	Name       string                           `json:"name,omitempty"`
	MTU        uint32                           `json:"mtu,omitempty"`
	Address    badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey string                           `json:"private_key"`
	ListenPort uint16                           `json:"listen_port,omitempty"`
	Peers      []WireGuardPeer                  `json:"peers,omitempty"`
	UDPTimeout badoption.Duration               `json:"udp_timeout,omitempty"`
	Workers    int                              `json:"workers,omitempty"`
	DialerOptions
}

type WireGuardPeer struct {
	Address                     string                           `json:"address,omitempty"`
	Port                        uint16                           `json:"port,omitempty"`
	PublicKey                   string                           `json:"public_key,omitempty"`
	PreSharedKey                string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs                  badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval uint16                           `json:"persistent_keepalive_interval,omitempty"`
	Reserved                    []uint8                          `json:"reserved,omitempty"`
	WarpScanner                 WarpScannerOptions               `json:"warp_scanner"`
	WarpNoise                   WarpNoiseOptions                 `json:"warp_noise"`
}

type WarpScannerOptions struct {
	EnableIpScanner   bool                             `json:"enable_ip_scanner,omitempty"`
	EnablePortScanner bool                             `json:"enable_port_scanner,omitempty"`
	Cidrs             badoption.Listable[netip.Prefix] `json:"cidrs,omitempty"`
}

type WarpNoiseOptions struct {
	Enable      bool     `json:"enable,omitempty"`
	PacketCount IntRange `json:"packet_count"`
	PacketDelay IntRange `json:"packet_delay"`
}
