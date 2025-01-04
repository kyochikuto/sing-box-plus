package wireguard

import (
	"github.com/redpilllabs/wireguard-go/tun"
	N "github.com/sagernet/sing/common/network"
)

type Device interface {
	tun.Device
	N.Dialer
	Start() error
	// NewEndpoint() (stack.LinkEndpoint, error)
}
