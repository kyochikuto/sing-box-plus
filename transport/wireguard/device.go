package wireguard

import (
	"context"
	"net/netip"
	"time"

	"github.com/redpilllabs/wireguard-go/device"
	wgTun "github.com/redpilllabs/wireguard-go/tun"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type Device interface {
	wgTun.Device
	N.Dialer
	Start() error
	SetDevice(device *device.Device)
}

type DeviceOptions struct {
	Context        context.Context
	Logger         logger.ContextLogger
	System         bool
	Handler        tun.Handler
	UDPTimeout     time.Duration
	CreateDialer   func(interfaceName string) N.Dialer
	Name           string
	MTU            uint32
	Address        []netip.Prefix
	AllowedAddress []netip.Prefix
}

func NewDevice(options DeviceOptions) (Device, error) {
	if !options.System {
		return newStackDevice(options)
	} else if options.Handler == nil {
		return newSystemDevice(options)
	} else {
		return newSystemStackDevice(options)
	}
}
