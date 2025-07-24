package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redpilllabs/wireguard-go/conn"
	"github.com/redpilllabs/wireguard-go/device"
	"github.com/sagernet/sing-box/ipscanner"
	"github.com/sagernet/sing-box/warp"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

type Endpoint struct {
	options        EndpointOptions
	peers          []peerConfig
	ipcConf        string
	allowedAddress []netip.Prefix
	tunDevice      Device
	device         *device.Device
	pause          pause.Manager
	pauseCallback  *list.Element[pause.Callback]
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	privateKey := hex.EncodeToString(privateKeyBytes)
	ipcConf := "private_key=" + privateKey
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	var peers []peerConfig
	for peerIndex, rawPeer := range options.Peers {
		peer := peerConfig{
			allowedIPs: rawPeer.AllowedIPs,
			keepalive:  rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.Addr.IsValid() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		} else if rawPeer.Endpoint.IsFqdn() {
			if warp.IsPeerCloudflareWarp(rawPeer.PublicKey) {
				switch rawPeer.Endpoint.AddrString() {
				case "warp_auto":
					options.Logger.Info("running WARP IP scanner on all subnets, this might take a while...")

					bestEndpoint, err := scanWarpEndpoints(options.PrivateKey, warp.All, rawPeer.Endpoint.Port)
					if err != nil {
						return nil, err
					}
					options.Logger.Info(fmt.Sprintf("fastest WARP endpoint available is %s with RTT of %s ", bestEndpoint.AddrPort.String(), bestEndpoint.RTT.String()))

					peer.endpoint = bestEndpoint.AddrPort
					peer.enableWarpNoiseGen = true
				case "warp_188":
					options.Logger.Info("running WARP IP scanner on the 188.114.x.x subnet, this might take a while...")

					bestEndpoint, err := scanWarpEndpoints(options.PrivateKey, warp.Prefix188, rawPeer.Endpoint.Port)
					if err != nil {
						return nil, err
					}
					options.Logger.Info(fmt.Sprintf("fastest WARP endpoint available is %s with RTT of %s ", bestEndpoint.AddrPort.String(), bestEndpoint.RTT.String()))

					peer.endpoint = bestEndpoint.AddrPort
					peer.enableWarpNoiseGen = true
				case "warp_162":
					options.Logger.Info("running WARP IP scanner on the 162.159.x.x subnet, this might take a while...")

					bestEndpoint, err := scanWarpEndpoints(options.PrivateKey, warp.Prefix162, rawPeer.Endpoint.Port)
					if err != nil {
						return nil, err
					}
					options.Logger.Info(fmt.Sprintf("fastest WARP endpoint available is %s with RTT of %s ", bestEndpoint.AddrPort.String(), bestEndpoint.RTT.String()))

					peer.endpoint = bestEndpoint.AddrPort
					peer.enableWarpNoiseGen = true
				case "warp_8":
					options.Logger.Info("running WARP IP scanner on the 8.x.x.x subnet, this might take a while...")

					bestEndpoint, err := scanWarpEndpoints(options.PrivateKey, warp.Prefix8, rawPeer.Endpoint.Port)
					if err != nil {
						return nil, err
					}
					options.Logger.Info(fmt.Sprintf("fastest WARP endpoint available is %s with RTT of %s ", bestEndpoint.AddrPort.String(), bestEndpoint.RTT.String()))

					peer.endpoint = bestEndpoint.AddrPort
					peer.enableWarpNoiseGen = true
				default:
					peer.destination = rawPeer.Endpoint
				}
			} else {
				peer.destination = rawPeer.Endpoint
			}
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		peer.publicKeyHex = hex.EncodeToString(publicKeyBytes)
		if rawPeer.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if len(rawPeer.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		if len(rawPeer.Reserved) > 0 {
			if len(rawPeer.Reserved) != 3 {
				return nil, E.New("invalid reserved value for peer ", peerIndex, ", required 3 bytes, got ", len(peer.reserved))
			}
			copy(peer.reserved[:], rawPeer.Reserved[:])
		}
		peers = append(peers, peer)
	}
	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()
	if options.MTU == 0 {
		options.MTU = 1408
	}
	deviceOptions := DeviceOptions{
		Context:        options.Context,
		Logger:         options.Logger,
		System:         options.System,
		Handler:        options.Handler,
		UDPTimeout:     options.UDPTimeout,
		CreateDialer:   options.CreateDialer,
		Name:           options.Name,
		MTU:            options.MTU,
		Address:        options.Address,
		AllowedAddress: allowedAddresses,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	return &Endpoint{
		options:        options,
		peers:          peers,
		ipcConf:        ipcConf,
		allowedAddress: allowedAddresses,
		tunDevice:      tunDevice,
	}, nil
}

func (e *Endpoint) Start(resolve bool) error {
	if common.Any(e.peers, func(peer peerConfig) bool {
		return !peer.endpoint.IsValid() && peer.destination.IsFqdn()
	}) {
		if !resolve {
			return nil
		}
		for peerIndex, peer := range e.peers {
			if peer.endpoint.IsValid() || !peer.destination.IsFqdn() {
				continue
			}
			destinationAddress, err := e.options.ResolvePeer(peer.destination.Fqdn)
			if err != nil {
				return E.Cause(err, "resolve endpoint domain for peer[", peerIndex, "]: ", peer.destination)
			}
			e.peers[peerIndex].endpoint = netip.AddrPortFrom(destinationAddress, peer.destination.Port)
		}
	} else if resolve {
		return nil
	}
	var bind conn.Bind
	wgListener, isWgListener := common.Cast[conn.Listener](e.options.Dialer)
	if isWgListener {
		bind = conn.NewStdNetBind(wgListener)
	} else {
		var (
			isConnect   bool
			connectAddr netip.AddrPort
			reserved    [3]uint8
		)
		if len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
			isConnect = true
			connectAddr = e.peers[0].endpoint
			reserved = e.peers[0].reserved
		}
		bind = NewClientBind(e.options.Context, e.options.Logger, e.options.Dialer, isConnect, connectAddr, reserved)
	}
	if isWgListener || len(e.peers) > 1 {
		for _, peer := range e.peers {
			if peer.reserved != [3]uint8{} {
				bind.SetReservedForEndpoint(peer.endpoint, peer.reserved)
			}
		}
	}
	err := e.tunDevice.Start()
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	wgDevice := device.NewDevice(e.options.Context, e.tunDevice, bind, logger, e.options.Workers)
	e.tunDevice.SetDevice(wgDevice)
	ipcConf := e.ipcConf
	for _, peer := range e.peers {
		ipcConf += peer.GenerateIpcLines()
	}
	err = wgDevice.IpcSet(ipcConf)
	if err != nil {
		return E.Cause(err, "setup wireguard: \n", ipcConf)
	}
	e.device = wgDevice
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) Close() error {
	if e.device != nil {
		e.device.Close()
	}
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
	}
	return nil
}

func (e *Endpoint) onPauseUpdated(event int) {
	switch event {
	case pause.EventDevicePaused, pause.EventNetworkPause:
		e.device.Down()
	case pause.EventDeviceWake, pause.EventNetworkWake:
		e.device.Up()
	}
}

type peerConfig struct {
	destination        M.Socksaddr
	endpoint           netip.AddrPort
	publicKeyHex       string
	preSharedKeyHex    string
	allowedIPs         []netip.Prefix
	keepalive          uint16
	reserved           [3]uint8
	enableWarpNoiseGen bool
}

func (c peerConfig) GenerateIpcLines() string {
	ipcLines := "\npublic_key=" + c.publicKeyHex
	if c.endpoint.IsValid() {
		ipcLines += "\nendpoint=" + c.endpoint.String()
	}
	if c.preSharedKeyHex != "" {
		ipcLines += "\npreshared_key=" + c.preSharedKeyHex
	}
	for _, allowedIP := range c.allowedIPs {
		ipcLines += "\nallowed_ip=" + allowedIP.String()
	}
	if c.keepalive > 0 {
		ipcLines += "\npersistent_keepalive_interval=" + F.ToString(c.keepalive)
	}
	if c.enableWarpNoiseGen {
		ipcLines += "\nenable_warp_noise_gen=true"
	}

	return ipcLines
}

func isPeerCloudflareWarp(publicKey string) bool {
	if publicKey == warp.WarpPublicKey {
		return true
	}

	return false
}

func scanWarpEndpoints(privateKey string, cidrPrefix warp.Prefix, port uint16) (ipscanner.IPInfo, error) {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	scanOpts := ipscanner.WarpScanOptions{
		PrivateKey: privateKey,
		PublicKey:  warp.WarpPublicKey,
		MaxRTT:     500 * time.Millisecond,
		V4:         true,
		V6:         true,
		Port:       port,
		CidrPrefix: cidrPrefix,
	}

	return ipscanner.RunWarpScan(ctx, scanOpts)
}
