package wireguard

import (
	"github.com/fractal-networking/wireguard-go/conn"
	"github.com/sagernet/sing-box/common/dialer"
)

func init() {
	dialer.WgControlFns = conn.ControlFns
}
