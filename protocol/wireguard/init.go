package wireguard

import (
	"github.com/redpilllabs/wireguard-go/conn"
	"github.com/sagernet/sing-box/common/dialer"
)

func init() {
	dialer.WgControlFns = conn.ControlFns
}
