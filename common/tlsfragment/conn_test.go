package tf_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestTLSFragment(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), option.IntRange{Min: 1, Max: 1}, option.IntRange{Min: 1, Max: 1}, option.IntRange{Min: 4, Max: 4}, 517), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}
