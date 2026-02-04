package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	tf "github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
)

type STDClientConfig struct {
	ctx      context.Context
	config   *tls.Config
	fragment *option.OutboundTLSFragmentOptions
}

func (c *STDClientConfig) ServerName() string {
	return c.config.ServerName
}

func (c *STDClientConfig) SetServerName(serverName string) {
	c.config.ServerName = serverName
}

func (c *STDClientConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *STDClientConfig) SetNextProtos(nextProto []string) {
	c.config.NextProtos = nextProto
}

func (c *STDClientConfig) Config() (*STDConfig, error) {
	return c.config, nil
}

func (c *STDClientConfig) Client(conn net.Conn) (Conn, error) {
	if c.fragment != nil && c.fragment.Enabled {
		conn = tf.NewConn(conn, c.ctx, c.fragment.Packets, c.fragment.Length, c.fragment.Interval, c.fragment.MaxSplits)
	}
	return tls.Client(conn, c.config), nil
}

func (c *STDClientConfig) Clone() Config {
	return &STDClientConfig{c.ctx, c.config.Clone(), c.fragment}
}

func (c *STDClientConfig) ECHConfigList() []byte {
	return c.config.EncryptedClientHelloConfigList
}

func (c *STDClientConfig) SetECHConfigList(EncryptedClientHelloConfigList []byte) {
	c.config.EncryptedClientHelloConfigList = EncryptedClientHelloConfigList
}

func NewSTDClient(ctx context.Context, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	var serverName string
	if options.ServerName != "" {
		serverName = options.ServerName
	} else if serverAddress != "" {
		serverName = serverAddress
	}
	if serverName == "" && !options.Insecure {
		return nil, E.New("missing server_name or insecure=true")
	}

	var tlsConfig tls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	tlsConfig.RootCAs = adapter.RootPoolFromContext(ctx)
	if !options.DisableSNI {
		tlsConfig.ServerName = serverName
	}
	if options.Insecure {
		tlsConfig.InsecureSkipVerify = options.Insecure
	} else if options.DisableSNI {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			verifyOptions := x509.VerifyOptions{
				Roots:         tlsConfig.RootCAs,
				DNSName:       serverName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				verifyOptions.Intermediates.AddCert(cert)
			}
			if tlsConfig.Time != nil {
				verifyOptions.CurrentTime = tlsConfig.Time()
			}
			_, err := state.PeerCertificates[0].Verify(verifyOptions)
			return err
		}
	}
	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = options.ALPN
	}
	if options.MinVersion != "" {
		minVersion, err := ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		tlsConfig.MinVersion = minVersion
	}
	if options.MaxVersion != "" {
		maxVersion, err := ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		tlsConfig.MaxVersion = maxVersion
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(options.Certificate) > 0 {
		certificate = []byte(strings.Join(options.Certificate, "\n"))
	} else if options.CertificatePath != "" {
		content, err := os.ReadFile(options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("failed to parse certificate:\n\n", certificate)
		}
		tlsConfig.RootCAs = certPool
	}
	stdConfig := &STDClientConfig{ctx, &tlsConfig, options.Fragment}
	if options.ECH != nil && options.ECH.Enabled {
		return parseECHClientConfig(ctx, stdConfig, options)
	} else {
		return stdConfig, nil
	}
}
