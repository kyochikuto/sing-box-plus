---
icon: material/new-box
---

!!! question "Since sing-box 1.11.0"

### Structure

```json
{
  "type": "wireguard",
  "tag": "wg-ep",
  
  "system": false,
  "name": "",
  "mtu": 1408,
  "address": [],
  "private_key": "",
  "listen_port": 10000,
  "peers": [
    {
      "address": "127.0.0.1",
      "port": 10001,
      "public_key": "",
      "pre_shared_key": "",
      "allowed_ips": [],
      "persistent_keepalive_interval": 0,
      "reserved": [0, 0, 0],
      "warp_scanner": {
        "enable_ip_scanner": false,
        "enable_port_scanner": false,
        "cidrs": [
          "8.6.112.0/24"
        ]
      },
      "warp_noise": {
        "enable": false,
        "packet_count": "30-50",
        "packet_delay": "10-20"
      }
    }
  ],
  "udp_timeout": "",
  "workers": 0,
 
  ... // Dial Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### system

Use system interface.

Requires privilege and cannot conflict with exists system interfaces.

#### name

Custom interface name for system interface.

#### mtu

WireGuard MTU.

`1408` will be used by default.

#### address

==Required==

List of IP (v4 or v6) address prefixes to be assigned to the interface.

#### private_key

==Required==

WireGuard requires base64-encoded public and private keys. These can be generated using the wg(8) utility:

```shell
wg genkey
echo "private key" || wg pubkey
```

or `sing-box generate wg-keypair`.

#### peers

==Required==

List of WireGuard peers.

#### peers.address

WireGuard peer address.

#### peers.port

WireGuard peer port.

#### peers.public_key

==Required==

WireGuard peer public key.

#### peers.pre_shared_key

WireGuard peer pre-shared key.

#### peers.allowed_ips

==Required==

WireGuard allowed IPs.

#### peers.persistent_keepalive_interval

WireGuard persistent keepalive interval, in seconds.

Disabled by default.

#### peers.reserved

WireGuard reserved field bytes.

### WARP Scanner Fields

Scans for unblocked Cloudflare WARP endpoints and ports.

#### enable_ip_scanner

Enable scanning for working Cloudflare WARP endpoint IPs.

#### enable_port_scanner

Enable scanning for working Cloudflare WARP endpoint ports.

#### cidrs

List of CIDR prefixes to be scanned. If empty, all IPv4 and IPv6 addresses will be scanned.

### WARP Handshake Noise Generator Fields

#### enable

Enable WARP handshake noise generator, sends fake QUIC packets before a handshake to bypass handshake detection.

#### packet_count

Number of fake QUIC packets to send. This can be either a fixed number or a range.

Valid examples: `10`, `10-20`

#### packet_delay

Delay between fake QUIC packets, in milliseconds. This can be either a fixed number or a range.

Valid examples: `10`, `10-20`

#### udp_timeout

UDP NAT expiration time.

`5m` will be used by default.

#### workers

WireGuard worker count.

CPU count is used by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
