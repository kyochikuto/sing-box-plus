# sing-box-plus

## Cloudflare IP Scanner

Scans for unblocked Cloudflare IPs (currently only WARP CIDRs).
Enable it by setting your Wireguard peer `address`  to `warp_auto` and also optionally enable port scanning by setting the `port` to `0`. You can also limit the scanner to a specific IP range or port by settings the `address` to either of `[warp_8, warp_162, warp_188]` and the port to any port listed in [here](https://github.com/kyochikuto/sing-box-plus/blob/ab5093bd25962847927bbc084f9dfae81c053fa4/warp/endpoint.go#L86):

```json
"endpoints": [ // <- Since sing-box v1.11 Wireguard conns are added to `endpoints`
    {
        "type": "wireguard",
        "tag": "warp-out",
        "system": false,
        "address": [
            "10.0.0.1/32"
        ],
        "private_key": "YOUR_PRIVATE_KEY",
        "peers": [
            {
                "address": "warp_auto", // <- for WarpInWarp configs set this to the original value `engage.cloudflareclient.com` to disable ip scanner and noise generator for the tunneled warp connection
                "port": 2408, // <- set to 0 to pick a random WARP port or set it to a fixed port like this to scan endpoints only with this port
                "public_key": "bmXOC+F1FxEMF9dyiK2H5\/1SUtzH0JuVo51h2wPfgyo=",
                "allowed_ips": [
                    "0.0.0.0/0"
                ]
            }
        ],
        "mtu": 1280
    }
]        
```

## Cloudflare WARP blocking bypass

Bypasses Cloudflare WARP blockings by applying certain Wireguard hacks.
Enabled by default for WARP endpoints with `warp_*` set as their `address` field.

## TLS clientHello Packet Fragmentation
#### ⚠️ Note
TLS fragmentation is deprecated in favor the upcoming implementation in version 1.12 by upstream, keep an eye on this space!

~~ Fragments TLS ClientHello packets in multiple segments, making it harder to drop connections based on SNI filtering.
Enable it by adding the `tls_fragment` entry to any outbound connection: ~~

```json
...
"outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            // DEPRECATED, new version coming in v1.12
            "type": "direct",
            "tag": "fragment",
            "tcp_fast_open": false,
            "tls_fragment": {
                "enabled": true,
                "size": "20-100",
                "sleep": "0-2"
            }
        },
]
...
```

## Example configurations

See the `examples` directory for example configuration files.

## Docker

Docker images are available for `linux/amd64` and `linux/386` architectures at `ghcr.io/kyochikuto/sing-box-plus:latest`.

## Fork License

```text
Copyright (C) 2024 by Kyōchikutō | キョウチクトウ 

This fork includes the following changes:

* [TLS Handshake Fragmentation]
* [WARP Unblocker]
```

Credits to [@bepass-org](https://github.com/bepass-org), [@markpash](https://github.com/markpash), and [@GFW-knocker](https://github.com/GFW-knocker)

## License

```text

Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
