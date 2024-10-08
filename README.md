# sing-box
Sing-Box + Blocking Bypass Hacks = ❤️


### Cloudflare IP Scanner

Scans for unblocked Cloudflare IPs (currently only WARP CIDRs).
Enable it by setting your Wireguard peer `server`  to `warp_auto`, and also optionally enable port scanning by setting the `server_port` to `0`:
```
{
            "type": "wireguard",
            "tag": "warp-out",
            "local_address": [
                "10.0.0.2/32"
            ],
            "private_key": "YOUR_PRIVATE_KEY",
            "peers": [
                {
                    "server": "warp_auto",  // <- for WarpInWarp configs set this to the original value `engage.cloudflareclient.com` to disable ip scanner and noise generator for the tunneled warp connection
                    "server_port": 2408,  // <- set to 0 to pick a random WARP port or set it to a fixed port like this to scan endpoints only with this port
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5\/1SUtzH0JuVo51h2wPfgyo=",
                    "allowed_ips": [
                        "0.0.0.0/0"
                    ],
                    "reserved": [
                        80,
                        183,
                        166
                    ]
                }
            ],
            "mtu": 1280
        }
```

### Cloudflare WARP blocking bypass

Bypasses Cloudflare WARP blockings by applying certain Wireguard hacks.
Enabled by default for WARP endpoints with `warp_auto` set as their `server` field.

### TLS clientHello Packet Fragmentation
Fragments TLS ClientHello packets in multiple segments, making it harder to drop connections based on SNI filtering.
Enable it by adding the `tls_fragment` entry to any outbound connection:

```
...
"outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "direct",
            "tag": "fragment",
            "tcp_fast_open": false,
            "tls_fragment": {
                "enabled": true,
                "size": "20-100",
                "sleep": "0-2"
            }
        },
...
```

## Example configurations

See the `examples` directory for example configuration files.

## Docker

Docker images are available for `linux/amd64` and `linux/386` architectures at `ghcr.io/kyochikuto/sing-box-plus:latest`.

## Fork License
```
Copyright (C) 2024 by Kyōchikutō | キョウチクトウ 

This fork includes the following changes:

* [TLS Fragmentation]
* [WARP Unblocker]
```

Credits to [@bepass-org](https://github.com/bepass-org), [@markpash](https://github.com/markpash), and [@GFW-knocker](https://github.com/GFW-knocker)

## License

```

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


