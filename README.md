# sing-box-plus

## Cloudflare WARP IP Scanner and Unblocker

Scans for Cloudflare WARP IPs and applies some tricks to mask the WARP handshake as legitimate QUIC traffic to bypass firewall blockings.
Enable them by configuring your Wireguard endpoint as the following:

```json
"endpoints": [
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
                "address": "engage.cloudflareclient.com",
                "port": 2408,
                "public_key": "bmXOC+F1FxEMF9dyiK2H5\/1SUtzH0JuVo51h2wPfgyo=",
                "allowed_ips": [
                    "0.0.0.0/0"
                ],
                // setting the `reserved` field may not work on some networks, experiment
                // "reserved": [109,250,239],
                "warp_scanner": {
                    "enable_ip_scanner": true,
                    "enable_port_scanner": true,
                    // Limit the scanner to these prefixes only, will scan all known WARP CIDRs if not set
                    "cidrs": [
                        "162.159.192.0/24",
                        "188.114.96.0/24"
                    ]
                },
                "warp_noise": {
                    "enable": true,
                    "packet_count": "10-20",
                    "packet_delay": "1-5"
                }
            }
        ],
        "mtu": 1280
    }
]        
```

## Example configurations

See the `examples` directory for example configuration files.

## Docker

Docker images are available for `linux/amd64` and `linux/386` architectures at `ghcr.io/kyochikuto/sing-box-plus:latest`.

## Credits

Credits to [@bepass-org](https://github.com/bepass-org), [@markpash](https://github.com/markpash), and [@GFW-knocker](https://github.com/GFW-knocker) for the original TLS fragmentation idea and WARP noise generator.

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
