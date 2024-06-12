# sing-box
Sing-Box + Blocking Bypass Hacks = ❤️

### TLS Fragmentation
Fragments TLS ClientHello packets in multiple segments such that the SNI extension is guaranteed to split, making it harder to drop connections based on SNI filtering.
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

### Cloudflare WARP blocking bypass
Bypasses Cloudflare WARP blockings by applying certain Wireguard hacks.
Enabled by default for all detected WARP endpoints.

## Examples
See the [examples](https://github.com/kyochikuto/sing-box-plus/tree/main/examples) directory for configuration examples.

## Fork License
```
Copyright (C) 2024 by Kyōchikutō | キョウチクトウ 

This fork includes the following changes:

* [TLS Fragmentation]
* [WARP Unblocker]
```

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


