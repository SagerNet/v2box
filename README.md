# v2box

Migrate your v2ray configuration into sing-box.

## Usage

```bash
v2box migrate -c /path/to/v2ray-config.json > config.json
v2box migrate geoip -i /path/to/geoip.dat -o geoip.db
v2box migrate geosite -i /path/to/geosite.dat -o geosite.db
```

## TODO

- [x] Inbound
- [x] Outbound
- [x] Routing Rule
- [x] DNS
- [x] Convert geo resources
- [x] Xray support
