# v2box

Migrate your v2ray configuration into sing-box.
for 09.11.2023 go 1.19 is required (not 1.21)

## Usage

```bash
git clone https://github.com/SagerNet/v2box
cd v2box
make build

./v2box migrate -c /path/to/v2ray-config.json > config.json
./v2box migrate geoip -i /path/to/geoip.dat -o geoip.db
./v2box migrate geosite -i /path/to/geosite.dat -o geosite.db
```

## TODO

- [x] Inbound
- [x] Outbound
- [x] Routing Rule
- [x] DNS
- [x] Convert geo resources
- [x] Xray support
