# v2box

Migrate your v2ray configuration into sing-box.

## Usage

```
v2box [flags]
v2box [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  migrate     Migrate your v2ray configuration into sing-box.
  run         run V2Ray with config
  version     Print V2Ray version

Flags:
  -c, --config string   configuration file path (default "config.json")
  -h, --help            help for v2box
  -t, --type string     configuration file type (default "auto")

Use "v2box [command] --help" for more information about a command.
```

## Example

```bash
v2box migrate -c /path/to/v2ray-config.json > config.json
```

## TODO

- [x] Inbound
- [x] Outbound
- [x] Routing Rule
- [x] DNS
- [x] Xray support
