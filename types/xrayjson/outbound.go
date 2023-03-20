package xrayjson

import (
	"net/netip"
	"reflect"
	"strings"
	_ "unsafe"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-dns"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/blackhole"
	proxy_dns "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/loopback"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vless_outbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmess_outbound "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/proxy/wireguard"
)

//go:linkname outboundConfigLoader github.com/xtls/xray-core/infra/conf.outboundConfigLoader
var outboundConfigLoader *conf.JSONConfigLoader

func migrateOutbound(outboundConfig conf.OutboundDetourConfig, dnsRule *option.DefaultDNSRule) (option.Outbound, error) {
	var outbound option.Outbound
	outbound.Tag = outboundConfig.Tag

	var dialOptions option.DialerOptions
	var tlsOptions option.OutboundTLSOptions
	var transportOptions option.V2RayTransportOptions
	// var multiplexOptions option.MultiplexOptions
	var err error

	if streamSettings := outboundConfig.StreamSetting; streamSettings != nil {
		if socketSettings := streamSettings.SocketSettings; socketSettings != nil {
			if socketSettings.Mark > 0 {
				dialOptions.RoutingMark = int(socketSettings.Mark)
			}
			if socketSettings.TFO != nil {
				switch tfoType := socketSettings.TFO.(type) {
				case bool:
					dialOptions.TCPFastOpen = tfoType
				case float64:
					dialOptions.TCPFastOpen = tfoType != -1
				}
			}
			dialOptions.BindInterface = socketSettings.Interface
		}
		transportOptions, err = parseTransport(streamSettings)
		if err != nil {
			return option.Outbound{}, err
		}
		if security := streamSettings.Security; security != "" {
			switch security {
			case "tls":
				tlsOptions.Enabled = true
				if tlsSettings := streamSettings.TLSSettings; tlsSettings != nil {
					tlsOptions.Insecure = tlsSettings.Insecure
					tlsOptions.ServerName = tlsSettings.ServerName
					for _, certConfig := range tlsSettings.Certs {
						if certConfig.Usage != "" && certConfig.Usage != "encipherment" {
							continue
						}
						if len(certConfig.CertStr) > 0 {
							tlsOptions.Certificate = strings.Join(certConfig.CertStr, "\n")
						}
						tlsOptions.CertificatePath = certConfig.CertFile
					}
					if tlsSettings.ALPN != nil && tlsSettings.ALPN.Len() > 0 {
						tlsOptions.ALPN = []string(*tlsSettings.ALPN)
					}
					if tlsSettings.Fingerprint != "" {
						tlsOptions.UTLS = &option.OutboundUTLSOptions{
							Enabled:     true,
							Fingerprint: tlsSettings.Fingerprint,
						}
					}
				}
			case "reality":
				tlsOptions.Enabled = true
				if tlsSettings := streamSettings.REALITYSettings; tlsSettings != nil {
					tlsOptions.ServerName = tlsSettings.ServerName
					tlsOptions.UTLS = &option.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: tlsSettings.Fingerprint,
					}
					tlsOptions.Reality = &option.OutboundRealityOptions{
						Enabled:   true,
						PublicKey: tlsSettings.PublicKey,
						ShortID:   tlsSettings.ShortId,
					}
				}
			}
		}
	}
	/*if muxSettings := outboundConfig.MuxSettings; muxSettings != nil {
		multiplexOptions.Enabled = true
		multiplexOptions.MaxConnections = int(outboundConfig.MuxSettings.Concurrency)
	}*/
	settingsString := []byte("{}")
	if outboundConfig.Settings != nil {
		settingsString = *outboundConfig.Settings
	}
	rawConfig, err := outboundConfigLoader.LoadWithID(settingsString, outboundConfig.Protocol)
	if err != nil {
		return option.Outbound{}, err
	}
	proxySettings, err := rawConfig.(cfgcommon.Buildable).Build()
	if err != nil {
		return option.Outbound{}, err
	}
	switch proxyType := proxySettings.(type) {
	case *blackhole.Config:
		outbound.Type = C.TypeBlock
	case *proxy_dns.Config:
		outbound.Type = C.TypeDNS
	case *loopback.Config:
		return option.Outbound{}, E.New("loopback is not supported, please rewrite your config using listenOptions.detour")
	case *freedom.Config:
		outbound.Type = C.TypeDirect
		if destinationOverride := proxyType.DestinationOverride; destinationOverride != nil {
			if server := destinationOverride.Server; server != nil && server.Address.AsAddress() != nil {
				outbound.DirectOptions.OverrideAddress = server.Address.String()
				outbound.DirectOptions.OverridePort = uint16(server.Port)
			}
		}
		switch proxyType.DomainStrategy {
		case freedom.Config_AS_IS:
		case freedom.Config_USE_IP:
			outbound.DirectOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyPreferIPv4)
		case freedom.Config_USE_IP4:
			outbound.DirectOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv4)
		case freedom.Config_USE_IP6:
			outbound.DirectOptions.DomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv6)
		}
	case *http.ClientConfig:
		outbound.Type = C.TypeHTTP
		if tlsOptions.Enabled {
			outbound.HTTPOptions.TLS = &tlsOptions
		}
		serverAddress, users := parseServerAddress(proxyType.Server)
		addServerToDNSOptions(serverAddress, dnsRule)
		outbound.HTTPOptions.Server = serverAddress.AddrString()
		outbound.HTTPOptions.ServerPort = serverAddress.Port
		for _, user := range users {
			account, err := user.Account.GetInstance()
			if err != nil {
				return option.Outbound{}, E.Cause(err, "get instance of ", user.Account.Type)
			}
			switch accountType := account.(type) {
			case *http.Account:
				outbound.HTTPOptions.Username = accountType.Username
				outbound.HTTPOptions.Password = accountType.Password
			}
		}
	case *socks.ClientConfig:
		outbound.Type = C.TypeSocks
		switch proxyType.Version {
		case socks.Version_SOCKS4:
			outbound.SocksOptions.Version = "4"
		case socks.Version_SOCKS4A:
			outbound.SocksOptions.Version = "4a"
		}
		serverAddress, users := parseServerAddress(proxyType.Server)
		addServerToDNSOptions(serverAddress, dnsRule)
		outbound.SocksOptions.Server = serverAddress.AddrString()
		outbound.SocksOptions.ServerPort = serverAddress.Port
		for _, user := range users {
			account, err := user.Account.GetInstance()
			if err != nil {
				return option.Outbound{}, E.Cause(err, "get instance of ", user.Account.Type)
			}
			switch accountType := account.(type) {
			case *socks.Account:
				outbound.SocksOptions.Username = accountType.Username
				outbound.SocksOptions.Password = accountType.Password
			}
		}
	case *shadowsocks.ClientConfig:
		outbound.Type = C.TypeShadowsocks
		serverAddress, users := parseServerAddress(proxyType.Server)
		addServerToDNSOptions(serverAddress, dnsRule)
		outbound.ShadowsocksOptions.Server = serverAddress.AddrString()
		outbound.ShadowsocksOptions.ServerPort = serverAddress.Port
		for _, user := range users {
			account, err := user.Account.GetInstance()
			if err != nil {
				return option.Outbound{}, E.Cause(err, "get instance of ", user.Account.Type)
			}
			switch accountType := account.(type) {
			case *shadowsocks.Account:
				var method string
				switch accountType.CipherType {
				case shadowsocks.CipherType_AES_128_GCM:
					method = "aes-128-gcm"
				case shadowsocks.CipherType_AES_256_GCM:
					method = "aes-256-gcm"
				case shadowsocks.CipherType_CHACHA20_POLY1305:
					method = "chacha20-ietf-poly1305"
				default:
					method = "none"
				}
				outbound.ShadowsocksOptions.Method = method
				outbound.ShadowsocksOptions.Password = accountType.Password
			}
		}
	case *shadowsocks_2022.ClientConfig:
		outbound.Type = C.TypeShadowsocks
		outbound.ShadowsocksOptions.Server = proxyType.Address.AsAddress().String()
		outbound.ShadowsocksOptions.ServerPort = uint16(proxyType.Port)
		outbound.ShadowsocksOptions.Method = proxyType.Method
		outbound.ShadowsocksOptions.Password = proxyType.Key
		if proxyType.UdpOverTcp {
			outbound.ShadowsocksOptions.UDPOverTCPOptions = &option.UDPOverTCPOptions{
				Enabled: true,
			}
		}
	case *trojan.ClientConfig:
		outbound.Type = C.TypeTrojan
		if tlsOptions.Enabled {
			outbound.TrojanOptions.TLS = &tlsOptions
		}
		if transportOptions.Type != "" {
			outbound.TrojanOptions.Transport = &transportOptions
		}
		serverAddress, users := parseServerAddress(proxyType.Server)
		addServerToDNSOptions(serverAddress, dnsRule)
		outbound.TrojanOptions.Server = serverAddress.AddrString()
		outbound.TrojanOptions.ServerPort = serverAddress.Port
		for _, user := range users {
			account, err := user.Account.GetInstance()
			if err != nil {
				return option.Outbound{}, E.Cause(err, "get instance of ", user.Account.Type)
			}
			switch accountType := account.(type) {
			case *trojan.Account:
				outbound.TrojanOptions.Password = accountType.Password
			}
		}
	case *vmess_outbound.Config:
		outbound.Type = C.TypeVMess
		if tlsOptions.Enabled {
			outbound.VMessOptions.TLS = &tlsOptions
		}
		if transportOptions.Type != "" {
			outbound.VMessOptions.Transport = &transportOptions
		}
		serverAddress, users := parseServerAddress(proxyType.Receiver)
		addServerToDNSOptions(serverAddress, dnsRule)
		outbound.VMessOptions.Server = serverAddress.AddrString()
		outbound.VMessOptions.ServerPort = serverAddress.Port
		for _, user := range users {
			account, err := user.Account.GetInstance()
			if err != nil {
				return option.Outbound{}, E.Cause(err, "get instance of ", user.Account.Type)
			}
			switch accountType := account.(type) {
			case *vmess.Account:
				var security string
				switch accountType.SecuritySettings.Type {
				case protocol.SecurityType_AES128_GCM:
					security = "aes-128-gcm"
				case protocol.SecurityType_CHACHA20_POLY1305:
					security = "chacha20-poly1305"
				case protocol.SecurityType_NONE:
					security = "none"
				case protocol.SecurityType_ZERO:
					security = "zero"
				}
				outbound.VMessOptions.UUID = accountType.Id
				outbound.VMessOptions.Security = security
				outbound.VMessOptions.AlterId = int(accountType.AlterId)
				if strings.Contains(accountType.TestsEnabled, "AuthenticatedLength") {
					outbound.VMessOptions.AuthenticatedLength = true
				}
			}
		}
	case *vless_outbound.Config:
		outbound.Type = C.TypeVLESS
		if tlsOptions.Enabled {
			outbound.VLESSOptions.TLS = &tlsOptions
		}
		if transportOptions.Type != "" {
			outbound.VLESSOptions.Transport = &transportOptions
		}
		serverAddress, users := parseServerAddress(proxyType.Vnext)
		addServerToDNSOptions(serverAddress, dnsRule)
		outbound.VLESSOptions.Server = serverAddress.AddrString()
		outbound.VLESSOptions.ServerPort = serverAddress.Port
		for _, user := range users {
			account, err := user.Account.GetInstance()
			if err != nil {
				return option.Outbound{}, E.Cause(err, "get instance of ", user.Account.Type)
			}
			switch accountType := account.(type) {
			case *vless.Account:
				outbound.VLESSOptions.UUID = accountType.Id
				outbound.VLESSOptions.Flow = accountType.Flow
			}
		}
	case *wireguard.DeviceConfig:
		outbound.Type = C.TypeWireGuard
		for _, peer := range proxyType.Peers {
			destination := M.ParseSocksaddr(peer.Endpoint)
			outbound.WireGuardOptions.Server = destination.AddrString()
			outbound.WireGuardOptions.ServerPort = destination.Port
			outbound.WireGuardOptions.PeerPublicKey = peer.PublicKey
			outbound.WireGuardOptions.PreSharedKey = peer.PreSharedKey
			break
		}
		for _, endpoint := range proxyType.Endpoint {
			destination := M.ParseAddr(endpoint)
			outbound.WireGuardOptions.LocalAddress = append(outbound.WireGuardOptions.LocalAddress, option.ListenPrefix(netip.PrefixFrom(destination, destination.BitLen())))
		}
		outbound.WireGuardOptions.PrivateKey = proxyType.SecretKey
		outbound.WireGuardOptions.MTU = uint32(proxyType.Mtu)
		outbound.WireGuardOptions.Workers = int(proxyType.NumWorkers)
		outbound.WireGuardOptions.Reserved = proxyType.Reserved
	default:
		return option.Outbound{}, E.New("unknown outbound type: ", reflect.TypeOf(proxyType))
	}
	return outbound, nil
}

func addServerToDNSOptions(address M.Socksaddr, dnsRule *option.DefaultDNSRule) {
	if address.IsFqdn() {
		dnsRule.Domain = append(dnsRule.Domain, address.Fqdn)
	}
}
