package xrayjson

import (
	"reflect"
	"strings"
	"time"
	_ "unsafe"

	"github.com/sagernet/sing-box/common/badjson"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vless_inbound "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmess_inbound "github.com/xtls/xray-core/proxy/vmess/inbound"
)

//go:linkname inboundConfigLoader github.com/xtls/xray-core/infra/conf.inboundConfigLoader
var inboundConfigLoader *conf.JSONConfigLoader

func migrateInbound(inboundConfig conf.InboundDetourConfig) (option.Inbound, error) {
	var inbound option.Inbound
	inbound.Tag = inboundConfig.Tag

	var listenOptions option.ListenOptions
	if inboundConfig.ListenOn != nil {
		listenOptions.Listen = option.NewListenAddress(M.ParseAddr(inboundConfig.ListenOn.Address.String()))
	}
	if inboundConfig.PortList != nil {
		listenOptions.ListenPort = parsePort(inboundConfig.PortList)
	}

	var tlsOptions option.InboundTLSOptions
	var transportOptions option.V2RayTransportOptions
	var tproxyName string
	var err error

	if inboundConfig.StreamSetting != nil {
		streamSettings := inboundConfig.StreamSetting
		if socketSettings := streamSettings.SocketSettings; socketSettings != nil {
			if socketSettings.TFO != nil {
				switch tfoType := socketSettings.TFO.(type) {
				case bool:
					listenOptions.TCPFastOpen = tfoType
				case float64:
					listenOptions.TCPFastOpen = tfoType != -1
				}
			}
			tproxyName = socketSettings.TProxy
			if socketSettings.AcceptProxyProtocol {
				listenOptions.ProxyProtocol = true
				listenOptions.ProxyProtocolAcceptNoHeader = true
			}
		}
		transportOptions, err = parseTransport(streamSettings)
		if err != nil {
			return option.Inbound{}, err
		}
		if security := streamSettings.Security; security != "" {
			switch security {
			case "tls":
				tlsOptions.Enabled = true
				if tlsSettings := streamSettings.TLSSettings; tlsSettings != nil {
					tlsOptions.ServerName = tlsSettings.ServerName
					for _, certConfig := range tlsSettings.Certs {
						if certConfig.Usage != "" && certConfig.Usage != "encipherment" {
							continue
						}
						if len(certConfig.CertStr) > 0 {
							tlsOptions.Certificate = strings.Join(certConfig.CertStr, "\n")
						}
						if len(certConfig.KeyStr) > 0 {
							tlsOptions.Key = strings.Join(certConfig.KeyStr, "\n")
						}
						tlsOptions.CertificatePath = certConfig.CertFile
						tlsOptions.KeyPath = certConfig.KeyFile
					}
					if tlsSettings.ALPN != nil && tlsSettings.ALPN.Len() > 0 {
						tlsOptions.ALPN = []string(*tlsSettings.ALPN)
					}
				}
			case "reality":
				tlsOptions.Enabled = true
				if tlsSettings := streamSettings.REALITYSettings; tlsSettings != nil {
					if len(tlsSettings.ServerNames) > 0 {
						tlsOptions.ServerName = tlsSettings.ServerNames[0]
					}
					tlsOptions.Reality = &option.InboundRealityOptions{
						Enabled:           true,
						PrivateKey:        tlsSettings.PrivateKey,
						ShortID:           tlsSettings.ShortIds,
						MaxTimeDifference: option.Duration(time.Duration(tlsSettings.MaxTimeDiff) * time.Millisecond),
					}
					if len(tlsSettings.Dest) > 0 {
						destValue, err := badjson.Decode(tlsSettings.Dest)
						if err == nil {
							switch destType := destValue.(type) {
							case string:
								destination := M.ParseSocksaddr(destType)
								tlsOptions.Reality.Handshake.Server = destination.AddrString()
								tlsOptions.Reality.Handshake.ServerPort = destination.Port
							case float64:
								tlsOptions.Reality.Handshake.Server = net.LocalHostIP.String()
								tlsOptions.Reality.Handshake.ServerPort = uint16(destType)
							}
						}
					}
				}
			}
		}
	}
	settingsString := []byte("{}")
	if inboundConfig.Settings != nil {
		settingsString = *inboundConfig.Settings
	}
	rawConfig, err := inboundConfigLoader.LoadWithID(settingsString, inboundConfig.Protocol)
	if err != nil {
		return option.Inbound{}, err
	}
	proxySettings, err := rawConfig.(conf.Buildable).Build()
	if err != nil {
		return option.Inbound{}, err
	}
	switch proxyType := proxySettings.(type) {
	case *dokodemo.Config:
		if proxyType.FollowRedirect || tproxyName == "redirect" {
			inbound.Type = C.TypeRedirect
			inbound.RedirectOptions.ListenOptions = listenOptions
		} else if tproxyName == "tproxy" {
			inbound.Type = C.TypeTProxy
			inbound.TProxyOptions.ListenOptions = listenOptions
			inbound.TProxyOptions.Network = option.NetworkList(parseNetworks(proxyType.Networks))
		} else {
			inbound.Type = C.TypeDirect
			inbound.DirectOptions.ListenOptions = listenOptions
			if address := proxyType.GetPredefinedAddress(); address != nil {
				inbound.DirectOptions.OverrideAddress = address.String()
			}
			inbound.DirectOptions.OverridePort = uint16(proxyType.Port)
			inbound.DirectOptions.Network = option.NetworkList(parseNetworks(proxyType.Networks))
		}
	case *http.ServerConfig:
		inbound.Type = C.TypeHTTP
		inbound.HTTPOptions.ListenOptions = listenOptions
		for username, password := range proxyType.Accounts {
			inbound.HTTPOptions.Users = append(inbound.HTTPOptions.Users, auth.User{
				Username: username,
				Password: password,
			})
			if tlsOptions.Enabled {
				inbound.HTTPOptions.TLS = &tlsOptions
			}
		}
	case *socks.ServerConfig:
		inbound.Type = C.TypeSocks
		inbound.SocksOptions.ListenOptions = listenOptions
		for username, password := range proxyType.Accounts {
			inbound.SocksOptions.Users = append(inbound.SocksOptions.Users, auth.User{
				Username: username,
				Password: password,
			})
		}
	case *shadowsocks.ServerConfig:
		inbound.Type = C.TypeShadowsocks
		inbound.ShadowsocksOptions.ListenOptions = listenOptions
		inbound.ShadowsocksOptions.Network = option.NetworkList(parseNetworks(proxyType.Network))
		for _, user := range proxyType.Users {
			shadowsocksAccount, err := user.Account.GetInstance()
			if err != nil {
				return option.Inbound{}, E.Cause(err, "create account")
			}
			switch shadowsocksAccountType := shadowsocksAccount.(type) {
			case *shadowsocks.Account:
				switch shadowsocksAccountType.CipherType {
				case shadowsocks.CipherType_AES_128_GCM:
					inbound.ShadowsocksOptions.Method = "aes-128-gcm"
				case shadowsocks.CipherType_CHACHA20_POLY1305:
					inbound.ShadowsocksOptions.Method = "chacha20-ietf-poly1305"
				default:
					inbound.ShadowsocksOptions.Method = "none"
				}
				inbound.ShadowsocksOptions.Password = shadowsocksAccountType.Password
				break
			}
		}
	case *shadowsocks_2022.ServerConfig:
		inbound.Type = C.TypeShadowsocks
		inbound.ShadowsocksOptions.ListenOptions = listenOptions
		inbound.ShadowsocksOptions.Network = option.NetworkList(parseNetworks(proxyType.Network))
		inbound.ShadowsocksOptions.Method = proxyType.Method
		inbound.ShadowsocksOptions.Password = proxyType.Key
	case *shadowsocks_2022.MultiUserServerConfig:
		inbound.Type = C.TypeShadowsocks
		inbound.ShadowsocksOptions.ListenOptions = listenOptions
		inbound.ShadowsocksOptions.Network = option.NetworkList(parseNetworks(proxyType.Network))
		inbound.ShadowsocksOptions.Method = proxyType.Method
		inbound.ShadowsocksOptions.Password = proxyType.Key
		for _, user := range proxyType.Users {
			inbound.ShadowsocksOptions.Users = append(inbound.ShadowsocksOptions.Users, option.ShadowsocksUser{
				Name:     user.Email,
				Password: user.Key,
			})
		}
	case *shadowsocks_2022.RelayServerConfig:
		inbound.Type = C.TypeShadowsocks
		inbound.ShadowsocksOptions.ListenOptions = listenOptions
		inbound.ShadowsocksOptions.Network = option.NetworkList(parseNetworks(proxyType.Network))
		inbound.ShadowsocksOptions.Method = proxyType.Method
		inbound.ShadowsocksOptions.Password = proxyType.Key
		for _, destination := range proxyType.Destinations {
			inbound.ShadowsocksOptions.Destinations = append(inbound.ShadowsocksOptions.Destinations, option.ShadowsocksDestination{
				Name:     destination.Email,
				Password: destination.Key,
				ServerOptions: option.ServerOptions{
					Server:     destination.Address.AsAddress().String(),
					ServerPort: uint16(destination.Port),
				},
			})
		}
	case *vmess_inbound.Config:
		inbound.Type = C.TypeVMess
		inbound.VMessOptions.ListenOptions = listenOptions
		if tlsOptions.Enabled {
			inbound.VMessOptions.TLS = &tlsOptions
		}
		if transportOptions.Type != "" {
			inbound.VMessOptions.Transport = &transportOptions
		}
		for _, user := range proxyType.User {
			account, err := user.Account.GetInstance()
			if err != nil {
				return option.Inbound{}, E.Cause(err, "get instance of ", user.Account.Type)
			}
			switch accountType := account.(type) {
			case *vmess.Account:
				inbound.VMessOptions.Users = append(inbound.VMessOptions.Users, option.VMessUser{
					Name:    user.Email,
					UUID:    accountType.Id,
					AlterId: int(accountType.AlterId),
				})
			}
		}
	case *vless_inbound.Config:
		inbound.Type = C.TypeVLESS
		inbound.VLESSOptions.ListenOptions = listenOptions
		if tlsOptions.Enabled {
			inbound.VLESSOptions.TLS = &tlsOptions
		}
		if transportOptions.Type != "" {
			inbound.VLESSOptions.Transport = &transportOptions
		}
		for _, client := range proxyType.Clients {
			account, err := client.Account.GetInstance()
			if err != nil {
				return option.Inbound{}, E.Cause(err, "get instance of ", client.Account.Type)
			}
			switch accountType := account.(type) {
			case *vless.Account:
				inbound.VLESSOptions.Users = append(inbound.VLESSOptions.Users, option.VLESSUser{
					Name: client.Email,
					UUID: accountType.Id,
					Flow: accountType.Flow,
				})
			}
		}
	case *trojan.ServerConfig:
		inbound.Type = C.TypeTrojan
		inbound.TrojanOptions.ListenOptions = listenOptions
		if tlsOptions.Enabled {
			inbound.TrojanOptions.TLS = &tlsOptions
		}
		if transportOptions.Type != "" {
			inbound.TrojanOptions.Transport = &transportOptions
		}
		for _, user := range proxyType.Users {
			account, err := user.Account.GetInstance()
			if err != nil {
				return option.Inbound{}, E.Cause(err, "get instance of ", user.Account.Type)
			}
			switch accountType := account.(type) {
			case *trojan.Account:
				inbound.TrojanOptions.Users = append(inbound.TrojanOptions.Users, option.TrojanUser{
					Name:     user.Email,
					Password: accountType.Password,
				})
			}
		}
	default:
		return option.Inbound{}, E.New("unsupported inbound type ", reflect.TypeOf(proxyType))
	}
	return inbound, nil
}
