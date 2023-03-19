package v2rayjson

import (
	"reflect"
	"strings"
	_ "unsafe"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/loader"
	v4json "github.com/v2fly/v2ray-core/v5/infra/conf/v4"
	"github.com/v2fly/v2ray-core/v5/proxy/dokodemo"
	"github.com/v2fly/v2ray-core/v5/proxy/http"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks"
	"github.com/v2fly/v2ray-core/v5/proxy/socks"
	"github.com/v2fly/v2ray-core/v5/proxy/trojan"
	"github.com/v2fly/v2ray-core/v5/proxy/vless"
	vless_inbound "github.com/v2fly/v2ray-core/v5/proxy/vless/inbound"
	"github.com/v2fly/v2ray-core/v5/proxy/vmess"
	vmess_inbound "github.com/v2fly/v2ray-core/v5/proxy/vmess/inbound"
)

//go:linkname inboundConfigLoader github.com/v2fly/v2ray-core/v5/infra/conf/v4.inboundConfigLoader
var inboundConfigLoader *loader.JSONConfigLoader

func migrateInbound(inboundConfig v4json.InboundDetourConfig) (option.Inbound, error) {
	var inbound option.Inbound
	inbound.Tag = inboundConfig.Tag

	var listenOptions option.ListenOptions
	if inboundConfig.ListenOn != nil {
		listenOptions.Listen = option.NewListenAddress(M.ParseAddr(inboundConfig.ListenOn.Address.String()))
	}
	if inboundConfig.PortRange != nil {
		listenOptions.ListenPort = uint16(inboundConfig.PortRange.From)
	}

	var tlsOptions option.InboundTLSOptions
	var transportOptions option.V2RayTransportOptions
	var tproxyName string
	var err error

	if inboundConfig.StreamSetting != nil {
		streamSettings := inboundConfig.StreamSetting
		if socketSettings := streamSettings.SocketSettings; socketSettings != nil {
			if socketSettings.TFO != nil {
				listenOptions.TCPFastOpen = *socketSettings.TFO
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
	proxySettings, err := rawConfig.(cfgcommon.Buildable).Build()
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
		shadowsocksAccount, err := serial.GetInstanceOf(proxyType.User.Account)
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
			account, err := serial.GetInstanceOf(user.Account)
			if err != nil {
				return option.Inbound{}, E.Cause(err, "get instance of ", user.Account.TypeUrl)
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
			account, err := serial.GetInstanceOf(client.Account)
			if err != nil {
				return option.Inbound{}, E.Cause(err, "get instance of ", client.Account.TypeUrl)
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
			account, err := serial.GetInstanceOf(user.Account)
			if err != nil {
				return option.Inbound{}, E.Cause(err, "get instance of ", user.Account.TypeUrl)
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
