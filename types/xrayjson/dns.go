package xrayjson

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common"

	"github.com/xtls/xray-core/infra/conf"
)

func migrateDNS(dnsConfig conf.DNSConfig, options *option.Options) {
	defaultServer := common.Find(dnsConfig.Servers, func(it *conf.NameServerConfig) bool {
		return len(it.Domains) == 0 && len(it.ExpectIPs) > 0
	})
	var defaultServerAddress string
	if defaultServer != nil {
		if !strings.Contains(defaultServerAddress, "+local://") {
			defaultServerAddress = defaultServer.Address.String()
		}
	}
	if defaultServerAddress == "" {
		defaultServerAddress = "tls://8.8.8.8"
	}

	var dnsOptions option.DNSOptions
	dnsOptions.Strategy = parseStrategy(dnsConfig.QueryStrategy)
	dnsOptions.Servers = []option.DNSServerOptions{
		{
			Address: "tls://8.8.8.8",
			Tag:     "remote",
		},
		{
			Address: "local",
			Tag:     "local",
			Detour:  "direct",
		},
	}
	if common.Any(dnsConfig.Servers, func(it *conf.NameServerConfig) bool {
		return len(it.Domains) > 0 && common.Any(it.Domains, func(it string) bool {
			return strings.HasSuffix(it, "cn")
		})
	}) {
		dnsOptions.Rules = append(dnsOptions.Rules, option.DNSRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultDNSRule{
				Domain: []string{"geosite:cn"},
				Server: "local",
			},
		})
	}
	if !common.Any(options.Outbounds, func(it option.Outbound) bool {
		return it.Tag == "direct"
	}) {
		options.Outbounds = append(options.Outbounds, option.Outbound{
			Type: C.TypeDirect,
			Tag:  "direct",
		})
	}
	options.DNS = &dnsOptions
}

func parseStrategy(queryStrategy string) option.DomainStrategy {
	switch strings.ToLower(queryStrategy) {
	case "useip4", "useipv4", "use_ip4", "use_ipv4", "use_ip_v4", "use-ip4", "use-ipv4", "use-ip-v4":
		return option.DomainStrategy(dns.DomainStrategyUseIPv4)
	case "useip6", "useipv6", "use_ip6", "use_ipv6", "use_ip_v6", "use-ip6", "use-ipv6", "use-ip-v6":
		return option.DomainStrategy(dns.DomainStrategyUseIPv6)
	}
	return option.DomainStrategy(dns.DomainStrategyAsIS)
}
