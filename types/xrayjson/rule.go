package xrayjson

import (
	"encoding/json"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/format"

	"github.com/xtls/xray-core/infra/conf"
)

type RawFieldRule struct {
	conf.RouterRule
	Domain     option.Listable[string] `json:"domain"`
	Domains    option.Listable[string] `json:"domains"`
	IP         option.Listable[string] `json:"ip"`
	Port       *conf.PortList          `json:"port"`
	Network    *conf.NetworkList       `json:"network"`
	SourceIP   option.Listable[string] `json:"source"`
	SourcePort *conf.PortList          `json:"sourcePort"`
	User       option.Listable[string] `json:"user"`
	InboundTag option.Listable[string] `json:"inboundTag"`
	Protocols  option.Listable[string] `json:"protocol"`
	Attributes string                  `json:"attrs"`
}

func migrateRule(ruleMessage json.RawMessage) (option.Rule, error) {
	var rule option.DefaultRule
	var rawRule conf.RouterRule
	err := json.Unmarshal(ruleMessage, &rawRule)
	if err != nil {
		return option.Rule{}, err
	}
	if rawRule.BalancerTag != "" {
		return option.Rule{}, E.New("balancer rule is not supported")
	}
	if rawRule.Type != "field" {
		return option.Rule{}, E.New("unknown router rule type: ", rawRule.Type)
	}
	var field RawFieldRule
	err = json.Unmarshal(ruleMessage, &field)
	if err != nil {
		return option.Rule{}, err
	}
	rule.Outbound = field.OutboundTag
	for _, domain := range field.Domain {
		err = parseDomain(domain, &rule)
		if err != nil {
			return option.Rule{}, err
		}
	}
	for _, domain := range field.Domains {
		err = parseDomain(domain, &rule)
		if err != nil {
			return option.Rule{}, err
		}
	}
	for _, address := range field.IP {
		err = parseAddress(address, false, &rule)
		if err != nil {
			return option.Rule{}, err
		}
	}
	for _, address := range field.SourceIP {
		err = parseAddress(address, true, &rule)
		if err != nil {
			return option.Rule{}, err
		}
	}
	if field.Port != nil {
		for _, portRange := range field.Port.Range {
			if portRange.From == portRange.To {
				rule.Port = append(rule.Port, uint16(portRange.From))
			} else {
				rule.PortRange = append(rule.PortRange, format.ToString(portRange.From, ":", portRange.To))
			}
		}
	}
	if field.SourcePort != nil {
		for _, portRange := range field.SourcePort.Range {
			if portRange.From == portRange.To {
				rule.SourcePort = append(rule.SourcePort, uint16(portRange.From))
			} else {
				rule.SourcePortRange = append(rule.SourcePortRange, format.ToString(portRange.From, ":", portRange.To))
			}
		}
	}
	rule.Network = parseNetworkList(field.Network)
	rule.AuthUser = field.User
	rule.Inbound = field.InboundTag
	rule.Protocol = field.Protocols
	if field.Attributes != "" {
		return option.Rule{}, E.New("attributes rule is not supported")
	}
	return option.Rule{
		Type:           C.RuleTypeDefault,
		DefaultOptions: rule,
	}, nil
}

func parseDomain(domain string, rule *option.DefaultRule) error {
	if strings.HasPrefix(domain, "ext:") || strings.HasPrefix(domain, "ext-domain:") {
		return E.New("load external geosite is not supported")
	} else if strings.HasPrefix(domain, "geosite:") {
		domain = domain[8:]
		rule.Geosite = append(rule.Geosite, domain)
		return nil
	} else if strings.HasPrefix(domain, "regexp:") {
		domain = domain[7:]
		rule.DomainRegex = append(rule.Domain, domain)
		return nil
	} else if strings.HasPrefix(domain, "domain:") {
		domain = domain[7:]
		rule.Domain = append(rule.Domain, domain)
		rule.DomainSuffix = append(rule.DomainSuffix, "."+domain)
		return nil
	} else if strings.HasPrefix(domain, "full:") {
		domain = domain[5:]
		rule.Domain = append(rule.Domain, domain)
	} else if strings.HasPrefix(domain, "keyword:") {
		domain = domain[8:]
		rule.DomainKeyword = append(rule.DomainKeyword, domain)
	} else if strings.HasPrefix(domain, "dotless:") {
		domain = domain[8:]
		if domain == "" {
			rule.DomainRegex = append(rule.DomainRegex, "^[^.]*$")
		} else {
			rule.DomainRegex = append(rule.DomainRegex, "^[^.]*"+domain+"[^.]*$")
		}
	} else {
		rule.DomainKeyword = append(rule.DomainKeyword, domain)
	}
	return nil
}

func parseAddress(address string, isSource bool, rule *option.DefaultRule) error {
	if strings.HasPrefix(address, "ext:") || strings.HasPrefix(address, "ext-ip:") {
		return E.New("load external geoip is not supported")
	} else if strings.HasPrefix(address, "geoip:!") {
		return E.New("geoip with reserve match not supported, rewrite your rule with rule.invert")
	} else if strings.HasPrefix(address, "geoip:") {
		address = address[6:]
		if isSource {
			rule.SourceGeoIP = append(rule.SourceGeoIP, address)
		} else {
			rule.GeoIP = append(rule.GeoIP, address)
		}
	} else {
		if isSource {
			rule.SourceIPCIDR = append(rule.SourceIPCIDR, address)
		} else {
			rule.IPCIDR = append(rule.IPCIDR, address)
		}
	}
	return nil
}
