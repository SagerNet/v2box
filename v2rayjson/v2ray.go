package v2rayjson

import (
	"bytes"

	"github.com/sagernet/sing-box/common/json"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"

	v4json "github.com/v2fly/v2ray-core/v5/infra/conf/v4"
)

func Migrate(content []byte, logger logger.Logger) (option.Options, error) {
	var options option.Options
	var v2rayConfig v4json.Config
	decoder := json.NewDecoder(json.NewCommentFilter(bytes.NewReader(content)))
	err := decoder.Decode(&v2rayConfig)
	if err != nil {
		return option.Options{}, err
	}
	if v2rayConfig.LogConfig != nil && v2rayConfig.LogConfig.ErrorLog != "" || v2rayConfig.LogConfig.LogLevel != "" {
		options.Log = &option.LogOptions{}
		options.Log.Output = v2rayConfig.LogConfig.ErrorLog
		options.Log.Level = v2rayConfig.LogConfig.LogLevel
	}
	for i, inboundConfig := range v2rayConfig.InboundConfigs {
		inbound, err := migrateInbound(inboundConfig)
		if err != nil {
			tag := inboundConfig.Tag
			if tag == "" {
				tag = format.ToString(i)
			}
			logger.Warn("ignoring inbound ", tag, ": ", err)
			continue
		}
		options.Inbounds = append(options.Inbounds, inbound)
	}
	for i, outboundConfig := range v2rayConfig.OutboundConfigs {
		outbound, err := migrateOutbound(outboundConfig)
		if err != nil {
			tag := outboundConfig.Tag
			if tag == "" {
				tag = format.ToString(i)
			}
			logger.Warn("ignoring outbound ", tag, ": ", err)
			continue
		}
		options.Outbounds = append(options.Outbounds, outbound)
	}
	if routerConfig := v2rayConfig.RouterConfig; routerConfig != nil {
		for _, ruleMessage := range routerConfig.RuleList {
			rule, err := migrateRule(ruleMessage)
			if err != nil {
				logger.Warn("ignoring rule: ", err)
				continue
			}
			if options.Route == nil {
				options.Route = &option.RouteOptions{}
			}
			options.Route.Rules = append(options.Route.Rules, rule)
		}
	}
	return options, nil
}
