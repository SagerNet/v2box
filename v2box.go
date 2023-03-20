package v2box

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type Migration func(configuration []byte, logger logger.Logger) (option.Options, error)

var (
	migrationMap map[string]Migration
	versionMap   map[string]string
)

func Register(typeName string, versionString string, migration Migration) {
	if migrationMap == nil {
		migrationMap = make(map[string]Migration)
	}
	if versionMap == nil {
		versionMap = make(map[string]string)
	}
	migrationMap[typeName] = migration
	versionMap[typeName] = versionString
}

func Migrate(typeName string, configuration []byte, logger logger.Logger) (option.Options, error) {
	if typeName == "auto" {
		for migrationType, migration := range migrationMap {
			logger.Info("trying to migrate configuration as type ", migrationType)
			options, err := migration(configuration, logger)
			if err == nil {
				return options, nil
			}
		}
		return option.Options{}, E.New("failed to detect configuration type")
	}
	migration, loaded := migrationMap[typeName]
	if !loaded {
		return option.Options{}, E.New("unknown configuration type: ", typeName)
	}
	return migration(configuration, logger)
}

func Version(typeName string) string {
	if typeName == "auto" {
		if version, loaded := versionMap["v2ray"]; loaded {
			return version
		}
		for _, version := range versionMap {
			return version
		}
		return "unknown"
	}
	version, loaded := versionMap[typeName]
	if !loaded {
		return "unknown"
	}
	return version
}
