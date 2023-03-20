package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/v2box/types/v2rayjson"

	"github.com/spf13/cobra"
)

var (
	geoipInput  string
	geoipOutput string
)

var commandMigrateGeoIP = &cobra.Command{
	Use:   "geoip",
	Short: "Migrate V2Ray geoip resource file into sing-box",
	Run: func(cmd *cobra.Command, args []string) {
		err := migrateGeoIP()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandMigrateGeoIP.Flags().StringVarP(&geoipInput, "input", "i", "geoip.dat", "Input path")
	commandMigrateGeoIP.Flags().StringVarP(&geoipOutput, "output", "o", "geoip.db", "Output path")
	commandMigrate.AddCommand(commandMigrateGeoIP)
}

func migrateGeoIP() error {
	log.Info("<< ", common.Must1(filepath.Abs(geoipInput)))
	var (
		content []byte
		err     error
	)
	if configPath == "stdin" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(geoipInput)
	}
	if err != nil {
		return E.Cause(err, "read geoip")
	}
	writer, err := os.Create(geoipOutput)
	if err != nil {
		return E.Cause(err, "open output")
	}
	err = v2rayjson.MigrateGeoIP(content, writer)
	if err != nil {
		os.RemoveAll(geoipOutput)
		return err
	}
	log.Info(">> ", common.Must1(filepath.Abs(geoipOutput)))
	return nil
}
