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
	geositeInput  string
	geositeOutput string
)

var commandMigrateGeoSite = &cobra.Command{
	Use:   "geosite",
	Short: "Migrate V2Ray geosite resource file into sing-box",
	Run: func(cmd *cobra.Command, args []string) {
		err := migrateGeoSite()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandMigrateGeoSite.Flags().StringVarP(&geositeInput, "input", "i", "geosite.dat", "Input path")
	commandMigrateGeoSite.Flags().StringVarP(&geositeOutput, "output", "o", "geosite.db", "Output path")
	commandMigrate.AddCommand(commandMigrateGeoSite)
}

func migrateGeoSite() error {
	log.Info("<< ", common.Must1(filepath.Abs(geositeInput)))
	var (
		content []byte
		err     error
	)
	if configPath == "stdin" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(geositeInput)
	}
	if err != nil {
		return E.Cause(err, "read geoip")
	}
	writer, err := os.Create(geositeOutput)
	if err != nil {
		return E.Cause(err, "open output")
	}
	err = v2rayjson.MigrateGeoSite(content, writer)
	if err != nil {
		os.RemoveAll(geositeOutput)
		return err
	}
	log.Info(">> ", common.Must1(filepath.Abs(geositeOutput)))
	return nil
}
