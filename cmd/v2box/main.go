package main

import (
	"github.com/sagernet/sing-box/log"
	_ "github.com/sagernet/v2box/types/v2rayjson"
	_ "github.com/sagernet/v2box/types/xrayjson"

	"github.com/spf13/cobra"
)

var (
	configType string
	configPath string
)

var command = &cobra.Command{
	Use:   "v2box",
	Short: "sing-box, but with v2ray configuration support.",
	Run: func(cmd *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	command.PersistentFlags().StringVarP(&configType, "type", "t", "auto", "configuration file type")
	command.PersistentFlags().StringVarP(&configPath, "config", "c", "config.json", "configuration file path")
}

func main() {
	err := command.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
