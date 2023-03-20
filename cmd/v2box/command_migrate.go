package main

import (
	"io"
	"os"

	"github.com/sagernet/sing-box/common/json"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/v2box"

	"github.com/spf13/cobra"
)

var commandMigrate = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate your v2ray configuration into sing-box.",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := migrate()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	command.AddCommand(commandMigrate)
}

func migrate() error {
	var (
		options option.Options
		content []byte
		err     error
	)
	if configPath == "stdin" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(configPath)
	}
	if err != nil {
		return E.Cause(err, "read config")
	}
	options, err = v2box.Migrate(configType, content, log.StdLogger())
	if err != nil {
		return E.Cause(err, "load config")
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(options)
}
