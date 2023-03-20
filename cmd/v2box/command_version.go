package main

import (
	"fmt"

	"github.com/sagernet/v2box"

	"github.com/spf13/cobra"
)

var commandVersion = &cobra.Command{
	Use:   "version",
	Short: "Print V2Ray version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		printVersion()
	},
}

func init() {
	command.AddCommand(commandVersion)
}

func printVersion() {
	fmt.Println(v2box.Version(configType))
}
