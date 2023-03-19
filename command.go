package v2box

import (
	"encoding/json"
	"io"
	"os"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/v2box/v2rayjson"

	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "v2ray2box",
	Short: "Migrate your v2ray configuration into sing-box.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := Run(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func Run(path string) error {
	var (
		content []byte
		err     error
	)
	if path == "stdin" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(path)
	}
	if err != nil {
		return E.Cause(err, "read v2ray config")
	}
	options, err := v2rayjson.Migrate(content, log.StdLogger())
	if err != nil {
		return E.Cause(err, "load v2ray config")
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stderr)
	encoder.SetIndent("", "  ")
	return encoder.Encode(options)
}
