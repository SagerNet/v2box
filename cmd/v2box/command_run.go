package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/v2box"

	"github.com/spf13/cobra"
)

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "run V2Ray with config",
	Run: func(cmd *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	command.AddCommand(commandRun)
}

func run() error {
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
	ctx, cancel := context.WithCancel(context.Background())
	instance, err := box.New(ctx, options, nil)
	if err != nil {
		cancel()
		return E.Cause(err, "create service")
	}
	err = instance.Start()
	if err != nil {
		cancel()
		return E.Cause(err, "start service")
	}
	debug.FreeOSMemory()
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(osSignals)
	<-osSignals
	cancel()
	instance.Close()
	return nil
}
