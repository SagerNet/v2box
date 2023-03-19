package main

import (
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/v2box"
)

func main() {
	err := v2box.Command.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
