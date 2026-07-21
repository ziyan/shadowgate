package main

import (
	"os"

	"github.com/ziyan/shadowgate/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args))
}
