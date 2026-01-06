package main

import (
	"context"
	"log"
	"os"

	"github.com/nerdsec/goaes/cmd/goaes/commands"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "goaes",
		Usage: "Simple AES encryption built with Go",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return cli.DefaultShowRootCommandHelp(cmd)
		},
		Commands: []*cli.Command{
			{
				Name:    "generate",
				Aliases: []string{"g"},
				Usage:   "Generate a base64 encoded key",
				Action:  commands.Generate,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
