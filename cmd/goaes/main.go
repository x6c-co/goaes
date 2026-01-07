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
			{
				Name:    "encrypt",
				Aliases: []string{"e"},
				Usage:   "Encrypt a file",
				Action:  commands.Encrypt,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "source",
						Aliases:  []string{"s"},
						Usage:    "source file to encrypt",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "destination",
						Aliases:  []string{"d"},
						Usage:    "where to write the encrypted file",
						Required: true,
					},
				},
			},
			{
				Name:    "decrypt",
				Aliases: []string{"d"},
				Usage:   "Decrypt a file",
				Action:  commands.Decrypt,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
