package commands

import (
	"context"
	"os"
	"path/filepath"

	"github.com/nerdsec/goaes/internal"
	"github.com/urfave/cli/v3"
)

func Encrypt(ctx context.Context, cmd *cli.Command) error {
	source := cmd.StringArg("source")
	destination := cmd.StringArg("destination")

	if source == "" {
		return cli.Exit("missing source file", invalidArgsExit)
	}

	if destination == "" {
		destination = source + ".goaes"
	}

	source = filepath.Clean(source)
	plaintext, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	passphrase := os.Getenv(PassphraseEnvVar)

	payload, err := internal.Encrypt(passphrase, plaintext)
	if err != nil {
		return err
	}

	buffer := internal.PackagePayload(payload)

	destination = filepath.Clean(destination)
	err = os.WriteFile(destination, buffer, fileMode)
	if err != nil {
		return err
	}

	return nil
}
