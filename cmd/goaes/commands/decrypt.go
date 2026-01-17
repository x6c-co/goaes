package commands

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nerdsec/goaes/internal"
	"github.com/urfave/cli/v3"
)

func Decrypt(ctx context.Context, cmd *cli.Command) error {
	source := cmd.StringArg("source")
	destination := cmd.StringArg("destination")

	if source == "" {
		return cli.Exit("missing source", invalidArgsExit)
	}

	if destination == "" {
		return cli.Exit("missing destination", invalidArgsExit)
	}

	source = filepath.Clean(source)
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			slog.Error("failed to close file", "error", err)
		}
	}()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	encryptedPayload := internal.UnpackagePayload(data)

	passphrase := os.Getenv(PassphraseEnvVar)

	plaintext, err := internal.Decrypt(passphrase, encryptedPayload.DEK, encryptedPayload.Payload, encryptedPayload.Salt)
	if err != nil {
		return err
	}

	destination = filepath.Clean(destination)
	err = os.WriteFile(destination, plaintext, fileMode)
	if err != nil {
		return err
	}

	return nil
}
