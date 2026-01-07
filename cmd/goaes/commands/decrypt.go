package commands

import (
	"context"
	"encoding/gob"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nerdsec/goaes/internal"
	"github.com/urfave/cli/v3"
)

func Decrypt(ctx context.Context, cmd *cli.Command) error {
	source := cmd.String("source")
	destination := cmd.String("destination")

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

	enc := gob.NewDecoder(file)

	var encryptedPayload internal.EncryptedDataPayload

	err = enc.Decode(&encryptedPayload)
	if err != nil {
		return err
	}

	plaintext, err := internal.Decrypt(encryptedPayload.DEK, encryptedPayload.Payload, encryptedPayload.Salt)
	if err != nil {
		return err
	}

	err = os.WriteFile(destination, plaintext, fileMode)
	if err != nil {
		return err
	}

	return nil
}
