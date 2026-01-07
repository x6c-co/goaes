package commands

import (
	"bytes"
	"context"
	"encoding/gob"
	"os"
	"path/filepath"

	"github.com/nerdsec/goaes/internal"
	"github.com/urfave/cli/v3"
)

func Encrypt(ctx context.Context, cmd *cli.Command) error {
	source := cmd.String("source")
	destination := cmd.String("destination")

	source = filepath.Clean(source)
	plaintext, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	payload, err := internal.Encrypt(plaintext)
	if err != nil {
		return err
	}

	var dataBuffer bytes.Buffer
	enc := gob.NewEncoder(&dataBuffer)

	err = enc.Encode(payload)
	if err != nil {
		return err
	}

	err = os.WriteFile(destination, dataBuffer.Bytes(), fileMode)
	if err != nil {
		return err
	}

	return nil
}
