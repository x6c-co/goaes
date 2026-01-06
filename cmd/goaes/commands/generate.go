package commands

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/nerdsec/goaes/internal"
	"github.com/urfave/cli/v3"
)

func Generate(ctx context.Context, cmd *cli.Command) error {
	key, err := internal.NewDEK()
	if err != nil {
		return err
	}

	fmt.Println(base64.StdEncoding.EncodeToString(key))

	return nil
}
