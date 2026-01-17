package internal_test

import (
	"bytes"
	"testing"

	"github.com/nerdsec/goaes/internal"
)

func TestPackagePayload(t *testing.T) {
	const (
		passphrase = "test"
		message    = "hello"
	)

	payload, err := internal.Encrypt(passphrase, []byte(message))
	if err != nil {
		t.Error("failed to encrypt payload during test")
	}

	packaged := internal.PackagePayload(payload)
	if packaged == nil {
		t.Error("package shouldn't be nil")
	}

	unpackaged := internal.UnpackagePayload(packaged)

	plaintext, err := internal.Decrypt(
		passphrase,
		unpackaged.DEK,
		unpackaged.Payload,
		unpackaged.Salt,
	)
	if err != nil {
		t.Error("failed to decrypt")
	}

	if !bytes.Equal(plaintext, []byte(message)) {
		t.Error("plaintext didn't match")
	}
}
