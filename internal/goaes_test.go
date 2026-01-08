package internal_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/nerdsec/goaes/internal"
)

const (
	totalIterationTests = 10
	minSize             = 32
	minWrappedDEKSize   = 60

	//nolint:gosec // this is only for testing and not used for any implementation
	validPassphrase = "dJyHOdMbG94EMvQGQrs6YZiXGiAGQgDYtx6+eqLufQg="
)

func TestNewDEK(t *testing.T) {
	for i := range totalIterationTests {
		t.Run(fmt.Sprintf("TestNewDek %d", i), func(t *testing.T) {
			dek, err := internal.NewDEK()
			if err != nil {
				t.Errorf("failed to create dek. error: %v", err)
			}

			if len(dek) < minSize {
				t.Errorf("dek too small, dek: %v len: %d", dek, len(dek))
			}
		})
	}
}

func TestNewSalt(t *testing.T) {
	for i := range totalIterationTests {
		t.Run(fmt.Sprintf("TestNewSalt %d", i), func(t *testing.T) {
			salt, err := internal.NewSalt()
			if err != nil {
				t.Errorf("failed to create salt. error: %v", err)
			}

			if len(salt) < minSize {
				t.Errorf("salt too small, salt: %v len: %d", salt, len(salt))
			}
		})
	}
}

func TestNewKEKFromEnvB64(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		salt       internal.Salt
		wantErr    bool
	}{
		{
			name:       "Valid base64",
			passphrase: validPassphrase,
			salt:       []byte("kD+tNSxjss1XchcyyrKJyZBGg2mdmhh/IO3I87WW2Ds="),
			wantErr:    false,
		},
		{
			name:       "Invalid passphrase base64",
			passphrase: "dJyHOdMbG94EMvQGQrs6YZiXGiAGQgDYtx6eqLufQg=",
			salt:       []byte("kD+tNSxjss1XchcyyrKJyZBGg2mdmhh/IO3I87WW2Ds="),
			wantErr:    true,
		},
		{
			name:       "Empty seed",
			passphrase: validPassphrase,
			salt:       []byte(""),
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := internal.NewKEKFromEnvB64(tt.passphrase, tt.salt)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewKEKFromEnvB64() failed: %v", gotErr)
				}

				return
			}

			if tt.wantErr {
				t.Fatal("NewKEKFromEnvB64() succeeded unexpectedly")
			}
		})
	}
}

func TestWrapDEK(t *testing.T) {
	kek, err := internal.NewKEKFromEnvB64(
		validPassphrase,
		[]byte("salt"),
	)
	if err != nil {
		t.Fatalf("failed to create kek. error %v", err)
	}

	dek, err := internal.NewDEK()
	if err != nil {
		t.Fatalf("failed to create dek. error %v", err)
	}

	edek, err := internal.WrapDEK(dek, kek)
	if err != nil {
		t.Fatalf("failed to create edek. error %v", err)
	}

	if bytes.Equal(dek, edek) {
		t.Error("dek should not be the same as edek")
	}

	if len(edek) < minWrappedDEKSize {
		t.Errorf("edek too small, edek: %v len: %d", edek, len(edek))
	}
}

func TestUnwrapDEK(t *testing.T) {
	kek, err := internal.NewKEKFromEnvB64(
		validPassphrase,
		[]byte("salt"),
	)
	if err != nil {
		t.Fatalf("failed to create kek. error %v", err)
	}

	dek, err := internal.NewDEK()
	if err != nil {
		t.Fatalf("failed to create dek. error %v", err)
	}

	edek, err := internal.WrapDEK(dek, kek)
	if err != nil {
		t.Fatalf("failed to create edek. error %v", err)
	}

	if bytes.Equal(dek, edek) {
		t.Error("dek should not be the same as edek")
	}

	if len(edek) < minWrappedDEKSize {
		t.Errorf("edek too small, edek: %v len: %d", edek, len(edek))
	}

	unwrapped, err := internal.UnwrapDEK(edek, kek)
	if err != nil {
		t.Fatalf("failed to create edek. error %v", err)
	}

	if !bytes.Equal(dek, unwrapped) {
		t.Errorf("unwrapped key doesn't match, %v %v", edek, unwrapped)
	}
}

func TestEncryptData(t *testing.T) {
	input := []byte("hello")
	dek, err := internal.NewDEK()
	if err != nil {
		t.Fatalf("failed to create dek. error %v", err)
	}

	ct, err := internal.EncryptData(input, dek)
	if err != nil {
		t.Fatalf("failed to encrypt. error %v", err)
	}

	if bytes.Equal(input, ct) {
		t.Error("input wasn't encrypted")
	}
}

func TestDecryptData(t *testing.T) {
	input := []byte("hello")
	dek, err := internal.NewDEK()
	if err != nil {
		t.Fatalf("failed to create dek. error %v", err)
	}

	ct, err := internal.EncryptData(input, dek)
	if err != nil {
		t.Fatalf("failed to encrypt. error %v", err)
	}

	pt, err := internal.DecryptData(ct, dek)
	if err != nil {
		t.Fatalf("failed to decrypt. error %v", err)
	}

	if !bytes.Equal(input, pt) {
		t.Error("decrypted doesn't match input")
	}
}
