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
	validPassphrase     = "dJyHOdMbG94EMvQGQrs6YZiXGiAGQgDYtx6+eqLufQg="
)

func TestNewDEK(t *testing.T) {
	for i := range totalIterationTests {
		t.Run(fmt.Sprintf("TestNewDek %d", i), func(t *testing.T) {
			dek, err := internal.NewDEK()
			if err != nil {
				t.Errorf("failed to create dek. error: %v", err)
			}

			if len(dek) < minSize {
				t.Errorf("dek too small")
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
				t.Errorf("salt too small")
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
}
