package internal

import (
	"github.com/joho/godotenv"
)

func Decrypt(edek WrappedDEK, ct Ciphertext) ([]byte, error) {
	godotenv.Load()

	kek, err := NewKEKFromEnvB64("SECRET_KEY")
	if err != nil {
		return nil, err
	}

	dek2, err := UnwrapDEK(edek, kek)
	if err != nil {
		return nil, err
	}

	pt, err := DecryptData(ct, dek2)
	if err != nil {
		return nil, err
	}

	return pt, nil
}
