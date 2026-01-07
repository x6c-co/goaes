package internal

import (
	"github.com/joho/godotenv"
)

func Encrypt(data []byte) (EncryptedDataPayload, error) {
	godotenv.Load()

	kek, err := NewKEKFromEnvB64("SECRET_KEY")
	if err != nil {
		return EncryptedDataPayload{}, err
	}

	dek, err := NewDEK()
	if err != nil {
		return EncryptedDataPayload{}, err
	}

	edek, err := WrapDEK(dek, kek)
	if err != nil {
		return EncryptedDataPayload{}, err
	}

	ct, err := EncryptData(data, dek)
	if err != nil {
		return EncryptedDataPayload{}, err
	}

	return EncryptedDataPayload{
		DEK:     edek,
		Payload: ct,
	}, nil
}
