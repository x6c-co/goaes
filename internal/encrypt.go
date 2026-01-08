package internal

func Encrypt(passphrase string, data []byte) (EncryptedDataPayload, error) {
	salt, err := NewSalt()
	if err != nil {
		return EncryptedDataPayload{}, err
	}

	kek, err := NewKEKFromEnvB64(passphrase, salt)
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
		Salt:    salt,
		Payload: ct,
	}, nil
}
