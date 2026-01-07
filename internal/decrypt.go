package internal

func Decrypt(edek WrappedDEK, ct Ciphertext, salt Salt) ([]byte, error) {
	kek, err := NewKEKFromEnvB64("GOAES_PASSPHRASE", salt)
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
