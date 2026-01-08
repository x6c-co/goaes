package internal

func Decrypt(passphrase string, edek WrappedDEK, ct Ciphertext, salt Salt) ([]byte, error) {
	kek, err := NewKEKFromEnvB64(passphrase, salt)
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
