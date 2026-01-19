package internal

import "errors"

// Decrypt recreates the kek from a passphrase and a salt, unwraps the dek using
// the kek, decrypts the data using the dek, and then returns the plaintext.
func Decrypt(passphrase string, edek WrappedDEK, ct Ciphertext, salt Salt) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase cannot be empty")
	}

	if len(edek) == 0 {
		return nil, errors.New("wrapped DEK cannot be empty")
	}

	if len(ct) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}

	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	kek, err := NewKEKFromEnvB64(passphrase, salt)
	if err != nil {
		return nil, err
	}

	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()

	dek, err := UnwrapDEK(edek, kek)
	if err != nil {
		return nil, err
	}

	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	pt, err := DecryptData(ct, dek)
	if err != nil {
		return nil, err
	}

	return pt, nil
}
