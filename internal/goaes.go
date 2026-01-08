package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	time    = 3
	memory  = 256 * 1024 // 256mb
	threads = 4
	keyLen  = 32
)

func NewKEKFromEnvB64(b64Passphrase string, salt Salt) (KEK, error) {
	passphrase, err := base64.StdEncoding.DecodeString(b64Passphrase)
	if err != nil {
		return nil, fmt.Errorf("decode %s base64: %w", b64Passphrase, err)
	}

	raw := argon2.IDKey(passphrase, salt, time, memory, threads, keyLen)

	if !validAESKeyLen(len(raw)) {
		return nil, errBadKeyLn
	}

	return KEK(raw), nil
}

func NewDEK() (DEK, error) {
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("random DEK gen: %w", err)
	}

	return DEK(key), nil
}

func NewSalt() (Salt, error) {
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("random salt gen: %w", err)
	}

	return Salt(key), nil
}

func WrapDEK(dek DEK, kek KEK) (WrappedDEK, error) {
	edek, err := encryptAEAD([]byte(dek), []byte(kek), aadWrapDEK)

	return WrappedDEK(edek), err
}

func UnwrapDEK(edek WrappedDEK, kek KEK) (DEK, error) {
	dek, err := decryptAEAD([]byte(edek), []byte(kek), aadWrapDEK)

	return DEK(dek), err
}

func EncryptData(plaintext []byte, dek DEK) (Ciphertext, error) {
	ct, err := encryptAEAD(plaintext, []byte(dek), aadDataMsg)

	return Ciphertext(ct), err
}

func DecryptData(ct Ciphertext, dek DEK) ([]byte, error) {
	return decryptAEAD([]byte(ct), []byte(dek), aadDataMsg)
}

// encryptAEAD returns: nonce || ciphertext
func encryptAEAD(plaintext, key, aad []byte) ([]byte, error) {
	if !validAESKeyLen(len(key)) {
		return nil, errBadKeyLn
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func decryptAEAD(ciphertext, key, aad []byte) ([]byte, error) {
	if !validAESKeyLen(len(key)) {
		return nil, errBadKeyLn
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:ns]
	body := ciphertext[ns:]

	return gcm.Open(nil, nonce, body, aad)
}

func validAESKeyLen(n int) bool {
	return n == 16 || n == 24 || n == 32
}
