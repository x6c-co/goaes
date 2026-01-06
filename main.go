package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type (
	KEK        []byte
	DEK        []byte
	WrappedDEK []byte
	Ciphertext []byte
)

type EncryptedDataPayload struct {
	DEK     WrappedDEK
	Payload Ciphertext
}

var (
	aadWrapDEK  = []byte("wrap:dek:v1")
	aadDataMsg  = []byte("data:msg:v1")
	errBadKeyLn = errors.New("invalid key length: must be 16, 24, or 32 bytes")
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	kek, err := NewKEKFromEnvB64("SECRET_KEY")
	if err != nil {
		log.Fatal(err)
	}

	dek, err := NewDEK()
	if err != nil {
		log.Fatal(err)
	}

	edek, err := WrapDEK(dek, kek)
	if err != nil {
		log.Fatal(err)
	}

	ct, err := EncryptData([]byte("hello"), dek)
	if err != nil {
		log.Fatal(err)
	}

	// Print as base64 for readability/transport.
	fmt.Println("edek_b64:", base64.StdEncoding.EncodeToString(edek))
	fmt.Println("ct_b64:  ", base64.StdEncoding.EncodeToString(ct))

	var dataBuffer bytes.Buffer
	enc := gob.NewEncoder(&dataBuffer)

	err = enc.Encode(EncryptedDataPayload{
		DEK:     edek,
		Payload: ct,
	})

	fmt.Println(dataBuffer)

	os.WriteFile("out.bin", dataBuffer.Bytes(), 0666)

	// Round-trip demo.
	dek2, err := UnwrapDEK(edek, kek)
	if err != nil {
		log.Fatal(err)
	}

	pt, err := DecryptData(ct, dek2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("pt:", string(pt))
}

func NewKEKFromEnvB64(envVar string) (KEK, error) {
	b64 := os.Getenv(envVar)
	if b64 == "" {
		return nil, fmt.Errorf("%s is not set", envVar)
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode %s base64: %w", envVar, err)
	}

	if !validAESKeyLen(len(raw)) {
		return nil, errBadKeyLn
	}

	return KEK(raw), nil
}

func NewDEK() (DEK, error) {
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("random DEK gen: %w", err)
	}
	return DEK(key), nil
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
