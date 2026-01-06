package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	base64kek := os.Getenv("SECRET_KEY")

	kek, err := base64.StdEncoding.DecodeString(base64kek)
	if err != nil {
		panic(err)
	}

	dek := GenCipherKey()

	encryptedDek, err := Encrypt(dek, kek)
	if err != nil {
		panic(err)
	}

	fmt.Println("edek", encryptedDek)

	cipherText, err := Encrypt([]byte("hello"), dek)
	if err != nil {
		panic(err)
	}

	fmt.Println("ciphertext", cipherText)
}

type CipherKey []byte

func GenCipherKey() CipherKey {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatalf("random key gen: %v", err)
	}
	return CipherKey(key)
}

func Encrypt(plaintext []byte, key CipherKey) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext []byte, key CipherKey) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
