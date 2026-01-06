package internal

import (
	"crypto/rand"
	"fmt"
	"io"
)

func NewDEK() (DEK, error) {
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("random DEK gen: %w", err)
	}
	return DEK(key), nil
}
