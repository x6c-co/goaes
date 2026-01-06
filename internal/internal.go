package internal

import "errors"

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
