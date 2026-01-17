package internal

const (
	saltLength       = 32
	wrappedDEKLength = 60
	headerLength     = saltLength + wrappedDEKLength
)

func PackagePayload(payload EncryptedDataPayload) []byte {
	header := make([]byte, headerLength)

	copy(header[:], payload.Salt)
	copy(header[len(payload.Salt):], payload.DEK)

	buffer := make([]byte, headerLength+len(payload.Payload))
	copy(buffer[:], header)
	copy(buffer[len(header):], payload.Payload)

	return buffer
}

func UnpackagePayload(data []byte) EncryptedDataPayload {
	salt := data[:saltLength]
	edek := data[saltLength:headerLength]
	payload := data[headerLength:]

	return EncryptedDataPayload{
		Salt:    Salt(salt),
		DEK:     WrappedDEK(edek),
		Payload: Ciphertext(payload),
	}
}
