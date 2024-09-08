package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// ProcessDataGCM processes data using AES encryption in GCM mode.
// The 'operation' parameter specifies whether to encrypt or decrypt the data.
func ProcessDataGCM(data, secretKey, operation string) (string, error) {
	// Initialize the AES cipher block using the provided key
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("error initializing cipher: %w", err)
	}

	// Create a GCM mode instance for the AES block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM instance: %w", err)
	}

	// Generate a nonce to be used in the operation
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("error generating nonce: %w", err)
	}

	switch operation {
	case "encrypt":
		// Encrypt the data and include the nonce for reference
		ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
		return base64.StdEncoding.EncodeToString(ciphertext), nil

	case "decrypt":
		// Decode the base64 encoded data for decryption
		decodedData, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return "", fmt.Errorf("error decoding base64 data: %w", err)
		}

		// Separate the nonce from the ciphertext and decrypt the data
		nonce, ciphertext := decodedData[:gcm.NonceSize()], decodedData[gcm.NonceSize():]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return "", fmt.Errorf("error decrypting data: %w", err)
		}
		return string(plaintext), nil

	default:
		return "", fmt.Errorf("invalid operation: %s", operation)
	}
}

// GenerateRandomKey creates a secure random key of the specified length.
// This key can be used for encryption or other secure operations.
func GenerateRandomKey(length int) (string, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("error generating random key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// XORCipher performs a simple bitwise XOR operation on the data using the provided key.
func XORCipher(data, key string) string {
	keyLen := len(key)
	result := make([]byte, len(data))

	for i := range data {
		// Apply XOR and rotate bits to modify the data
		result[i] = (data[i]^key[i%keyLen])<<1 | (data[i]^key[i%keyLen])>>7
	}

	return string(result)
}

// MultiPassXOR applies the XORCipher function multiple times to add extra layers of processing.
func MultiPassXOR(data, key string, passes int) string {
	result := data
	for i := 0; i < passes; i++ {
		result = XORCipher(result, key)
	}
	return result
}
