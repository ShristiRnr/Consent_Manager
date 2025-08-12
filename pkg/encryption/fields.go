package encryption

import (
	"encoding/base64"
	"fmt"
)

// EncryptedString represents an encrypted string value
type EncryptedString string

// Encrypt encrypts a plaintext string and returns an EncryptedString
func (es *EncryptedString) Encrypt(plaintext string) error {
	if plaintext == "" {
		*es = EncryptedString("")
		return nil
	}

	encrypted, err := Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt string: %w", err)
	}
	*es = EncryptedString(encrypted)
	return nil
}

// Decrypt decrypts an EncryptedString and returns the plaintext
func (es EncryptedString) Decrypt() (string, error) {
	if string(es) == "" {
		return "", nil
	}

	plaintext, err := Decrypt(string(es))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt string: %w", err)
	}
	return plaintext, nil
}

// String returns the encrypted value as a string
func (es EncryptedString) String() string {
	return string(es)
}

// EncryptedJSON represents an encrypted JSON value
type EncryptedJSON string

// Encrypt encrypts a plaintext JSON string and returns an EncryptedJSON
func (ej *EncryptedJSON) Encrypt(plaintext string) error {
	if plaintext == "" {
		*ej = EncryptedJSON("")
		return nil
	}

	encrypted, err := Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt JSON: %w", err)
	}
	*ej = EncryptedJSON(encrypted)
	return nil
}

// Decrypt decrypts an EncryptedJSON and returns the plaintext
func (ej EncryptedJSON) Decrypt() (string, error) {
	if string(ej) == "" {
		return "", nil
	}

	plaintext, err := Decrypt(string(ej))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt JSON: %w", err)
	}
	return plaintext, nil
}

// String returns the encrypted value as a string
func (ej EncryptedJSON) String() string {
	return string(ej)
}

// IsValidBase64 checks if a string is valid base64
func IsValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}
