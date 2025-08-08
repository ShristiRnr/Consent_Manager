package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"os"
)

var (
	encryptionKey []byte
	isInitialized bool
)

func InitEncryption() error {
	key := os.Getenv("ENCRYPTION_KEY")
	if len(key) == 32 {
		encryptionKey = []byte(key)
		isInitialized = true
		return nil
	}

	log.Println("[WARN] ENCRYPTION_KEY not found or invalid. Using temporary dev key.")
	tempKey := make([]byte, 32)
	if _, err := rand.Read(tempKey); err != nil {
		return errors.New("failed to generate fallback encryption key")
	}
	encryptionKey = tempKey
	isInitialized = true
	return nil
}

func Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := aesGCM.NonceSize()
	if len(data) < ns {
		return "", errors.New("invalid ciphertext")
	}
	nonce, ciphertext := data[:ns], data[ns:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	return string(plaintext), err
}

func DeterministicEncrypt(value string) (string, error) {
	if !isInitialized {
		return "", errors.New("encryption system not initialized")
	}
	h := hmac.New(sha256.New, encryptionKey)
	h.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func IsReady() bool {
	return isInitialized
}

// DecryptDeterministic decrypts a value that was encrypted using DeterministicEncrypt
func DecryptDeterministic(encoded string) (string, error) {
	if !isInitialized {
		return "", errors.New("encryption system not initialized")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, encryptionKey)
	h.Write(data)
	return string(h.Sum(nil)), nil
}
