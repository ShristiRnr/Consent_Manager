package auth

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateSecureToken creates a random, URL-safe, hex-encoded string.
func GenerateSecureToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// In a real-world scenario, this error should be handled more robustly.
		// For now, we panic because if the OS's entropy source fails, we can't generate secure tokens.
		panic("failed to generate secure token: " + err.Error())
	}
	return hex.EncodeToString(b)
}
