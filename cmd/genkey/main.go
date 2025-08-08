package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/sha3"
)

func main() {
	const keySize = 32

	// Generate a secure random 256-bit (32-byte) key
	rawKey := make([]byte, keySize)
	if _, err := rand.Read(rawKey); err != nil {
		log.Fatalf("Failed to generate random key: %v", err)
	}

	// Encode raw key to hex
	rawKeyHex := hex.EncodeToString(rawKey)

	// Hash the key using SHA3-256
	hasher := sha3.New256()
	hasher.Write([]byte(rawKeyHex))
	hashed := hex.EncodeToString(hasher.Sum(nil))

	// Display results
	fmt.Println("🔑 Raw API Key (store securely):", rawKeyHex)
	fmt.Println("🔒 Hashed Key (store in DB):", hashed)
}
