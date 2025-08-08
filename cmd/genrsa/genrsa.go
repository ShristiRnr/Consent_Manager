package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func main() {
	// Generate RSA Private Key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Save Private Key
	privFile, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer privFile.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	// Save Public Key
	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	pubFile, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	defer pubFile.Close()
	pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1})
}
