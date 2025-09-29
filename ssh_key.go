package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type KeyGenerator func() (any, error)

var keyGenerators = map[string]KeyGenerator{
	"rsa":     generateRsa,
	"ed25519": generateEd25519,
	"ecdsa":   generateEcdsa,
}

func generateRsa() (any, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func generateEd25519() (any, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	return privateKey, err
}

func generateEcdsa() (any, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func loadHostKeys() ([]ssh.Signer, error) {
	log.Printf("prepare host keys")
	var signers []ssh.Signer
	for keyType, generator := range keyGenerators {
		filename := config.SshHostKeyPath + "ssh_host_" + keyType + "_key"
		key, err := generateLoadKey(filename, generator)
		if err != nil {
			return nil, fmt.Errorf("error loading %s: %w", filename, err)
		}

		signer, err := gossh.NewSignerFromKey(key)
		if err != nil {
			return nil, fmt.Errorf("error creating signer from %s: %w", filename, err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

func generateLoadKey(filename string, generator KeyGenerator) (any, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Printf("%s not found, generating new key", filename)
		key, err := generator()
		if err != nil {
			return nil, fmt.Errorf("error generating %s: %w", filename, err)
		}

		privBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("error marshalling %s: %w", filename, err)
		}

		file, err := os.Create(filename)
		if err != nil {
			return nil, fmt.Errorf("error creating %s: %w", filename, err)
		}
		defer file.Close()

		pem.Encode(file, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		})
		return key, nil
	}

	log.Printf("Loading %s", filename)
	privPem, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %w", filename, err)
	}

	block, _ := pem.Decode(privPem)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", filename, err)
	}
	return key, nil
}
