// Package identity manages Ed25519 keypair persistence.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// LoadOrGenerate loads an Ed25519 keypair from path. If the file does not
// exist, a new keypair is generated, written to path (mode 0600), and returned.
func LoadOrGenerate(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return generateAndSave(path)
	}
	if err != nil {
		return nil, nil, err
	}
	return decode(data)
}

func generateAndSave(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func decode(data []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.New("identity: no PEM block in file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("identity: key is not Ed25519")
	}
	return priv.Public().(ed25519.PublicKey), priv, nil
}
