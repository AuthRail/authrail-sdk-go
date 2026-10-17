package authrail

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ParseExecutorPrivateKeyPEM reads a PKCS#8 Ed25519 key held by the protected application.
func ParseExecutorPrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("executor key must be a single PKCS#8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("executor key must be Ed25519")
	}
	if subtle.ConstantTimeCompare(ed25519.NewKeyFromSeed(key.Seed()), key) != 1 {
		return nil, errors.New("executor key is invalid")
	}
	return append(ed25519.PrivateKey(nil), key...), nil
}
