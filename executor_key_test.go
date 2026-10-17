package authrail

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParseExecutorPrivateKeyPEM(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := ParseExecutorPrivateKeyPEM(encoded)
	if err != nil || !bytes.Equal(parsed, key) {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := ParseExecutorPrivateKeyPEM([]byte("bad key")); err == nil {
		t.Fatal("invalid key accepted")
	}
	if _, err := ParseExecutorPrivateKeyPEM(append(encoded, encoded...)); err == nil {
		t.Fatal("extra key accepted")
	}
}
