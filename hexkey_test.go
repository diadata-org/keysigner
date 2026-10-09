package keysigner

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func testDigest(t *testing.T) [32]byte {
	t.Helper()
	var digest [32]byte
	copy(digest[:], crypto.Keccak256([]byte("keysigner test digest")))
	return digest
}

func TestHexKeySigner_SignDigest(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(priv))

	ks, err := NewHexKeySigner(privHex)
	if err != nil {
		t.Fatalf("NewHexKeySigner() error = %v", err)
	}

	if ks.Address() != crypto.PubkeyToAddress(priv.PublicKey) {
		t.Fatalf("Address() = %s, want %s", ks.Address().Hex(), crypto.PubkeyToAddress(priv.PublicKey).Hex())
	}

	digest := testDigest(t)
	sig, err := ks.SignDigest(context.Background(), digest)
	if err != nil {
		t.Fatalf("SignDigest() error = %v", err)
	}

	if sig[64] > 1 {
		t.Fatalf("expected raw recovery id in {0,1}, got %d", sig[64])
	}

	s := new(big.Int).SetBytes(sig[32:64])
	if s.Cmp(secp256k1HalfN) > 0 {
		t.Fatalf("expected low-S signature, got high-S: %s", s.String())
	}

	recovered, err := recoverAddress(digest, sig)
	if err != nil {
		t.Fatalf("recoverAddress() error = %v", err)
	}
	if recovered != ks.Address() {
		t.Fatalf("recovered address %s does not match signer address %s", recovered.Hex(), ks.Address().Hex())
	}
}

func TestHexKeySigner_InvalidKey(t *testing.T) {
	if _, err := NewHexKeySigner("not-hex"); err == nil {
		t.Fatal("expected error for invalid hex key")
	}
}

func TestHexKeySigner_Close(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	ks, err := NewHexKeySigner(hex.EncodeToString(crypto.FromECDSA(priv)))
	if err != nil {
		t.Fatalf("NewHexKeySigner() error = %v", err)
	}
	if err := ks.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
