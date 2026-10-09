package keysigner

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// HexKeySigner is a KeySigner backed by an in-memory ECDSA private key.
type HexKeySigner struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
}

// NewHexKeySigner parses a hex-encoded ECDSA private key (with or without a 0x prefix).
func NewHexKeySigner(privateKeyHex string) (*HexKeySigner, error) {
	cleanKey := strings.TrimPrefix(privateKeyHex, "0x")
	privateKey, err := crypto.HexToECDSA(cleanKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &HexKeySigner{
		privateKey: privateKey,
		address:    crypto.PubkeyToAddress(privateKey.PublicKey),
	}, nil
}

func (k *HexKeySigner) Address() common.Address {
	return k.address
}

func (k *HexKeySigner) SignDigest(ctx context.Context, digest [32]byte) ([65]byte, error) {
	var sig65 [65]byte

	sig, err := crypto.Sign(digest[:], k.privateKey)
	if err != nil {
		return sig65, fmt.Errorf("failed to sign digest: %w", err)
	}
	copy(sig65[:], sig)

	recovered, err := recoverAddress(digest, sig65)
	if err != nil {
		return sig65, fmt.Errorf("failed to verify signature: %w", err)
	}
	if recovered != k.address {
		return sig65, fmt.Errorf("signature verification failed: recovered address %s does not match signer address %s", recovered.Hex(), k.address.Hex())
	}

	return sig65, nil
}

func (k *HexKeySigner) Close() error {
	return nil
}
