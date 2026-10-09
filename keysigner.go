// Package keysigner abstracts ECDSA signing behind a common interface so a
// service can sign with an in-memory key or a PKCS#11-backed key (SoftHSM,
// AWS CloudHSM) without depending on where the key material lives.
package keysigner

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
)

// PKCS11PINEnvVar is the conventional env var for a PKCS#11 token PIN.
// Not bound through any config loader so it never gets logged in a config dump.
const PKCS11PINEnvVar = "PKCS11_PIN"

// KeySigner performs ECDSA signing for a single Ethereum address without
// exposing the private key material.
type KeySigner interface {
	// Address derives the Ethereum address from the signer's public key.
	Address() common.Address

	// SignDigest signs a pre-hashed 32-byte digest, returning [R(32)||S(32)||V(1)]
	// with raw recovery id (0/1) and low-S normalized S. Implementations must
	// verify the signature recovers to Address() before returning it.
	SignDigest(ctx context.Context, digest [32]byte) ([65]byte, error)

	// Close releases resources held by the signer.
	Close() error
}
