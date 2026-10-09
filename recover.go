package keysigner

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// For low-S normalization (EIP-2).
var (
	secp256k1N     = crypto.S256().Params().N
	secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)
)

// recoverAddress recovers the signer address from a [R||S||V] signature (V in {0,1}).
func recoverAddress(digest [32]byte, sig [65]byte) (common.Address, error) {
	pub, err := crypto.SigToPub(digest[:], sig[:])
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// normalizeLowS flips s and its recovery id to low-S form if currently high-S.
func normalizeLowS(r, s *big.Int, recoveryID byte) (*big.Int, *big.Int, byte) {
	if s.Cmp(secp256k1HalfN) > 0 {
		s = new(big.Int).Sub(secp256k1N, s)
		recoveryID ^= 1
	}
	return r, s, recoveryID
}

// recoverSignature brute-forces which recovery id in {0,1} recovers to expected.
func recoverSignature(digest [32]byte, r, s *big.Int, expected common.Address) ([65]byte, error) {
	var sig65 [65]byte

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig65[32-len(rBytes):32], rBytes)
	copy(sig65[64-len(sBytes):64], sBytes)

	for v := byte(0); v < 2; v++ {
		sig65[64] = v
		recovered, err := recoverAddress(digest, sig65)
		if err != nil {
			continue
		}
		if recovered == expected {
			return sig65, nil
		}
	}

	return sig65, fmt.Errorf("recovered address mismatch: no recovery id for signature matches expected signer address %s", expected.Hex())
}
