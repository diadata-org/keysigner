// Package evm signs EVM transactions on top of any keysigner.KeySigner.
package evm

import (
	"context"
	"fmt"

	ethTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/diadata-org/keysigner"
)

// Signer wraps a KeySigner with EVM transaction signing.
type Signer struct {
	keysigner.KeySigner
}

// New wraps ks for EVM transaction signing.
func New(ks keysigner.KeySigner) Signer {
	return Signer{KeySigner: ks}
}

// SignTx signs tx's sighash via SignDigest and attaches the signature.
func (s Signer) SignTx(ctx context.Context, signer ethTypes.Signer, tx *ethTypes.Transaction) (*ethTypes.Transaction, error) {
	hash := signer.Hash(tx)

	sig, err := s.SignDigest(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction digest: %w", err)
	}

	signedTx, err := tx.WithSignature(signer, sig[:])
	if err != nil {
		return nil, fmt.Errorf("failed to attach signature to transaction: %w", err)
	}

	return signedTx, nil
}
