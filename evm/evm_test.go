package evm

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/diadata-org/keysigner"
)

func TestSigner_SignTx(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	ks, err := keysigner.NewHexKeySigner(hex.EncodeToString(crypto.FromECDSA(priv)))
	if err != nil {
		t.Fatalf("NewHexKeySigner() error = %v", err)
	}

	to := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := ethTypes.NewTx(&ethTypes.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     nil,
	})

	chainSigner := ethTypes.NewEIP155Signer(big.NewInt(1))
	evmSigner := New(ks)
	signedTx, err := evmSigner.SignTx(context.Background(), chainSigner, tx)
	if err != nil {
		t.Fatalf("SignTx() error = %v", err)
	}

	sender, err := ethTypes.Sender(chainSigner, signedTx)
	if err != nil {
		t.Fatalf("failed to recover sender: %v", err)
	}
	if sender != evmSigner.Address() {
		t.Fatalf("recovered sender %s does not match signer address %s", sender.Hex(), evmSigner.Address().Hex())
	}
}
