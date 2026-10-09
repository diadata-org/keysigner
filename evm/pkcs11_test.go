//go:build pkcs11integration

package evm

import (
	"context"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/diadata-org/keysigner"
)

// pkcs11TestParams builds PKCS11Params from KEYSIGNER_TEST_PKCS11_* env
// vars, skipping the test if any required var is unset. Duplicated from
// keysigner's own test helper since Go test files can't export across
// package boundaries.
func pkcs11TestParams(t *testing.T) keysigner.PKCS11Params {
	t.Helper()

	modulePath := os.Getenv("KEYSIGNER_TEST_PKCS11_MODULE_PATH")
	tokenLabel := os.Getenv("KEYSIGNER_TEST_PKCS11_TOKEN_LABEL")
	keyLabel := os.Getenv("KEYSIGNER_TEST_PKCS11_KEY_LABEL")
	publicKeyLabel := os.Getenv("KEYSIGNER_TEST_PKCS11_PUBLIC_KEY_LABEL") // optional, defaults to keyLabel
	pin := os.Getenv("KEYSIGNER_TEST_PKCS11_PIN")

	if modulePath == "" || tokenLabel == "" || keyLabel == "" || pin == "" {
		t.Skip("Skipping PKCS#11 integration test: KEYSIGNER_TEST_PKCS11_MODULE_PATH, " +
			"KEYSIGNER_TEST_PKCS11_TOKEN_LABEL, KEYSIGNER_TEST_PKCS11_KEY_LABEL, and " +
			"KEYSIGNER_TEST_PKCS11_PIN must all be set")
	}

	return keysigner.PKCS11Params{
		ModulePath:     modulePath,
		TokenLabel:     tokenLabel,
		Pin:            pin,
		KeyLabel:       keyLabel,
		PublicKeyLabel: publicKeyLabel,
	}
}

func TestSigner_SignTx_PKCS11(t *testing.T) {
	params := pkcs11TestParams(t)

	ks, err := keysigner.NewPKCS11KeySigner(params)
	if err != nil {
		t.Fatalf("NewPKCS11KeySigner() error = %v", err)
	}
	defer ks.Close()

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
