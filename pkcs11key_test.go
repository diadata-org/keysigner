//go:build pkcs11integration

package keysigner

import (
	"context"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// These tests exercise PKCS11KeySigner against a real PKCS#11 token (e.g.
// SoftHSM2). They are gated behind the pkcs11integration build tag and skip
// unless the KEYSIGNER_TEST_PKCS11_* env vars are set, so `go test ./...`
// never requires a PKCS#11 module to be present.
//
// To provision a local SoftHSM2 token for this test:
//
//	export SOFTHSM2_CONF=/tmp/keysigner-softhsm/softhsm2.conf
//	mkdir -p /tmp/keysigner-softhsm/tokens
//	cat > "$SOFTHSM2_CONF" <<EOF
//	directories.tokendir = /tmp/keysigner-softhsm/tokens
//	EOF
//	softhsm2-util --init-token --free --label keysigner-test --pin 1234 --so-pin 5678
//	pkcs11-tool --module "$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so" \
//	  --token-label keysigner-test --login --pin 1234 \
//	  --keypairgen --key-type EC:secp256k1 --label keysigner-test-key --id 01 --usage-sign
//
// Then run:
//
//	SOFTHSM2_CONF=/tmp/keysigner-softhsm/softhsm2.conf \
//	KEYSIGNER_TEST_PKCS11_MODULE_PATH="$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so" \
//	KEYSIGNER_TEST_PKCS11_TOKEN_LABEL=keysigner-test \
//	KEYSIGNER_TEST_PKCS11_KEY_LABEL=keysigner-test-key \
//	KEYSIGNER_TEST_PKCS11_PIN=1234 \
//	go test -tags pkcs11integration ./...

func pkcs11TestParams(t *testing.T) PKCS11Params {
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

	return PKCS11Params{
		ModulePath:     modulePath,
		TokenLabel:     tokenLabel,
		Pin:            pin,
		KeyLabel:       keyLabel,
		PublicKeyLabel: publicKeyLabel,
	}
}

func TestPKCS11KeySigner_SignDigest(t *testing.T) {
	params := pkcs11TestParams(t)

	ks, err := NewPKCS11KeySigner(params)
	if err != nil {
		t.Fatalf("NewPKCS11KeySigner() error = %v", err)
	}
	defer ks.Close()

	if ks.Address() == (common.Address{}) {
		t.Fatal("expected non-zero address derived from PKCS#11 public key")
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

func TestPKCS11KeySigner_MultipleSignaturesConcurrent(t *testing.T) {
	params := pkcs11TestParams(t)

	ks, err := NewPKCS11KeySigner(params)
	if err != nil {
		t.Fatalf("NewPKCS11KeySigner() error = %v", err)
	}
	defer ks.Close()

	const n = 8
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			var digest [32]byte
			copy(digest[:], crypto.Keccak256([]byte("concurrent digest")))
			digest[31] = byte(i)

			sig, err := ks.SignDigest(context.Background(), digest)
			if err != nil {
				errCh <- err
				return
			}
			recovered, err := recoverAddress(digest, sig)
			if err != nil {
				errCh <- err
				return
			}
			if recovered != ks.Address() {
				errCh <- err
				return
			}
			errCh <- nil
		}(i)
	}

	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent SignDigest() error = %v", err)
		}
	}
}
