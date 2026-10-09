package keysigner

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"

	commonAddr "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/miekg/pkcs11"
)

// PKCS11KeySigner is a KeySigner backed by an ECDSA key held in a PKCS#11
// token (e.g. SoftHSM, AWS CloudHSM); private key material never leaves the
// token.
//
// Uses miekg/pkcs11 directly instead of a wrapper like crypto11, which
// whitelists NIST/SEC curves and has no entry for secp256k1.
type PKCS11KeySigner struct {
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	mu         sync.Mutex // serializes PKCS#11 session use
	privHandle pkcs11.ObjectHandle
	address    commonAddr.Address
}

// PKCS11Params configures a PKCS11KeySigner.
type PKCS11Params struct {
	ModulePath string
	TokenLabel string
	SlotNumber *int
	Pin        string
	KeyLabel   string
	// PublicKeyLabel defaults to KeyLabel when empty (CloudHSM requires
	// separate --private-label/--public-label).
	PublicKeyLabel string
	KeyID          []byte
}

// NewPKCS11KeySigner opens a PKCS#11 session and locates the ECDSA key pair
// identified by KeyLabel/KeyID.
func NewPKCS11KeySigner(p PKCS11Params) (*PKCS11KeySigner, error) {
	if p.KeyLabel == "" && len(p.KeyID) == 0 {
		return nil, fmt.Errorf("pkcs11: key_label or key_id is required")
	}

	ctx := pkcs11.New(p.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: failed to load module %q", p.ModulePath)
	}

	var loggedIn, sessionOpen bool // gate deferred cleanup to steps actually set up
	var session pkcs11.SessionHandle
	success := false
	defer func() {
		if success {
			return
		}
		if loggedIn {
			ctx.Logout(session)
		}
		if sessionOpen {
			ctx.CloseSession(session)
		}
		ctx.Finalize()
		ctx.Destroy()
	}()

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11: failed to initialize module: %w", err)
	}

	slotID, err := resolveSlot(ctx, p.TokenLabel, p.SlotNumber)
	if err != nil {
		return nil, err
	}

	session, err = ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: failed to open session: %w", err)
	}
	sessionOpen = true

	if err := ctx.Login(session, pkcs11.CKU_USER, p.Pin); err != nil {
		return nil, fmt.Errorf("pkcs11: failed to login: %w", err)
	}
	loggedIn = true

	privHandle, err := findKeyObject(ctx, session, pkcs11.CKO_PRIVATE_KEY, p.KeyLabel, p.KeyID)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: failed to find private key: %w", err)
	}

	publicKeyLabel := p.PublicKeyLabel
	if publicKeyLabel == "" {
		publicKeyLabel = p.KeyLabel
	}
	pubHandle, err := findKeyObject(ctx, session, pkcs11.CKO_PUBLIC_KEY, publicKeyLabel, p.KeyID)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: failed to find public key: %w", err)
	}

	pub, err := readECDSAPublicKey(ctx, session, pubHandle)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: failed to read public key: %w", err)
	}

	success = true
	return &PKCS11KeySigner{
		ctx:        ctx,
		session:    session,
		privHandle: privHandle,
		address:    gethcrypto.PubkeyToAddress(*pub),
	}, nil
}

// resolveSlot finds the slot matching tokenLabel/slotNumber, or the first slot with a token.
func resolveSlot(ctx *pkcs11.Ctx, tokenLabel string, slotNumber *int) (uint, error) {
	if slotNumber != nil {
		return uint(*slotNumber), nil
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: failed to list slots: %w", err)
	}

	for _, slotID := range slots {
		info, err := ctx.GetTokenInfo(slotID)
		if err != nil {
			continue
		}
		if tokenLabel == "" || trimNulls(info.Label) == tokenLabel {
			return slotID, nil
		}
	}

	return 0, fmt.Errorf("pkcs11: no slot found matching token label %q", tokenLabel)
}

func trimNulls(s string) string {
	for len(s) > 0 && (s[len(s)-1] == 0 || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

func findKeyObject(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, label string, id []byte) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if len(id) > 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to init object search: %w", err)
	}
	defer ctx.FindObjectsFinal(session)

	handles, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("no matching key object found (label=%q id=%x)", label, id)
	}

	return handles[0], nil
}

// readECDSAPublicKey parses CKA_EC_POINT as a secp256k1 public key.
func readECDSAPublicKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	attrs, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read CKA_EC_POINT: %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("CKA_EC_POINT attribute is empty")
	}

	// CKA_EC_POINT is usually DER OCTET STRING-wrapped; some tokens return it raw.
	var point []byte
	if _, err := asn1.Unmarshal(attrs[0].Value, &point); err != nil {
		point = attrs[0].Value
	}

	pub, err := gethcrypto.UnmarshalPubkey(point)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC point as secp256k1 public key: %w", err)
	}

	return pub, nil
}

func (k *PKCS11KeySigner) Address() commonAddr.Address {
	return k.address
}

// SignDigest low-S normalizes the token's signature and brute-forces the
// recovery id against k.address (PKCS#11 has no recovery id concept).
func (k *PKCS11KeySigner) SignDigest(ctx context.Context, digest [32]byte) ([65]byte, error) {
	var sig65 [65]byte

	k.mu.Lock()
	rawSig, err := func() ([]byte, error) {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
		if err := k.ctx.SignInit(k.session, mech, k.privHandle); err != nil {
			return nil, fmt.Errorf("sign init failed: %w", err)
		}
		return k.ctx.Sign(k.session, digest[:])
	}()
	k.mu.Unlock()
	if err != nil {
		return sig65, fmt.Errorf("pkcs11: failed to sign digest: %w", err)
	}

	r, s, err := parseRawRS(rawSig)
	if err != nil {
		return sig65, fmt.Errorf("pkcs11: failed to parse signature: %w", err)
	}

	r, s, _ = normalizeLowS(r, s, 0)

	sig65, err = recoverSignature(digest, r, s, k.address)
	if err != nil {
		return sig65, fmt.Errorf("pkcs11: %w", err)
	}

	return sig65, nil
}

// parseRawRS parses CKM_ECDSA's fixed-length R||S output (not DER).
func parseRawRS(sig []byte) (r, s *big.Int, err error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, nil, fmt.Errorf("invalid signature length from token: %d", len(sig))
	}
	n := len(sig) / 2
	r = new(big.Int).SetBytes(sig[:n])
	s = new(big.Int).SetBytes(sig[n:])
	return r, s, nil
}

func (k *PKCS11KeySigner) Close() error {
	if k.ctx == nil {
		return nil
	}
	k.ctx.Logout(k.session)
	k.ctx.CloseSession(k.session)
	k.ctx.Finalize()
	k.ctx.Destroy()
	return nil
}
