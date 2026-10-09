# keysigner

Shared ECDSA signing abstraction for DIA services: one `KeySigner`
interface with two backends, so a service can sign with an in-memory
private key or a PKCS#11 HSM key (SoftHSM, AWS CloudHSM) without the rest
of the codebase knowing where the key material lives.

- `HexKeySigner` — in-memory key from hex (default backend, also the test
  fixture).
- `PKCS11KeySigner` — PKCS#11 token via [miekg/pkcs11] (cgo). Raw
  `CKM_ECDSA`, secp256k1 public key read via go-ethereum's curve, low-S
  normalization, recovery id brute-forced against the signer's own
  address, every signature verified before return.

## Interface

```go
type KeySigner interface {
	Address() common.Address
	SignDigest(ctx context.Context, digest [32]byte) ([65]byte, error)
	Close() error
}
```

`SignDigest` takes a pre-hashed 32-byte digest and returns
`[R(32) || S(32) || V(1)]` with V the raw recovery id (0/1) and S
low-normalized. Implementations verify the signature recovers to
`Address()` before returning — a signature that fails self-check is an
error, never returned.

`KeySigner` only covers algorithm-generic ECDSA/secp256k1 signing. Chain-
specific transaction signing lives in its own subpackage built on top of
any `KeySigner` — see `evm` below — so adding a chain never changes this
interface or its existing backends.

## EVM transaction signing

The `evm` subpackage wraps any `KeySigner` to sign EVM transactions:

```go
type Signer struct { keysigner.KeySigner }

func New(ks keysigner.KeySigner) Signer
func (s Signer) SignTx(ctx context.Context, signer ethTypes.Signer, tx *ethTypes.Transaction) (*ethTypes.Transaction, error)
```

## Usage

```go
// hex backend
ks, err := keysigner.NewHexKeySigner(os.Getenv("PRIVATE_KEY"))

// HSM backend (build with CGO_ENABLED=1)
ks, err := keysigner.NewPKCS11KeySigner(keysigner.PKCS11Params{
	ModulePath: "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
	TokenLabel: "hsm1",
	Pin:        os.Getenv(keysigner.PKCS11PINEnvVar), // "PKCS11_PIN"
	KeyLabel:   "feeder-key",
})

// wrap for EVM transaction signing
evmSigner := evm.New(ks)

// wire into abigen TransactOpts
chainID := big.NewInt(1050)
chainSigner := ethTypes.LatestSignerForChainID(chainID)
auth := &bind.TransactOpts{
	From: evmSigner.Address(),
	Signer: func(addr common.Address, tx *ethTypes.Transaction) (*ethTypes.Transaction, error) {
		return evmSigner.SignTx(ctx, chainSigner, tx)
	},
}
```

PIN convention: read from the `PKCS11_PIN` env var (const
`keysigner.PKCS11PINEnvVar`) at the point of use — never stored in config
files, never logged.

## Building

The hex backend is pure Go. The PKCS#11 backend requires cgo
(`CGO_ENABLED=1`) and the target token's PKCS#11 library present at
runtime (module path is a runtime `dlopen`, not a build-time dependency).

## Testing

```sh
go test ./...                      # unit tests, no HSM needed
go vet ./...

# PKCS#11 integration (SoftHSM2); see header of pkcs11key_test.go for
# full provisioning instructions:
export SOFTHSM2_CONF=$PWD/.softhsm/softhsm2.conf
go test -tags pkcs11integration ./...
```

## Consumers

- `lumina-guardians`  
- `Spectra-interoperability` attestor — EIP-712 intent + registry tx
  signing. 

[miekg/pkcs11]: https://github.com/miekg/pkcs11
