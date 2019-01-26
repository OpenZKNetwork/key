// Package did Ontology Distributed Identification Protocol impelement
package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/openzknetwork/key/internal/hash160"
	"github.com/openzknetwork/key/sign"
	"github.com/openzknetwork/key/sign/recoverable"

	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/key"
	"github.com/openzknetwork/key/internal/ecdsax"
	"github.com/openzknetwork/key/internal/secp256k1"
)

var version = byte(18)

func pubKeyToAddress(pub *ecdsa.PublicKey) string {

	pubBytes := ecdsax.PublicKeyBytes(pub)

	var nonce []byte

	if len(pubBytes) < 32 {
		nonce = make([]byte, 32)
		copy(nonce[:], pubBytes)
	} else {
		nonce = pubBytes[:32]
	}

	hashed := hash160.Hash160(nonce)

	hasher := sha256.New()

	hasher.Write(hashed)

	sum := hasher.Sum(nil)

	hasher.Reset()

	hasher.Write(sum)

	sum = hasher.Sum(nil)

	sum = sum[:3]

	did := append(hashed, sum...)

	return "did:lpt:" + base58.CheckEncode(did, version)
}

type didImpl struct {
	provider key.Provider
	key      *ecdsa.PrivateKey
	address  string // address
}

func (key *didImpl) Address() string {
	return key.address
}

func (key *didImpl) Provider() key.Provider {
	return key.provider
}

func (key *didImpl) PriKey() []byte {
	return ecdsax.PrivateKeyBytes(key.key)
}

func (key *didImpl) PubKey() []byte {
	return ecdsax.PublicKeyBytes(&key.key.PublicKey)
}

func (key *didImpl) SetBytes(priKey []byte) {

	key.key = ecdsax.BytesToPrivateKey(priKey, secp256k1.SECP256K1())

	key.address = pubKeyToAddress(&key.key.PublicKey)
}

func (key *didImpl) Sign(hashed []byte) ([]byte, error) {

	sig, err := recoverable.Sign(key.key, hashed, false)

	if err != nil {
		return nil, err
	}

	size := key.key.Curve.Params().BitSize / 8

	buff := make([]byte, 2*size+1)

	copy(buff, sig.R.Bytes()[:size])
	copy(buff[size:], sig.S.Bytes()[:size])
	buff[2*size] = sig.V.Bytes()[0]

	return buff, nil
}

type providerIml struct {
}

func (provider *providerIml) Name() string {
	return "did"
}

func (provider *providerIml) New() (key.Key, error) {

	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	if err != nil {
		return nil, xerrors.Wrapf(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	return &didImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(&privateKey.PublicKey),
	}, nil
}

func (provider *providerIml) FromBytes(buff []byte) key.Key {
	privateKey := ecdsax.BytesToPrivateKey(buff, secp256k1.SECP256K1())

	return &didImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(&privateKey.PublicKey),
	}
}

func (provider *providerIml) Verify(pubkey []byte, sig []byte, hash []byte) bool {

	curve := secp256k1.SECP256K1()

	size := curve.Params().BitSize / 8

	if len(sig) != 2*size+1 {
		return false
	}

	signature := &sign.Signature{
		R: new(big.Int).SetBytes(sig[:size]),
		S: new(big.Int).SetBytes(sig[size : 2*size]),
		V: new(big.Int).SetBytes(sig[2*size:]),
	}

	publicKey, _, err := recoverable.Recover(curve, signature, hash)

	if err != nil {
		return false
	}

	return signature.Verfiy(publicKey, hash)
}

func (provider *providerIml) PublicKeyToAddress(pubkey []byte) (string, error) {

	publicKey := ecdsax.BytesToPublicKey(secp256k1.SECP256K1(), pubkey)

	if nil == publicKey {
		return "", xerrors.Wrapf(key.ErrPublicKey, "decode public key error")
	}

	return pubKeyToAddress(publicKey), nil
}

func (provider *providerIml) PrivateToPublic(privateKey []byte) []byte {
	key := provider.FromBytes(privateKey)

	return key.PubKey()
}
func (provider *providerIml) Curve() elliptic.Curve {
	return secp256k1.SECP256K1()
}

func (provider *providerIml) Recover(sig []byte, hash []byte) (pubkey []byte, err error) {
	curve := secp256k1.SECP256K1()

	size := curve.Params().BitSize / 8

	if len(sig) != 2*size+1 {
		return nil, xerrors.Wrapf(key.ErrPublicKey, " public key length error")
	}

	signature := &sign.Signature{
		R: new(big.Int).SetBytes(sig[:size]),
		S: new(big.Int).SetBytes(sig[size : 2*size]),
		V: new(big.Int).SetBytes(sig[2*size:]),
	}

	publicKey, _, err := recoverable.Recover(curve, signature, hash)

	return ecdsax.PublicKeyBytes(publicKey), nil
}

func (provider *providerIml) ValidAddress(address string) bool {
	tokens := strings.Split(address, ":")

	if len(tokens) != 3 {
		return false
	}

	if tokens[0] != "did" || tokens[1] != "lpt" {
		return false
	}

	_, v, err := base58.CheckDecode(tokens[2])

	if err != nil {
		return false
	}

	return v == version
}

func init() {
	key.RegisterProvider(&providerIml{})
}
