package bnb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/key/internal/bech32"
	"github.com/openzknetwork/key/internal/hash160"
	"github.com/openzknetwork/key/internal/secp256k1"

	"github.com/openzknetwork/key"
	"github.com/openzknetwork/key/internal/ecdsax"
	"github.com/openzknetwork/key/sign"
	"github.com/openzknetwork/key/sign/recoverable"
)

var prefixOfPublicKey = []byte{0xEB, 0x5A, 0xE9, 0x87, 0x21}

func pubKeyToAddress(network string, pub *ecdsa.PublicKey) string {

	pubBytes := ecdsax.CompressedPublicKeyBytes(pub)

	// nonce := make([]byte, len(prefixOfPublicKey)+len(pubBytes))

	// copy(nonce, prefixOfPublicKey)
	// copy(nonce[len(prefixOfPublicKey):], pubBytes)

	hashed := hash160.Hash160(pubBytes)

	bech32Addr, err := bech32.ConvertAndEncode(network, hashed)

	if err != nil {
		panic(err)
	}

	return bech32Addr
}

type keyImpl struct {
	provider key.Provider
	key      *ecdsa.PrivateKey
	address  string // address
}

func (key *keyImpl) Address() string {
	return key.address
}

func (key *keyImpl) Provider() key.Provider {
	return key.provider
}

func (key *keyImpl) PriKey() []byte {
	return ecdsax.PrivateKeyBytes(key.key)
}

func (key *keyImpl) PubKey() []byte {
	return ecdsax.CompressedPublicKeyBytes(&key.key.PublicKey)
}

func (key *keyImpl) SetBytes(priKey []byte) {
	key.key = ecdsax.BytesToPrivateKey(priKey, secp256k1.SECP256K1())
	key.address = pubKeyToAddress(key.provider.Name(), &key.key.PublicKey)
}

func (key *keyImpl) Sign(hashed []byte) ([]byte, error) {

	sig, err := recoverable.Sign(key.key, hashed, false)

	if err != nil {
		return nil, err
	}

	size := key.key.Curve.Params().BitSize / 8

	buff := make([]byte, 2*size)

	r := sig.R.Bytes()

	if len(r) > size {
		r = r[:size]
	}

	s := sig.S.Bytes()

	if len(s) > size {
		s = s[:size]
	}

	copy(buff[size-len(r):size], r)
	copy(buff[2*size-len(s):2*size], s)

	return buff, nil

}

type providerIml struct {
	curve elliptic.Curve
	name  string
}

func newProvider(name string, curve elliptic.Curve) key.Provider {
	return &providerIml{
		curve: curve,
		name:  name,
	}
}

func (provider *providerIml) Name() string {
	return provider.name
}

func (provider *providerIml) Verify(pubkey []byte, sig []byte, hash []byte) bool {

	curve := provider.curve

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

func (provider *providerIml) New() (key.Key, error) {

	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	if err != nil {
		return nil, xerrors.Wrapf(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	return &keyImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(provider.name, &privateKey.PublicKey),
	}, nil
}

func (provider *providerIml) FromBytes(buff []byte) key.Key {

	privateKey := ecdsax.BytesToPrivateKey(buff, secp256k1.SECP256K1())

	return &keyImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(provider.name, &privateKey.PublicKey),
	}
}

func (provider *providerIml) PrivateToPublic(privateKey []byte) []byte {
	key := provider.FromBytes(privateKey)

	return key.PubKey()
}
func (provider *providerIml) Curve() elliptic.Curve {
	return provider.curve
}

func (provider *providerIml) PublicKeyToAddress(pubkey []byte) (string, error) {
	return "", nil
}

func (provider *providerIml) Recover(sig []byte, hash []byte) (pubkey []byte, err error) {
	curve := provider.curve

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

	address = strings.TrimPrefix(address, "0x")

	if len(address) != 40 {
		return false
	}

	_, err := hex.DecodeString(address)

	if err != nil {
		return false
	}

	return true
}

var (
	defaultBIP39Passphrase = ""
)

func init() {
	key.RegisterProvider(newProvider("bnb", secp256k1.SECP256K1()))
	key.RegisterProvider(newProvider("tbnb", secp256k1.SECP256K1()))
}
