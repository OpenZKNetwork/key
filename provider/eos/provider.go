package eos

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/key"
	"github.com/openzknetwork/key/internal/base58"
	"github.com/openzknetwork/key/internal/ecdsax"
	"github.com/openzknetwork/key/internal/secp256k1"
	"github.com/openzknetwork/key/sign"
	"github.com/openzknetwork/key/sign/recoverable"
	"golang.org/x/crypto/ripemd160"
)

var errSign = key.ErrCanonicalSign
var errRecover = key.ErrRecoverSign

func pubKeyToAddress(publickey *ecdsa.PublicKey) string {
	data := ecdsax.CompressedPublicKeyBytes(publickey)

	h := ripemd160.New()
	h.Write(data)

	sum := h.Sum(nil)

	rawKey := make([]byte, 37)
	copy(rawKey, data[:33])
	copy(rawKey[33:], sum[:4])

	return "EOS" + base58.Encode(rawKey)
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
	return ecdsax.PublicKeyBytes(&key.key.PublicKey)
}

func (key *keyImpl) SetBytes(priKey []byte) {
	key.key = ecdsax.BytesToPrivateKey(priKey, secp256k1.SECP256K1())

	key.address = pubKeyToAddress(&key.key.PublicKey)
}

func isCanonical(compactSig []byte) bool {
	// From EOS's codebase, our way of doing Canonical sigs.
	// https://steemit.com/steem/@dantheman/steem-and-bitshares-cryptographic-security-update
	//
	// !(c.data[1] & 0x80)
	// && !(c.data[1] == 0 && !(c.data[2] & 0x80))
	// && !(c.data[33] & 0x80)
	// && !(c.data[33] == 0 && !(c.data[34] & 0x80));

	d := compactSig
	t1 := (d[1] & 0x80) == 0
	t2 := !(d[1] == 0 && ((d[2] & 0x80) == 0))
	t3 := (d[33] & 0x80) == 0
	t4 := !(d[33] == 0 && ((d[34] & 0x80) == 0))
	return t1 && t2 && t3 && t4
}

func (key *keyImpl) signCanonical(hashed []byte) ([]byte, error) {
	for i := 0; i < 25; i++ {

		compactSig, err := key.sign(hashed, i)

		if err != nil {
			return nil, err
		}

		if isCanonical(compactSig) {
			return compactSig, nil
		}
	}

	return nil, errSign
}

func (key *keyImpl) sign(hashed []byte, nonce int) ([]byte, error) {

	sig, err := recoverable.SignWithNonce(key.key, hashed, nonce, true)

	if err != nil {
		return nil, err
	}

	size := key.key.Curve.Params().BitSize / 8

	buff := make([]byte, 2*size+1)

	r := sig.R.Bytes()

	if len(r) > size {
		r = r[:size]
	}

	s := sig.S.Bytes()

	if len(s) > size {
		s = s[:size]
	}

	buff[0] = sig.V.Bytes()[0]
	copy(buff[1+size-len(r):size+1], r)
	copy(buff[1+2*size-len(s):2*size+1], s)

	return buff, nil
}

func (key *keyImpl) Sign(hashed []byte) ([]byte, error) {
	return key.signCanonical(hashed)
}

type providerIml struct {
}

func (provider *providerIml) Name() string {
	return "eos"
}

func (provider *providerIml) Verify(pubkey []byte, sig []byte, hash []byte) bool {

	curve := secp256k1.SECP256K1()

	size := curve.Params().BitSize / 8

	if len(sig) != 2*size+1 {
		return false
	}

	signature := &sign.Signature{
		R: new(big.Int).SetBytes(sig[1 : size+1]),
		S: new(big.Int).SetBytes(sig[1+size : 2*size+1]),
		V: new(big.Int).SetBytes(sig[:1]),
	}

	for i := 0; i < 25; i++ {
		publicKey, _, err := recoverable.RecoverWithNonce(curve, signature, hash, i)

		if err == nil {
			return signature.Verfiy(publicKey, hash)
		}

	}

	return false
}

func (provider *providerIml) New() (key.Key, error) {

	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	if err != nil {
		return nil, xerrors.Wrapf(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	return &keyImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(&privateKey.PublicKey),
	}, nil
}

func (provider *providerIml) FromBytes(buff []byte) key.Key {
	privateKey := ecdsax.BytesToPrivateKey(buff, secp256k1.SECP256K1())

	return &keyImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(&privateKey.PublicKey),
	}
}

func (provider *providerIml) PrivateToPublic(privateKey []byte) []byte {
	key := provider.FromBytes(privateKey)

	return key.PubKey()
}
func (provider *providerIml) Curve() elliptic.Curve {
	return secp256k1.SECP256K1()
}

func (provider *providerIml) PublicKeyToAddress(pubkey []byte) (string, error) {
	publicKey := ecdsax.BytesToPublicKey(secp256k1.SECP256K1(), pubkey)

	if nil == pubkey {
		return "", xerrors.Wrapf(key.ErrPublicKey, "decode public key error")
	}

	return pubKeyToAddress(publicKey), nil
}

func (provider *providerIml) Recover(sig []byte, hash []byte) (pubkey []byte, err error) {
	curve := secp256k1.SECP256K1()

	size := curve.Params().BitSize / 8

	if len(sig) != 2*size+1 {
		return nil, xerrors.Wrapf(key.ErrPublicKey, " public key length error")
	}

	signature := &sign.Signature{
		R: new(big.Int).SetBytes(sig[1 : size+1]),
		S: new(big.Int).SetBytes(sig[1+size : 1+2*size]),
		V: new(big.Int).SetBytes(sig[:1]),
	}

	for i := 0; i < 25; i++ {
		publicKey, _, err := recoverable.RecoverWithNonce(curve, signature, hash, i)

		if err == nil {
			return ecdsax.PublicKeyBytes(publicKey), nil
		}
	}

	return nil, errRecover
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

func init() {
	key.RegisterProvider(&providerIml{})
}
