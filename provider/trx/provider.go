package trx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/openzknetwork/key/internal/base58"

	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/sha3"

	"github.com/openzknetwork/key"
	"github.com/openzknetwork/key/internal/ecdsax"
	"github.com/openzknetwork/key/internal/secp256k1"
	"github.com/openzknetwork/key/sign"
	"github.com/openzknetwork/key/sign/recoverable"
)

func pubKeyToAddress(pub *ecdsa.PublicKey) string {
	pubBytes := ecdsax.PublicKeyBytes(pub)
	hasher := sha3.NewKeccak256()
	hasher.Write(pubBytes[1:])

	pubBytes = hasher.Sum(nil)[12:] //取H的最后20字节

	if len(pubBytes) > 20 {
		pubBytes = pubBytes[len(pubBytes)-20:]
	}

	var address, addressCheck []byte
	prefix, _ := hex.DecodeString("41")

	address = append(address, prefix...)
	address = append(address, pubBytes...)

	sha := sha256.New()
	sha.Write(address)
	h1 := sha.Sum(nil)
	sha2 := sha256.New()
	sha2.Write(h1)
	h2 := sha2.Sum(nil)

	addressCheck = append(addressCheck, address...)
	addressCheck = append(addressCheck, h2[0:4]...)

	return base58.Encode(addressCheck)
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

func (key *keyImpl) Sign(hashed []byte) ([]byte, error) {

	sig, err := recoverable.Sign(key.key, hashed, false)

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

	copy(buff[size-len(r):size], r)
	copy(buff[2*size-len(s):2*size], s)
	buff[2*size] = sig.V.Bytes()[0]

	return buff, nil
}

type providerIml struct {
}

func (provider *providerIml) Name() string {
	return "trx"
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

func init() {
	key.RegisterProvider(&providerIml{})
}
