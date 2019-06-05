package ont

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/dynamicgo/xerrors"

	"github.com/openzknetwork/gochain/script/neo/script"
	"github.com/openzknetwork/key"
	"github.com/openzknetwork/key/internal/base58"
	"github.com/openzknetwork/key/internal/ecdsax"
	"github.com/openzknetwork/key/sign"
	"github.com/openzknetwork/key/sign/recoverable"
)

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
	key.key = ecdsax.BytesToPrivateKey(priKey, elliptic.P256())

	key.address, _ = pubKeyToAddress(&key.key.PublicKey)
}

func (key *keyImpl) Sign(hashed []byte) ([]byte, error) {

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

	privateKey, err := ecdsa.GenerateKey(provider.curve, rand.Reader)

	if err != nil {
		return nil, xerrors.Wrapf(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	address, err := pubKeyToAddress(&privateKey.PublicKey)

	if err != nil {
		return nil, xerrors.Wrapf(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	return &keyImpl{
		provider: provider,
		key:      privateKey,
		address:  address,
	}, nil
}

func (provider *providerIml) FromBytes(buff []byte) key.Key {
	privateKey := ecdsax.BytesToPrivateKey(buff, provider.curve)

	address, _ := pubKeyToAddress(&privateKey.PublicKey)

	return &keyImpl{
		provider: provider,
		key:      privateKey,
		address:  address,
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
	publicKey := ecdsax.BytesToPublicKey(provider.curve, pubkey)

	if nil == pubkey {
		return "", xerrors.Wrapf(key.ErrPublicKey, "decode public key error")
	}

	return pubKeyToAddress(publicKey)
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

func init() {
	key.RegisterProvider(newProvider("ont", elliptic.P256()))
}

func pubKeyToScriptHash(publicKey *ecdsa.PublicKey) ([]byte, error) {

	x := publicKey.X.Bytes()

	/* Pad X to 32-bytes */
	paddedx := append(bytes.Repeat([]byte{0x00}, 32-len(x)), x...)

	var pubbytes []byte

	/* Add prefix 0x02 or 0x03 depending on ylsb */
	if publicKey.Y.Bit(0) == 0 {
		pubbytes = append([]byte{0x02}, paddedx...)
	} else {
		pubbytes = append([]byte{0x03}, paddedx...)
	}

	addressScript := script.New("address")

	addressScript.EmitPushBytes(pubbytes)
	addressScript.Emit(script.CHECKSIG, nil)

	return addressScript.Hash()

}

// PrivateToAddress .
func pubKeyToAddress(pukey *ecdsa.PublicKey) (string, error) {

	programhash, err := pubKeyToScriptHash(pukey)

	if err != nil {
		return "", err
	}

	return base58.CheckEncode(programhash, 0x17), nil
}

// AddressToScriptHash  convert address to script hash
func AddressToScriptHash(address string) (ScriptHash, error) {
	result, _, err := base58.CheckDecode(address)

	if err != nil {
		return nil, err
	}

	return result[0:20], nil
}

// ScriptHashToAddress script hash to address
func ScriptHashToAddress(scriptHash []byte) string {
	return base58.CheckEncode(scriptHash, 0x17)
}

// ScriptHash .
type ScriptHash []byte

func (hash ScriptHash) String() string {
	return hex.EncodeToString(reverseBytes([]byte(hash)))
}

func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}
