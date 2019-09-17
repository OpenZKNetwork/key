package bnb

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/binance-chain/go-sdk/types"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dynamicgo/xerrors"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"

	"github.com/openzknetwork/gochain/rpc/bnb"
	"github.com/openzknetwork/key"
	"github.com/openzknetwork/key/internal/bip39"
	"github.com/openzknetwork/key/internal/ecdsax"
	"github.com/openzknetwork/key/sign"
	"github.com/openzknetwork/key/sign/recoverable"
)

// EncryptedKeyJSON .
type EncryptedKeyJSON struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}

// CryptoJSON  .
type CryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

type keyImpl struct {
	provider key.Provider
	key      crypto.PrivKey
	address  string // address
	mnemonic string //助记词
}

func (key *keyImpl) Address() string {
	return key.address
}

func (key *keyImpl) Provider() key.Provider {
	return key.provider
}

func (key *keyImpl) PriKey() []byte {
	secpPrivateKey, ok := key.key.(secp256k1.PrivKeySecp256k1)
	if !ok {
		return nil
	}
	return secpPrivateKey[:]
	// return ecdsax.PrivateKeyBytes(key.key)
}

func (key *keyImpl) PubKey() []byte {

	return key.key.PubKey().Bytes()
	// return ecdsax.PublicKeyBytes(&key.key.PublicKey)
}

func (key *keyImpl) SetBytes(privateKey []byte) {
	var keyBytesArray [32]byte
	copy(keyBytesArray[:], privateKey[:32])
	priKey := secp256k1.PrivKeySecp256k1(keyBytesArray)
	addr := bnb.AccAddress(priKey.PubKey().Address()).String()
	key.address = addr
	key.key = priKey
	key.mnemonic = ""
	// key.key = ecdsax.BytesToPrivateKey(priKey, elliptic.P256())
	// key.address, _ = pubKeyToAddress(&key.key.PublicKey)
}

func (key *keyImpl) Sign(hashed []byte) ([]byte, error) {

	return key.key.Sign(hashed)

}

func (key *keyImpl) ExportAsMnemonic() (string, error) {
	if key.mnemonic == "" {
		return "", fmt.Errorf("This key manager is not recover from mnemonic or anto generated ")
	}
	return key.mnemonic, nil
}

func (key *keyImpl) ExportAsPrivateKey() (string, error) {
	secpPrivateKey, ok := key.key.(secp256k1.PrivKeySecp256k1)
	if !ok {
		return "", fmt.Errorf(" Only PrivKeySecp256k1 key is supported ")
	}
	return hex.EncodeToString(secpPrivateKey[:]), nil
}

func (key *keyImpl) recoveryFromKMnemonic(mnemonic string) error {
	words := strings.Split(mnemonic, " ")
	if len(words) != 12 && len(words) != 24 {
		return fmt.Errorf("mnemonic length should either be 12 or 24")
	}
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, defaultBIP39Passphrase, bip39.ENUS())
	if err != nil {
		return err
	}
	// create master key and derive first key:
	masterPriv, ch := computeMastersFromSeed(seed)
	derivedPriv, err := derivePrivateKeyForPath(masterPriv, ch, bip39.FullFundraiserPath)
	if err != nil {
		return err
	}
	priKey := secp256k1.PrivKeySecp256k1(derivedPriv)
	addr := bnb.AccAddress(priKey.PubKey().Address()).String()
	if err != nil {
		return err
	}
	key.address = addr
	key.key = priKey
	key.mnemonic = mnemonic
	return nil
}
func computeMastersFromSeed(seed []byte) (secret [32]byte, chainCode [32]byte) {
	masterSecret := []byte("Bitcoin seed")
	secret, chainCode = i64(masterSecret, seed)

	return
}

func (key *keyImpl) recoveryFromPrivateKey(privateKey string) error {
	priBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return err
	}

	if len(priBytes) != 32 {
		return fmt.Errorf("Len of Keybytes is not equal to 32 ")
	}
	var keyBytesArray [32]byte
	copy(keyBytesArray[:], priBytes[:32])
	priKey := secp256k1.PrivKeySecp256k1(keyBytesArray)
	addr := bnb.AccAddress(priKey.PubKey().Address()).String()
	key.address = addr
	key.key = priKey
	return nil
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

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, err
	}
	mnemonic, err := bip39.NewMnemonic(entropy, bip39.ENUS())
	if err != nil {
		return nil, err
	}

	words := strings.Split(mnemonic, " ")
	if len(words) != 12 && len(words) != 24 {
		return nil, fmt.Errorf("mnemonic length should either be 12 or 24")
	}
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, defaultBIP39Passphrase, bip39.ENUS())
	if err != nil {
		return nil, err
	}
	// create master key and derive first key:
	masterPriv, ch := i64([]byte("Bitcoin seed"), seed)

	derivedPriv, err := derivePrivateKeyForPath(masterPriv, ch, bip39.FullFundraiserPath)
	if err != nil {
		return nil, err
	}

	priv := secp256k1.PrivKeySecp256k1(derivedPriv)
	address := bnb.AccAddress(priv.PubKey().Address()).String()
	return &keyImpl{
		provider: provider,
		key:      priv,
		address:  address,
	}, nil
}

func (provider *providerIml) FromBytes(buff []byte) key.Key {

	var keyBytesArray [32]byte
	copy(keyBytesArray[:], buff[:32])
	priv := secp256k1.PrivKeySecp256k1(keyBytesArray)
	address := bnb.AccAddress(priv.PubKey().Address()).String()
	return &keyImpl{
		provider: provider,
		key:      priv,
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
	key := new(secp256k1.PubKeySecp256k1)
	codec := types.NewCodec()
	codec.MustUnmarshalBinaryBare(pubkey, key)

	return bnb.AccAddress(key.Address()).String(), nil
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
	key.RegisterProvider(newProvider("bnb", elliptic.P256()))
}

// i64 returns the two halfs of the SHA512 HMAC of key and data.
func i64(key []byte, data []byte) (IL [32]byte, IR [32]byte) {
	mac := hmac.New(sha512.New, key)
	// sha512 does not err
	_, _ = mac.Write(data)
	I := mac.Sum(nil)
	copy(IL[:], I[:32])
	copy(IR[:], I[32:])
	return
}

// DerivePrivateKeyForPath derives the private key by following the BIP 32/44 path from privKeyBytes,
// using the given chainCode.
func derivePrivateKeyForPath(privKeyBytes [32]byte, chainCode [32]byte, path string) ([32]byte, error) {
	data := privKeyBytes
	parts := strings.Split(path, "/")
	for _, part := range parts {
		// do we have an apostrophe?
		harden := part[len(part)-1:] == "'"
		// harden == private derivation, else public derivation:
		if harden {
			part = part[:len(part)-1]
		}
		idx, err := strconv.Atoi(part)
		if err != nil {
			return [32]byte{}, fmt.Errorf("invalid BIP 32 path: %s", err)
		}
		if idx < 0 {
			return [32]byte{}, errors.New("invalid BIP 32 path: index negative ot too large")
		}
		data, chainCode = derivePrivateKey(data, chainCode, uint32(idx), harden)
	}
	var derivedKey [32]byte
	n := copy(derivedKey[:], data[:])
	if n != 32 || len(data) != 32 {
		return [32]byte{}, fmt.Errorf("expected a (secp256k1) key of length 32, got length: %v", len(data))
	}

	return derivedKey, nil
}

// derivePrivateKey derives the private key with index and chainCode.
// If harden is true, the derivation is 'hardened'.
// It returns the new private key and new chain code.
// For more information on hardened keys see:
//  - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func derivePrivateKey(privKeyBytes [32]byte, chainCode [32]byte, index uint32, harden bool) ([32]byte, [32]byte) {
	var data []byte
	if harden {
		index = index | 0x80000000
		data = append([]byte{byte(0)}, privKeyBytes[:]...)
	} else {
		// this can't return an error:
		_, ecPub := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes[:])
		pubkeyBytes := ecPub.SerializeCompressed()
		data = pubkeyBytes

		/* By using btcec, we can remove the dependency on tendermint/crypto/secp256k1
		pubkey := secp256k1.PrivKeySecp256k1(privKeyBytes).PubKey()
		public := pubkey.(secp256k1.PubKeySecp256k1)
		data = public[:]
		*/
	}
	data = append(data, uint32ToBytes(index)...)
	data2, chainCode2 := i64(chainCode[:], data)
	x := addScalars(privKeyBytes[:], data2[:])
	return x, chainCode2
}

func uint32ToBytes(i uint32) []byte {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], i)
	return b[:]
}

// modular big endian addition
func addScalars(a []byte, b []byte) [32]byte {
	aInt := new(big.Int).SetBytes(a)
	bInt := new(big.Int).SetBytes(b)
	sInt := new(big.Int).Add(aInt, bInt)
	x := sInt.Mod(sInt, btcec.S256().N).Bytes()
	x2 := [32]byte{}
	copy(x2[32-len(x):], x)
	return x2
}

// NewMnemonicKeyManager .
func NewMnemonicKeyManager(mnemonic string) (key.Key, error) {
	k := keyImpl{}
	err := k.recoveryFromKMnemonic(mnemonic)
	return &k, err
}

// NewPrivateKeyManager .
func NewPrivateKeyManager(priKey string) (key.Key, error) {
	k := keyImpl{}
	err := k.recoveryFromPrivateKey(priKey)
	return &k, err
}
