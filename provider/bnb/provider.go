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

// // i64 returns the two halfs of the SHA512 HMAC of key and data.
// func i64(key []byte, data []byte) (IL [32]byte, IR [32]byte) {
// 	mac := hmac.New(sha512.New, key)
// 	// sha512 does not err
// 	_, _ = mac.Write(data)
// 	I := mac.Sum(nil)
// 	copy(IL[:], I[:32])
// 	copy(IR[:], I[32:])
// 	return
// }

// // DerivePrivateKeyForPath derives the private key by following the BIP 32/44 path from privKeyBytes,
// // using the given chainCode.
// func derivePrivateKeyForPath(privKeyBytes [32]byte, chainCode [32]byte, path string) ([32]byte, error) {
// 	// println(path)
// 	// path = "m/"+path
// 	data := privKeyBytes
// 	parts := strings.Split(path, "/")
// 	for _, part := range parts {
// 		// do we have an apostrophe?
// 		harden := part[len(part)-1:] == "'"
// 		// harden == private derivation, else public derivation:
// 		if harden {
// 			part = part[:len(part)-1]
// 		}
// 		idx, err := strconv.Atoi(part)
// 		if err != nil {
// 			return [32]byte{}, fmt.Errorf("invalid BIP 32 path: %s", err)
// 		}
// 		if idx < 0 {
// 			return [32]byte{}, errors.New("invalid BIP 32 path: index negative ot too large")
// 		}
// 		data, chainCode = derivePrivateKey(data, chainCode, uint32(idx), harden)
// 	}
// 	var derivedKey [32]byte
// 	n := copy(derivedKey[:], data[:])
// 	if n != 32 || len(data) != 32 {
// 		return [32]byte{}, fmt.Errorf("expected a (secp256k1) key of length 32, got length: %v", len(data))
// 	}

// 	return derivedKey, nil
// }

// // derivePrivateKey derives the private key with index and chainCode.
// // If harden is true, the derivation is 'hardened'.
// // It returns the new private key and new chain code.
// // For more information on hardened keys see:
// //  - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// func derivePrivateKey(privKeyBytes [32]byte, chainCode [32]byte, index uint32, harden bool) ([32]byte, [32]byte) {
// 	var data []byte
// 	if harden {
// 		index = index | 0x80000000
// 		data = append([]byte{byte(0)}, privKeyBytes[:]...)
// 	} else {
// 		// this can't return an error:
// 		_, ecPub := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes[:])
// 		pubkeyBytes := ecPub.SerializeCompressed()
// 		data = pubkeyBytes

// 		/* By using btcec, we can remove the dependency on tendermint/crypto/secp256k1
// 		pubkey := secp256k1.PrivKeySecp256k1(privKeyBytes).PubKey()
// 		public := pubkey.(secp256k1.PubKeySecp256k1)
// 		data = public[:]
// 		*/
// 	}
// 	data = append(data, uint32ToBytes(index)...)
// 	data2, chainCode2 := i64(chainCode[:], data)
// 	x := addScalars(privKeyBytes[:], data2[:])
// 	return x, chainCode2
// }

// func uint32ToBytes(i uint32) []byte {
// 	b := [4]byte{}
// 	binary.BigEndian.PutUint32(b[:], i)
// 	return b[:]
// }

// // modular big endian addition
// func addScalars(a []byte, b []byte) [32]byte {
// 	aInt := new(big.Int).SetBytes(a)
// 	bInt := new(big.Int).SetBytes(b)
// 	sInt := new(big.Int).Add(aInt, bInt)
// 	x := sInt.Mod(sInt, btcec.S256().N).Bytes()
// 	x2 := [32]byte{}
// 	copy(x2[32-len(x):], x)
// 	return x2
// }

// // NewMnemonicKeyManager .
// func NewMnemonicKeyManager(mnemonic string) (key.Key, error) {
// 	k := keyImpl{}
// 	err := k.recoveryFromKMnemonic(mnemonic)
// 	return &k, err
// }

// // NewPrivateKeyManager .
// func NewPrivateKeyManager(priKey string) (key.Key, error) {
// 	k := keyImpl{}
// 	err := k.recoveryFromPrivateKey(priKey)
// 	return &k, err

// }
