package bip32

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/key/internal/bip44"
)

// DrivedKey .
type DrivedKey struct {
	Param      KeyParam
	PublicKey  []byte // 33 bytes
	PrivateKey []byte // 32 bytes
	ChainCode  []byte // 32 bytes
}

// PublicKeyF .
type PublicKeyF func(privateKey []byte) []byte

// KeyParam .
type KeyParam interface {
	// PrivateToPublic(privateKey []byte) []byte
	Curve() elliptic.Curve
}

func compress(x, y *big.Int) []byte {
	two := big.NewInt(2)
	rem := two.Mod(y, two).Uint64()
	rem += 2
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(rem))
	rest := x.Bytes()
	return append(b[1:], rest...)
}

func privateToPublic(curve elliptic.Curve, key []byte) []byte {
	return compress(curve.ScalarBaseMult(key))
}

// NewMasterKey create new master key from seed
func NewMasterKey(seed []byte, param KeyParam) (*DrivedKey, error) {
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))

	_, err := hmac.Write(seed)

	if err != nil {
		return nil, xerrors.Wrapf(err, "hmac error")
	}

	intermediary := hmac.Sum(nil)

	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	return &DrivedKey{
		Param:     param,
		PublicKey: privateToPublic(param.Curve(), keyBytes),
		// PublicKey:  param.PrivateToPublic(keyBytes),
		PrivateKey: keyBytes,
		ChainCode:  chainCode,
	}, nil
}

func getPrivateKeyByte33(pk []byte) []byte {
	buff := make([]byte, 33)

	copy(buff[33-len(pk):], pk)

	return buff
}

// ChildKey get child key
func (key *DrivedKey) ChildKey(index bip44.Number) (*DrivedKey, error) {
	indexBytes := uint32Bytes(uint32(index))

	var buff bytes.Buffer

	if index.IsHardened() {
		buff.Write(getPrivateKeyByte33(key.PrivateKey))
	} else {
		buff.Write(key.PublicKey)
	}

	buff.Write(indexBytes)

	seed := buff.Bytes()

	dig := hmac.New(sha512.New, key.ChainCode)

	_, err := dig.Write(seed)

	if err != nil {
		return nil, err
	}

	intermediary := dig.Sum(nil)

	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	newkey := key.addPrivKeys(keyBytes, key.PrivateKey)

	return &DrivedKey{
		Param:     key.Param,
		PublicKey: privateToPublic(key.Param.Curve(), newkey),
		// PublicKey:  key.Param.PrivateToPublic(keyBytes),
		PrivateKey: newkey,
		ChainCode:  chainCode,
	}, nil
}

func (key *DrivedKey) addPrivKeys(k1, k2 []byte) []byte {
	i1 := big.NewInt(0).SetBytes(k1)
	i2 := big.NewInt(0).SetBytes(k2)
	i1.Add(i1, i2)
	i1.Mod(i1, key.Param.Curve().Params().N)
	k := i1.Bytes()
	zero, _ := hex.DecodeString("00")
	return append(zero, k...)
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}
