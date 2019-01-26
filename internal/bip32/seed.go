package bip32

import (
	"crypto/sha512"

	"github.com/dynamicgo/xerrors"

	"github.com/openzknetwork/key/internal/bip44"

	"golang.org/x/crypto/pbkdf2"
)

const pbkdfRounds = 2048

func mnemonicToSeed(mnemonic string, password string) []byte {
	salt := "mnemonic" + password

	return pbkdf2.Key([]byte(mnemonic), []byte(salt), pbkdfRounds, 64, sha512.New)
}

// FromMnemonic .
func FromMnemonic(param KeyParam, mnemonic string, password string) (*DrivedKey, error) {
	seed := mnemonicToSeed(mnemonic, password)

	return NewMasterKey(seed, param)
}

// DriveFrom driver key from path
func DriveFrom(key *DrivedKey, path string) ([]byte, error) {
	dpath, err := bip44.Parse(path)

	if err != nil {
		return nil, err
	}

	key, err = key.ChildKey(dpath.Purpose)

	if err != nil {
		return nil, xerrors.Wrapf(err, "create purpose child key error")
	}

	key, err = key.ChildKey(dpath.Coin)

	if err != nil {
		return nil, xerrors.Wrapf(err, "create purpose child key error")
	}

	key, err = key.ChildKey(dpath.Account)

	if err != nil {
		return nil, xerrors.Wrapf(err, "create account child key error")
	}

	key, err = key.ChildKey(dpath.Change)

	if err != nil {
		return nil, xerrors.Wrapf(err, "create change child key error")
	}

	key, err = key.ChildKey(dpath.Address)

	if err != nil {
		return nil, xerrors.Wrapf(err, "create address child key error")
	}

	return key.PrivateKey, nil
}
