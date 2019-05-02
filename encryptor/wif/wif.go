package wif

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/dynamicgo/xerrors"

	"github.com/openzknetwork/key"
	"github.com/openzknetwork/key/internal/base58"
)

type encryptorImpl struct {
	Version byte
}

func (encryptorImpl *encryptorImpl) Encrypt(k key.Key, property key.Property, writer io.Writer) error {
	bytesOfPrivateKey := k.PriKey()

	if len(bytesOfPrivateKey) == 32 {
		bytesOfPrivateKey = append(bytesOfPrivateKey, 0x01)
	}

	withNetID, ok := k.(key.WithNetID)

	version := encryptorImpl.Version

	if ok {
		version = withNetID.NetID()
	}

	wif := base58.CheckEncode(bytesOfPrivateKey, version)

	_, err := writer.Write([]byte(wif))

	if err != nil {
		return xerrors.Wrapf(err, "write wif error")
	}

	return nil
}

func (encryptorImpl *encryptorImpl) Decrypt(k key.Key, property key.Property, reader io.Reader) error {
	data, err := ioutil.ReadAll(reader)

	bytesOfPrivateKey, version, err := base58.CheckDecode(string(data))

	if err != nil {
		return err
	}

	withNetID, ok := k.(key.WithNetID)

	if ok {

		checked := false

		for _, v := range withNetID.SupportNetID() {
			if version == v {
				checked = true
				break
			}
		}

		if !checked {
			return xerrors.New(fmt.Sprintf("invalid version %v", version))
		}
	} else {
		if version != encryptorImpl.Version {
			return xerrors.New(fmt.Sprintf("invalid version %v", version))
		}
	}

	if len(bytesOfPrivateKey) == 33 {
		if bytesOfPrivateKey[len(bytesOfPrivateKey)-1] != 0x01 {
			return xerrors.New(fmt.Sprintf("Invalid private key, unknown suffix byte 0x%02x", bytesOfPrivateKey[len(bytesOfPrivateKey)-1]))
		}
		bytesOfPrivateKey = bytesOfPrivateKey[0:32]
	}

	k.SetBytes(bytesOfPrivateKey)

	return nil
}

func init() {
	key.RegisterEncryptor("wif", &encryptorImpl{Version: 0x80})
}
