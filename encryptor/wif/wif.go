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

func (encryptorImpl *encryptorImpl) Encrypt(key key.Key, property key.Property, writer io.Writer) error {
	bytesOfPrivateKey := key.PriKey()

	if len(bytesOfPrivateKey) == 32 {
		bytesOfPrivateKey = append(bytesOfPrivateKey, 0x01)
	}

	wif := base58.CheckEncode(bytesOfPrivateKey, encryptorImpl.Version)

	_, err := writer.Write([]byte(wif))

	if err != nil {
		return xerrors.Wrapf(err, "write wif error")
	}

	return nil
}

func (encryptorImpl *encryptorImpl) Decrypt(key key.Key, property key.Property, reader io.Reader) error {
	data, err := ioutil.ReadAll(reader)

	bytesOfPrivateKey, version, err := base58.CheckDecode(string(data))

	if err != nil {
		return err
	}

	/* Check that the version byte is 0x80 */
	if version != encryptorImpl.Version {
		return xerrors.New(fmt.Sprintf("invalid version %v", version))
	}

	/* If the private key bytes length is 33, check that suffix byte is 0x01 (for compression) and strip it off */
	if len(bytesOfPrivateKey) == 33 {
		if bytesOfPrivateKey[len(bytesOfPrivateKey)-1] != 0x01 {
			return xerrors.New(fmt.Sprintf("Invalid private key, unknown suffix byte 0x%02x", bytesOfPrivateKey[len(bytesOfPrivateKey)-1]))
		}
		bytesOfPrivateKey = bytesOfPrivateKey[0:32]
	}

	key.SetBytes(bytesOfPrivateKey)

	return nil
}

func init() {
	key.RegisterEncryptor("wif.neo", &encryptorImpl{Version: 0x80})
}
