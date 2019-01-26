package test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openzknetwork/key"
	_ "github.com/openzknetwork/key/encryptor"
	_ "github.com/openzknetwork/key/provider"
)

func TestEthKey(t *testing.T) {
	k, err := key.New("eth")

	require.NoError(t, err)

	println("address", k.Address())
}

func TestDidKey(t *testing.T) {
	k, err := key.New("eth")

	require.NoError(t, err)

	println("address", k.Address(), len(k.PriKey()))

	did, err := key.From("did", k)

	require.NoError(t, err)

	println("address", did.Address())

}

func TestSign(t *testing.T) {

	data := []byte("hello world")

	did, err := key.New("did")

	require.NoError(t, err)

	sig, err := did.Sign(data)

	require.NoError(t, err)

	pubkey, err := key.Recover("did", sig, data)

	require.NoError(t, err)

	require.Equal(t, pubkey, did.PubKey())

	address, err := key.PublicKeyToAddress("did", pubkey)

	require.NoError(t, err)

	require.Equal(t, address, did.Address())

	ok, err := key.Verify("did", nil, sig, data)

	require.NoError(t, err)

	require.True(t, ok)
}

func TestWeb3Encryptor(t *testing.T) {
	k, err := key.New("eth")

	require.NoError(t, err)

	var buff bytes.Buffer

	err = key.Encrypt("web3.standard", k, map[string]string{
		"password": "test",
	}, &buff)

	require.NoError(t, err)

	println(buff.String())

	k2, err := key.New("eth")

	require.NoError(t, err)

	err = key.Decrypt("web3.standard", k2, map[string]string{
		"password": "test",
	}, &buff)

	require.NoError(t, err)

	require.Equal(t, k.Address(), k2.Address())
	require.Equal(t, k.PriKey(), k2.PriKey())

}

func TestMnemonic(t *testing.T) {
	mnemonic, k, err := key.NewMnemonic("eth", "m/44'/60'/0'/0/0")

	require.NoError(t, err)

	println(mnemonic)

	println(k.Address())
}

func TestFromMnemonic(t *testing.T) {
	k, err := key.FromMnemonic("eth", "canal walnut regular license dust liberty story expect repeat design picture medal", "m/44'/60'/0'/0/0")

	require.NoError(t, err)

	println(k.Address())

	println(hex.EncodeToString(k.PriKey()))
}
