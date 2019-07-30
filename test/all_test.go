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
	k, err := key.New("eos")

	require.NoError(t, err)

	println("address", k.Address())

	println(len(k.PriKey()))
}

func TestDidKey(t *testing.T) {
	k, err := key.New("eth")

	require.NoError(t, err)

	println("address", k.Address(), len(k.PriKey()))

	did, err := key.From("did", k)

	require.NoError(t, err)

	println("address", did.Address())
}

func TestBNB(t *testing.T) {
	k, err := key.New("bnb")

	require.NoError(t, err)

	println("address", k.Address(), len(k.PriKey()))

	t.Logf("pri key %+v ", hex.EncodeToString(k.PriKey()))

	key.From("bnb", k)
	println("address", k.Address(), len(k.PriKey()))

	t.Logf("pri key %+v ", hex.EncodeToString(k.PriKey()))
	
	address,err:=k.Provider().PublicKeyToAddress(k.PubKey())
	require.NoError(t, err)
	t.Logf("address %+v ", address)
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

func TestNeo(t *testing.T) {
	k, err := key.New("neo")

	require.NoError(t, err)

	println("address", k.Address())

	var buff bytes.Buffer

	err = key.Encrypt("wif", k, nil, &buff)

	require.NoError(t, err)

	println("wif", buff.String())
}

func TestOnt(t *testing.T) {

	k, err := key.New("ont")

	require.NoError(t, err)

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("L1MNCbtnfUBvSebyrhjE3QmmvUaUXLziyWEjkVGHJhCusMXYAyKB"))

	require.NoError(t, err)

	println("===", k.Address())
}

func TestEOS(t *testing.T) {
	k, err := key.New("eos")

	require.NoError(t, err)

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("5K2fuk7wX7aPZirDspantDUzx59AoN3ASuoKX2pHRMCRz8YCfuk"))

	require.NoError(t, err)

	require.Equal(t, k.Address(), "EOS6RwynWJ8ycCkd24LHi7q3tBQx3QMdBCBFJQQWFw299qgBooWSs")
}

func TestEOSSign(t *testing.T) {
	k, err := key.New("eos")

	require.NoError(t, err)

	err = key.Decrypt("wif", k, nil, bytes.NewBufferString("5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss"))

	require.NoError(t, err)

	cnt := bytes.Repeat([]byte("h"), 32)

	sig, err := k.Sign(cnt)

	require.NoError(t, err)

	require.Equal(t, hex.EncodeToString(sig), "1f2ca91aba008e7a3cfc3122233cf0ef02832643cc9fea26c0b0bd8b3c1cdb1fcd05d36c06812e94bd3c835dfabbdc7f7d8f02f82e20b3080c95e36a4a42dc8a26")

	ok, err := key.Verify("eos", nil, sig, cnt)

	require.NoError(t, err)

	require.True(t, ok)

	pubkey, err := key.Recover("eos", sig, cnt)

	require.NoError(t, err)

	require.Equal(t, pubkey, k.PubKey())
}
