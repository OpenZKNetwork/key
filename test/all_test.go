package test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/openzknetwork/key/internal/bip39"

	"github.com/openzknetwork/key/internal/base58"

	"github.com/stretchr/testify/require"

	"github.com/openzknetwork/key"
	_ "github.com/openzknetwork/key/encryptor"
	_ "github.com/openzknetwork/key/provider"
)


func TestDid(t *testing.T) {
	k, err := key.New("did")

	require.NoError(t, err)

	println("address", k.Address())

	println(len(k.PriKey()))
}

func TestEthKey(t *testing.T) {
	k, err := key.New("eth")

	require.NoError(t, err)

	println("address", k.Address())

	println(len(k.PriKey()))
}

func TestHex(t *testing.T) {
	//address to hex
	b := base58.Decode("T9yai3UbXbDaGpVdsDHZyZC3wjqSLk4aor")
	println(strings.ToUpper(hex.EncodeToString(b[:len(b)-4])))

	//hex to address
	// 41C5CDDDB85D7E57C399A9A9D03E93F2B8CDF66943
	// 4189139CB1387AF85E3D24E212A008AC974967E561
	var addressCheck []byte
	address, _ := hex.DecodeString("41C5CDDDB85D7E57C399A9A9D03E93F2B8CDF66943")
	println(base58.Encode(address))

	sha := sha256.New()
	sha.Write(address)
	h1 := sha.Sum(nil)
	sha2 := sha256.New()
	sha2.Write(h1)
	h2 := sha2.Sum(nil)

	addressCheck = append(addressCheck, address...)
	addressCheck = append(addressCheck, h2[0:4]...)
	s := base58.Encode(addressCheck)
	println(s)
	// s := base58.Encode([]byte("4189139CB1387AF85E3D24E212A008AC974967E561"))
	// println(string(s))
}
func TestTrxKey(t *testing.T) {
	k, err := key.New("trx")

	require.NoError(t, err)

	println("address", k.Address())
	println(hex.EncodeToString(k.PriKey()))

	k.SetBytes(k.PriKey())
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

func TestBNB(t *testing.T) {
	k, err := key.New("bnb")

	require.NoError(t, err)

	println("address", k.Address(), len(k.PriKey()))

	t.Logf("pri key %+v ", hex.EncodeToString(k.PriKey()))

	key.From("bnb", k)
	println("address", k.Address(), len(k.PriKey()))

	t.Logf("pri key %+v ", hex.EncodeToString(k.PriKey()))

	address, err := k.Provider().PublicKeyToAddress(k.PubKey())
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

func TestLen(t *testing.T) {
	s := "17aUoDBkpSZxrPGRQNn7CsJaWy3X3vwhwb"
	println(len(s))

	s2 := "d662002f040affd6260652c861e9e10737fff0c240a1973e0f4056e6cc44aecc"
	println(len(s2))
}
func TestBip39(t *testing.T) {
	k, err := key.New("did")

	require.NoError(t, err)

	println(k.Address())

	mnemonic, err := bip39.NewMnemonic(k.PriKey(), bip39.ENUS())

	require.NoError(t, err)

	k, err = key.FromMnemonic("did", mnemonic, "")

	require.NoError(t, err)

	println(k.Address())

	println(mnemonic)

}

func TestMnemonicDrived(t *testing.T) {
	mnemonic, k, err := key.NewMnemonic("did", "m/44'/201910'/0'/0/0")

	require.NoError(t, err)

	println(mnemonic, "\n", k.Address())

	var buff bytes.Buffer

	err = key.MnemonicToKeystore(mnemonic, "test", &buff)

	require.NoError(t, err)

	println(buff.String())

	mnemonic, err = key.MnemonicFromKeystore(&buff, "test")

	require.NoError(t, err)

	println(mnemonic)

	k, err = key.FromMnemonic("eth", mnemonic, "m/44'/60'/0'/0/0")

	require.NoError(t, err)

	println(k.Address())
}

func TestParseMnemonic(t *testing.T){
	mnemonic:="keep sentence oxygen virtual flush aspect witness tent latin report auction thumb"
	k, err := key.FromMnemonic("eth", mnemonic, "m/44'/60'/0'/0/0")

	require.NoError(t, err)

	println(k.Address())

	k, err = key.FromMnemonic("did", mnemonic, "m/44'/201910'/0'/0/0")

	require.NoError(t, err)

	println(k.Address())
}
