package rfc6979

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openzknetwork/key/internal/secp256k1"
)

func TestSignVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	sign, err := Sign(privateKey, []byte(source))

	require.NoError(t, err)

	require.True(t, sign.Verfiy(&privateKey.PublicKey, []byte(source)))
}
