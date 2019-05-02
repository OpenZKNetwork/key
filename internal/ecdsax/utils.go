package ecdsax

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

// PublicKeyBytes .
func PublicKeyBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}

	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// CompressedPublicKeyBytes .
func CompressedPublicKeyBytes(pub *ecdsa.PublicKey) []byte {
	b := make([]byte, 0, 33)
	format := byte(0x2)
	if isOdd(pub.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, pub.X.Bytes())
}

// BytesToPublicKey .
func BytesToPublicKey(curve elliptic.Curve, buff []byte) *ecdsa.PublicKey {

	x, y := elliptic.Unmarshal(curve, buff)

	if x == nil {
		return nil
	}

	publicKey := new(ecdsa.PublicKey)

	publicKey.X = x
	publicKey.Y = y
	publicKey.Curve = curve

	return publicKey
}

// PrivateKeyBytes 。
func PrivateKeyBytes(priv *ecdsa.PrivateKey) (b []byte) {
	d := priv.D.Bytes()

	/* Pad D to 32 bytes */
	paddedd := append(bytes.Repeat([]byte{0x00}, 32-len(d)), d...)

	return paddedd
}

// BytesToPrivateKey 。
func BytesToPrivateKey(key []byte, curve elliptic.Curve) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = new(big.Int).SetBytes(key)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(key)
	return priv
}
