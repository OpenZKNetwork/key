package sign

import (
	"crypto/ecdsa"
	"math/big"
)

// Signature .
type Signature struct {
	R *big.Int
	S *big.Int
	V *big.Int
}

// Verfiy .
func (sign *Signature) Verfiy(publicKey *ecdsa.PublicKey, hash []byte) bool {
	return ecdsa.Verify(publicKey, hash, sign.R, sign.S)
}
