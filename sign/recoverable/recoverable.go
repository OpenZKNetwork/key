package recoverable

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/key/sign"
	"github.com/openzknetwork/key/sign/rfc6979"
)

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func decompressPoint(curve elliptic.Curve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)
	x3.Mod(x3, curve.Params().P)

	q := new(big.Int).Div(new(big.Int).Add(curve.Params().P,
		big.NewInt(1)), big.NewInt(4))

	// Now calculate sqrt mod p of x^3 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, q, curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}

	// Check that y is a square root of x^3 + B.
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.Params().P)
	if y2.Cmp(x3) != 0 {
		return nil, fmt.Errorf("invalid square root")
	}

	// Verify that y-coord has expected parity.
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}

	return y, nil
}

// ErrCurve .
var (
	ErrCurve  = errors.New("unsupport curve")
	ErrPubKey = errors.New("no valid solution for pubkey found")
)

// Cofactor elliptic.CurveParams extend interface
type Cofactor interface {
	H() int
}

// Sign .
func Sign(privateKey *ecdsa.PrivateKey, hash []byte, compressed bool) (*sign.Signature, error) {

	cofactor, ok := privateKey.Curve.(Cofactor)

	if !ok {
		return nil, xerrors.Wrapf(ErrCurve, "curve %s not support cofactor params", privateKey.Curve.Params().Name)
	}

	sig, err := rfc6979.Sign(privateKey, hash)

	if err != nil {
		return nil, err
	}

	curve := privateKey.Curve

	// bitcoind checks the bit length of R and S here. The ecdsa signature
	// algorithm returns R and S mod N therefore they will be the bitsize of
	// the curve, and thus correctly sized.
	for i := 0; i < (cofactor.H()+1)*2; i++ {
		pk, err := recoverKeyFromSignature(curve, sig, hash, i, true)
		if err == nil && pk.X.Cmp(privateKey.X) == 0 && pk.Y.Cmp(privateKey.Y) == 0 {

			v := 27 + byte(i)
			if compressed {
				v += 4
			}

			sig.V = new(big.Int).SetBytes([]byte{v})

			return sig, nil
		}
	}

	return nil, xerrors.Wrapf(err, "can't find v for public key")
}

// Recover recover public key from sig and hash
func Recover(curve elliptic.Curve, sig *sign.Signature, hash []byte) (*ecdsa.PublicKey, bool, error) {

	v := sig.V.Bytes()

	iteration := int((v[0] - 27) & ^byte(4))

	// The iteration used here was encoded
	key, err := recoverKeyFromSignature(curve, sig, hash, iteration, false)
	if err != nil {
		return nil, false, err
	}

	return key, ((v[0] - 27) & 4) == 4, nil
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
// This is borrowed from crypto/ecdsa.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// recoverKeyFromSignature recovers a public key from the signature "sig" on the
// given message hash "msg". Based on the algorithm found in section 5.1.5 of
// SEC 1 Ver 2.0, page 47-48 (53 and 54 in the pdf). This performs the details
// in the inner loop in Step 1. The counter provided is actually the j parameter
// of the loop * 2 - on the first iteration of j we do the R case, else the -R
// case in step 1.6. This counter is used in the bitcoin compressed signature
// format and thus we match bitcoind's behaviour here.
func recoverKeyFromSignature(curve elliptic.Curve, sig *sign.Signature, msg []byte,
	iter int, doChecks bool) (*ecdsa.PublicKey, error) {
	// 1.1 x = (n * i) + r
	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// convert 02<Rx> to point R. (step 1.2 and 1.3). If we are on an odd
	// iteration then 1.6 will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := decompressPoint(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	// 1.4 Check n*R is point at infinity
	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	// 1.5 calculate e from message using the same algorithm as ecdsa
	// signature calculation.
	e := hashToInt(msg, curve)

	// Step 1.6.1:
	// We calculate the two terms sR and eG separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sR-eG)
	invr := new(big.Int).ModInverse(sig.R, curve.Params().N)

	// first term.
	invrS := new(big.Int).Mul(invr, sig.S)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	// second term.
	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	// TODO: this would be faster if we did a mult and add in one
	// step to prevent the jacobian conversion back and forth.
	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}
