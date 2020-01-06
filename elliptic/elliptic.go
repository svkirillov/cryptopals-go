// Original from https://github.com/dnkolegov/dhpals/blob/master/elliptic/elliptic.go

// Package elliptic implements elliptic curve primitives.
package elliptic

import (
	"crypto/rand"
	"io"
	"math/big"
	"sync"
)

// A Curve represents a short-form Weierstrass curve y^2 = x^3 + a*x + b.
type Curve interface {
	// Params returns the parameters for the curve.
	Params() *CurveParams
	// IsOnCurve reports whether the given (x,y) lies on the curve.
	IsOnCurve(x, y *big.Int) bool
	// Add returns the sum of (x1,y1) and (x2,y2)
	Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int)
	// Double returns 2*(x,y)
	Double(x1, y1 *big.Int) (x, y *big.Int)
	// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
	ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int)
	// ScalarBaseMult returns k*(Gx, Gy) where (Gx, Gy) is the base point of the group
	// and k is a number in big-endian form.
	ScalarBaseMult(k []byte) (x, y *big.Int)
}

// CurveParams contains the parameters of an elliptic curve and also provides
// a generic, non-constant time implementation of the Curve.
type CurveParams struct {
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // b parameter
	A       *big.Int // a parameter
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
}

func (curve *CurveParams) Params() *CurveParams {
	return curve
}

func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {
	// y^2 = x^3 + a*x + b
	panic("not implemented")
	return false
}

// Add takes two points (x1, y1) and (x2, y2) and returns their sum.
// It is assumed that "point at infinity" is (0, 0).
func (curve *CurveParams) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	panic("not implemented")
	return nil, nil
}

func (curve *CurveParams) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return curve.Add(x1, y1, x1, y1)
}

func (curve *CurveParams) ScalarMult(xIn, yIn *big.Int, k []byte) (x, y *big.Int) {
	panic("not implemented")
	return nil, nil
}

func (curve *CurveParams) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func GenerateKey(curve Curve, rng io.Reader) (priv []byte, x, y *big.Int, err error) {
	if rng == nil {
		rng = rand.Reader
	}

	N := curve.Params().N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) >> 3
	priv = make([]byte, byteLen)

	for x == nil {
		_, err = io.ReadFull(rng, priv)
		if err != nil {
			return
		}
		if new(big.Int).SetBytes(priv).Cmp(N) >= 0 {
			continue
		}

		x, y = curve.ScalarBaseMult(priv)
	}
	return
}

func Inverse(curve Curve, x, y *big.Int) (ix *big.Int, iy *big.Int) {
	ix = new(big.Int).Set(x)
	iy = new(big.Int).Sub(curve.Params().P, y)
	iy.Mod(iy, curve.Params().P)
	return
}

func GeneratePoint(curve Curve) (*big.Int, *big.Int) {
	for {
		x, err := rand.Int(rand.Reader, curve.Params().P)

		if err != nil {
			panic(err)
		}

		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)

		ax := new(big.Int).Mul(curve.Params().A, x)
		x3.Add(x3, ax)
		x3.Add(x3, curve.Params().B)
		x3.Mod(x3, curve.Params().P)

		y := new(big.Int).ModSqrt(x3, curve.Params().P)
		if y != nil {
			return x, y
		}
	}
}

// Marshal converts a point into the uncompressed form specified in section 4.3.6 of ANSI X9.62.
func Marshal(curve Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	yBytes := y.Bytes()
	copy(ret[1+2*byteLen-len(yBytes):], yBytes)
	return ret
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair.
// It is an error if the point is not in uncompressed form or is not on the curve.
// On error, x = nil.
func Unmarshal(curve Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		return
	}
	if data[0] != 4 { // uncompressed form
		return
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

var p128, p128v1, p128v2, p128v3 *CurveParams
var p4 *CurveParams
var p256 *CurveParams
var p224 *CurveParams
var p48 *CurveParams

func initAll() {
	initP128()
	initP4()
	initP256()
	initP224()
	initP128V1()
	initP128V2()
	initP128V3()
	initP48()
}

var initonce sync.Once

func initP256() {
	p256 = &CurveParams{Name: "P-256"}
	p256.P, _ = new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	p256.N, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
	p256.B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	p256.A, _ = new(big.Int).SetString("-3", 10)
	p256.Gx, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
	p256.Gy, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
	p256.BitSize = 127
}

func initP224() {
	// See FIPS 186-3, section D.2.2
	p224 = &CurveParams{Name: "P-224"}
	p224.P, _ = new(big.Int).SetString("26959946667150639794667015087019630673557916260026308143510066298881", 10)
	p224.N, _ = new(big.Int).SetString("26959946667150639794667015087019625940457807714424391721682722368061", 10)
	p224.B, _ = new(big.Int).SetString("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16)
	p224.A, _ = new(big.Int).SetString("-3", 10)
	p224.Gx, _ = new(big.Int).SetString("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16)
	p224.Gy, _ = new(big.Int).SetString("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16)
	p224.BitSize = 224
}

func initP4() {
	p4 = &CurveParams{Name: "P-4"}
	p4.P, _ = new(big.Int).SetString("11", 10)
	p4.B, _ = new(big.Int).SetString("1", 10)
	p4.A, _ = new(big.Int).SetString("-3", 10)
	p4.BitSize = 4
}

func initP128() {
	p128 = &CurveParams{Name: "P-128"}
	p128.P, _ = new(big.Int).SetString("233970423115425145524320034830162017933", 10)
	p128.N, _ = new(big.Int).SetString("29246302889428143187362802287225875743", 10)
	p128.B, _ = new(big.Int).SetString("11279326", 10)
	p128.A, _ = new(big.Int).SetString("-95051", 10)
	p128.Gx, _ = new(big.Int).SetString("182", 10)
	p128.Gy, _ = new(big.Int).SetString("85518893674295321206118380980485522083", 10)
	p128.BitSize = 128
}

func initP128V1() {
	p128v1 = &CurveParams{Name: "P-128-V1"}
	p128v1.P, _ = new(big.Int).SetString("233970423115425145524320034830162017933", 10)
	p128v1.N, _ = new(big.Int).SetString("233970423115425145550826547352470124412", 10)
	p128v1.B, _ = new(big.Int).SetString("210", 10)
	p128v1.A, _ = new(big.Int).SetString("-95051", 10)
	p128v1.Gx, _ = new(big.Int).SetString("182", 10)
	p128v1.Gy, _ = new(big.Int).SetString("85518893674295321206118380980485522083", 10)
	p128v1.BitSize = 128
}

func initP128V2() {
	p128v2 = &CurveParams{Name: "P-128-V2"}
	p128v2.P, _ = new(big.Int).SetString("233970423115425145524320034830162017933", 10)
	p128v2.N, _ = new(big.Int).SetString("233970423115425145544350131142039591210", 10)
	p128v2.B, _ = new(big.Int).SetString("504", 10)
	p128v2.A, _ = new(big.Int).SetString("-95051", 10)
	p128v2.Gx, _ = new(big.Int).SetString("182", 10)
	p128v2.Gy, _ = new(big.Int).SetString("85518893674295321206118380980485522083", 10)
	p128v2.BitSize = 128
}

func initP128V3() {
	p128v3 = &CurveParams{Name: "P-128-V3"}
	p128v3.P, _ = new(big.Int).SetString("233970423115425145524320034830162017933", 10)
	p128v3.N, _ = new(big.Int).SetString("233970423115425145545378039958152057148", 10)
	p128v3.B, _ = new(big.Int).SetString("727", 10)
	p128v3.A, _ = new(big.Int).SetString("-95051", 10)
	p128v3.Gx, _ = new(big.Int).SetString("182", 10)
	p128v3.Gy, _ = new(big.Int).SetString("85518893674295321206118380980485522083", 10)
	p128v3.BitSize = 128
}

func initP48() {
	p48 = &CurveParams{Name: "P-48"}
	p48.P, _ = new(big.Int).SetString("146150163733117", 10)
	p48.N, _ = new(big.Int).SetString("146150168402890", 10)
	p48.B, _ = new(big.Int).SetString("1242422", 10)
	p48.A, _ = new(big.Int).SetString("544333", 10)
	p48.Gx, _ = new(big.Int).SetString("27249639878388", 10)
	p48.Gy, _ = new(big.Int).SetString("14987583413657", 10)
	p48.BitSize = 48
}

// P128 returns a Curve which implements Cryptopals P-128 defined in the challenge 59:
// y^2 = x^3 - 95051*x + 11279326.
func P128() Curve {
	initonce.Do(initAll)
	return p128
}

// P128V1 returns a malicious curve from Cryptopals challenge 59:
// y^2 = x^3 - 95051*x + 210
func P128V1() Curve {
	initonce.Do(initAll)
	return p128v1
}

// P128V2 returns a malicious curve from Cryptopals challenge 59:
// y^2 = x^3 - 95051*x + 504
func P128V2() Curve {
	initonce.Do(initAll)
	return p128v2
}

// P128V3 returns a malicious curve from Cryptopals challenge 59:
// y^2 = x^3 - 95051*x + 727
func P128V3() Curve {
	initonce.Do(initAll)
	return p128v3
}

// P4 returns a Curve which implement y^2 = x^3 -3x + 1 curve for testing purposes.
func P4() Curve {
	initonce.Do(initAll)
	return p4
}

// P256 returns the P-256 curve.
func P256() Curve {
	initonce.Do(initAll)
	return p256
}

// P224 returns the P-224 curve.
func P224() Curve {
	initonce.Do(initAll)
	return p224
}

// P48 returns the P-48 curve, see
// http://mslc.ctf.su/wp/hack-lu-ctf-2011-wipe-out-the-klingons-400/.
func P48() Curve {
	initonce.Do(initAll)
	return p48
}
