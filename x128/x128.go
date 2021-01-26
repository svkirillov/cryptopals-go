// Original: https://github.com/dnkolegov/dhpals/blob/master/x128

// Package x128 implements the insecure Montgomery curve x128 defined in the Cryptopals challenge 60.
package x128

import (
	"crypto/rand"
	"io"
	"math/big"
)

// curve parameters
var (
	// A - the a parameter.
	A = big.NewInt(534)

	// N - the order of the subgroup.
	N, _ = new(big.Int).SetString("233970423115425145498902418297807005944", 10)

	// P - the order of the underlying field.
	P, _ = new(big.Int).SetString("233970423115425145524320034830162017933", 10)

	// Q - the order of the base point.
	Q, _ = new(big.Int).SetString("29246302889428143187362802287225875743", 10)

	// U - the base point coordinate.
	U = big.NewInt(4)

	// V - the base point coordinate.
	V, _ = new(big.Int).SetString("85518893674295321206118380980485522083", 10)
)

var (
	bigZero  = big.NewInt(0)
	bigOne   = big.NewInt(1)
	bigTwo   = big.NewInt(2)
	bigThree = big.NewInt(3)
	bigFour  = big.NewInt(4)
)

func ScalarBaseMult(k []byte) *big.Int {
	return ScalarMult(U, k)
}

func ScalarMult(in *big.Int, k []byte) *big.Int {
	return ladder(in, new(big.Int).SetBytes(k))
}

func IsOnCurve(u, v *big.Int) bool {
	// B*v^2 = u^3 + A*u^2 + u
	v2 := new(big.Int).Exp(v, bigTwo, P)                       // v2 := v^2 mod P
	sum := new(big.Int).Exp(u, bigTwo, P)                      // sum := u^2 mod P
	sum.Mul(sum, A).Mod(sum, P)                                // sum = A*u^2 mod P
	sum.Add(sum, u).Mod(sum, P)                                // sum = A*u^2 + u mod P
	sum.Add(sum, new(big.Int).Exp(u, bigThree, P)).Mod(sum, P) // sum = u^3 + A*u^2 + u mod P

	return v2.Cmp(sum) == 0
}

func cswap(x, y *big.Int, b bool) (u, v *big.Int) {
	if b {
		return y, x
	}
	return x, y
}

func ladder(u, k *big.Int) *big.Int {
	// u2, w2 := (1, 0)
	// u3, w3 := (u, 1)
	u2 := new(big.Int).Set(bigOne)
	w2 := new(big.Int).Set(bigZero)
	u3 := new(big.Int).Set(u)
	w3 := new(big.Int).Set(bigOne)

	tmp1 := new(big.Int)
	tmp2 := new(big.Int)
	tmp3 := new(big.Int)
	tmp4 := new(big.Int)
	var b bool

	// for i in reverse(range(bitlen(p))):
	for i := P.BitLen() - 1; i >= 0; i-- {
		// b := 1 & (k >> i)
		b = tmp1.And(bigOne, tmp1.Rsh(k, uint(i))).Cmp(bigOne) == 0

		// u2, u3 := cswap(u2, u3, b)
		// w2, w3 := cswap(w2, w3, b)
		u2, u3 = cswap(u2, u3, b)
		w2, w3 = cswap(w2, w3, b)

		// u3, w3 := ((u2*u3 - w2*w3)^2, u * (u2*w3 - w2*u3)^2)
		tmp1.Mul(u2, u3).Mod(tmp1, P).Sub(tmp1, tmp2.Mul(w2, w3).Mod(tmp2, P)).Mod(tmp1, P) // tmp1 = (u2*u3 - w2*w3) mod P
		tmp2.Mul(u2, w3).Mod(tmp2, P).Sub(tmp2, tmp3.Mul(w2, u3).Mod(tmp3, P)).Mod(tmp2, P) // tmp2 = (u2*w3 - w2*u3) mod P
		u3.Exp(tmp1, bigTwo, P)
		w3.Exp(tmp2, bigTwo, P).Mul(w3, u).Mod(w3, P)

		// u2, w2 := ((u2^2 - w2^2)^2, 4*u2*w2 * (u2^2 + A*u2*w2 + w2^2))
		tmp1.Exp(u2, bigTwo, P)              // tmp1 = u2^2 mod P
		tmp2.Exp(w2, bigTwo, P)              // tmp2 = w2^2 mod P
		tmp3.Mul(u2, w2).Mod(tmp3, P)        // tmp3 = u2*w2 mod P
		tmp4.Mul(bigFour, tmp3).Mod(tmp4, P) // tmp4 = 4*u2*w2 mod P
		tmp3.Mul(A, tmp3).Mod(tmp3, P)       // tmp3 = A*u2*w2 mod P
		u2.Sub(tmp1, tmp2).Exp(u2, bigTwo, P)
		w2.Add(tmp1, tmp2).Mod(w2, P).Add(w2, tmp3).Mod(w2, P).Mul(w2, tmp4).Mod(w2, P)

		// u2, u3 := cswap(u2, u3, b)
		// w2, w3 := cswap(w2, w3, b)
		u2, u3 = cswap(u2, u3, b)
		w2, w3 = cswap(w2, w3, b)
	}

	res := new(big.Int).Exp(w2, tmp1.Sub(P, bigTwo), P) // res := w2^(P-2) mod P
	res.Mul(res, u2).Mod(res, P)                        // res = u2 * w2^(P-2) mod P

	// return u2 * w2^(p-2)
	return res
}

func GenerateKey(rng io.Reader) (priv []byte, pub *big.Int, err error) {
	if rng == nil {
		rng = rand.Reader
	}

	bitSize := Q.BitLen()
	byteLen := (bitSize + 7) >> 3
	priv = make([]byte, byteLen)

	for pub == nil {
		_, err = io.ReadFull(rng, priv)
		if err != nil {
			return
		}
		if new(big.Int).SetBytes(priv).Cmp(Q) >= 0 {
			continue
		}

		pub = ScalarBaseMult(priv)
	}
	return
}
