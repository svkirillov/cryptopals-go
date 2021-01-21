package challenge60

import (
	"math"
	"math/big"

	"github.com/svkirillov/cryptopals-go/elliptic"
	"github.com/svkirillov/cryptopals-go/helpers"
)

// f maps group elements to scalars.
// See tasks/challenge58.txt:24 and tasks/challenge58.txt:94 for details.
func f(y, k, p *big.Int) *big.Int {
	// f = 2^(y mod k) mod p
	return new(big.Int).Exp(helpers.BigTwo, new(big.Int).Mod(y, k), p)
}

// calcK calculates k based on a formula in this paper: https://arxiv.org/pdf/0812.0789.pdf
func calcK(a, b *big.Int) *big.Int {
	// k = log2(sqrt(b-a)) + log2(log2(sqrt(b-a))) - 2
	sqrtba := math.Sqrt(float64(new(big.Int).Sub(b, a).Uint64()))
	logSqrt := math.Log2(sqrtba)
	logLogSqrt := math.Log2(logSqrt)
	return new(big.Int).SetUint64(uint64(logSqrt + logLogSqrt - 2))
}

// calcN calculates amount of leaps for tame kangaroo.
func calcN(p, k *big.Int) *big.Int {
	N := new(big.Int).Set(helpers.BigZero)

	for i := new(big.Int).Set(helpers.BigZero); i.Cmp(k) < 0; i.Add(i, helpers.BigOne) {
		N.Add(N, f(i, k, p))
	}

	N.Div(N, k)

	// see for details: tasks/challenge58.txt:99
	return N.Mul(big.NewInt(4), N)
}

// tameKangaroo returns distance traveled by tame kangaroo and where he
// ended up.
func tameKangaroo(curve elliptic.Curve, bx, by, b, k *big.Int) (xT *big.Int, xyT *big.Int, yyT *big.Int) {
	curveN := curve.Params().N

	N := calcN(curveN, k)

	// xT := 0
	// xyT, yyT := b * base
	xT = new(big.Int).Set(helpers.BigZero)
	xyT, yyT = curve.ScalarMult(bx, by, b.Bytes())

	// for i in 1..N:
	for i := new(big.Int).Set(helpers.BigZero); i.Cmp(N) < 0; i.Add(i, helpers.BigOne) {
		// xT := xT + f(xyT)
		xT.Add(xT, f(xyT, k, curveN))

		// xyT, yyT := (xyT, yyT) + (base * f(yyT))
		tmpX, tmpY := curve.ScalarMult(bx, by, f(xyT, k, curveN).Bytes())
		xyT, yyT = curve.Add(xyT, yyT, tmpX, tmpY)
	}

	return
}

// CatchingWildKangaroo implements Pollard's method for catching kangaroos.
func CatchingWildKangaroo(curve elliptic.Curve, bx, by, x, y, a, b *big.Int) *big.Int {
	curveN := curve.Params().N

	k := calcK(a, b)
	xT, xyT, yyT := tameKangaroo(curve, bx, by, b, k)

	// xW := 0
	// xyW, yyW := x, y
	xW := new(big.Int).Set(helpers.BigZero)
	xyW := new(big.Int).Set(x)
	yyW := new(big.Int).Set(y)

	tmp := new(big.Int)

	// while xW < b - a + xT:
	for xW.Cmp(tmp.Add(tmp.Sub(b, a), xT)) < 0 {
		// xW := xW + f(xyW)
		xW.Add(xW, f(xyW, k, curveN))

		// xyW, yyW := (xyW, yyW) + (base * f(yyW))
		tmpX, tmpY := curve.ScalarMult(bx, by, f(xyW, k, curveN).Bytes())
		xyW, yyW = curve.Add(xyW, yyW, tmpX, tmpY)

		// if yW = yT:
		if xyW.Cmp(xyT) == 0 && yyW.Cmp(yyT) == 0 {
			// b + xT - xW
			return tmp.Add(b, tmp.Sub(xT, xW))
		}
	}

	return nil
}
