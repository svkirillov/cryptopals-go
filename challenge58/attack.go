package challenge58

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/svkirillov/cryptopals-go/dh"
	"github.com/svkirillov/cryptopals-go/helpers"
	"github.com/svkirillov/cryptopals-go/oracle"
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
func tameKangaroo(g, b, p, k *big.Int) (xT, yT *big.Int) {
	N := calcN(p, k)

	// xT := 0
	// yT := g^b
	xT = new(big.Int).Set(helpers.BigZero)
	yT = new(big.Int).Exp(g, b, p)

	tmp := new(big.Int)

	// for i in 1..N:
	for i := new(big.Int).Set(helpers.BigZero); i.Cmp(N) < 0; i.Add(i, helpers.BigOne) {
		// xT := xT + f(yT)
		xT.Add(xT, f(yT, k, p))

		// yT := yT * g^f(yT)
		yT.Mod(yT.Mul(yT, tmp.Exp(g, f(yT, k, p), p)), p)
	}

	return
}

// CatchingWildKangaroo implements Pollard's method for catching kangaroos
func CatchingWildKangaroo(g, y, p *big.Int, a, b *big.Int) *big.Int {
	k := calcK(a, b)
	xT, yT := tameKangaroo(g, b, p, k)

	// xW := 0
	// yW := y
	xW := new(big.Int).Set(helpers.BigZero)
	yW := new(big.Int).Set(y)

	tmp := new(big.Int)

	tmp.Sub(b, a).Add(tmp, xT)
	xWUpperBound := new(big.Int).Set(tmp) // xWUpperBound := b - a + xT

	// while xW < b - a + xT:
	for xW.Cmp(xWUpperBound) < 0 {
		fVal := f(yW, k, p)

		// xW := xW + f(yW)
		xW.Add(xW, fVal)

		// yW := yW * g^f(yW)
		yW.Mod(yW.Mul(yW, tmp.Exp(g, fVal, p)), p)

		// if yW = yT:
		if yW.Cmp(yT) == 0 {
			// b + xT - xW
			return tmp.Add(b, tmp.Sub(xT, xW))
		}
	}

	return nil
}

func CatchingKangaroosAttack(
	dhGroup dh.DHScheme,
	oracleDH func(publicKey *big.Int) []byte,
	getPublicKey func() *big.Int,
) (*big.Int, error) {
	p := dhGroup.DHParams().P
	g := dhGroup.DHParams().G
	q := dhGroup.DHParams().Q

	j := new(big.Int).Div(new(big.Int).Sub(p, helpers.BigOne), q)

	// Step #0
	jFactors := helpers.Factorize(j, big.NewInt(1<<16))
	if len(jFactors) == 0 {
		return nil, errors.New("factors not found")
	}

	var modules, remainders []*big.Int
	tmp := new(big.Int)

	for _, r := range jFactors {
		// Step #1
		power := tmp.Div(tmp.Sub(p, helpers.BigOne), r)
		h := new(big.Int).Set(helpers.BigOne)
		for h.Cmp(helpers.BigOne) == 0 {
			rand, err := helpers.GenerateBigInt(p)
			if err != nil {
				return nil, fmt.Errorf("couldn'ss generate random big.Int: %s", err.Error())
			}

			for rand.Cmp(helpers.BigZero) == 0 {
				rand, err = helpers.GenerateBigInt(p)
				if err != nil {
					return nil, fmt.Errorf("couldn'ss generate random big.Int: %s", err.Error())
				}
			}

			h.Exp(rand, power, p)
		}

		// Step #2,3
		ss := oracleDH(h)

		// Step #4
		for i := big.NewInt(1); i.Cmp(r) <= 0; i.Add(i, helpers.BigOne) {
			k1 := dhGroup.DH(i, h)
			ss1 := oracle.MAC(k1.Bytes())

			if hmac.Equal(ss, ss1) {
				modules = append(modules, r)
				remainders = append(remainders, new(big.Int).Set(i))
				continue
			}
		}
	}

	if len(modules) == 0 {
		return nil, errors.New("empty sets of modules and remainders")
	}

	// x = n mod r
	n, r, err := helpers.ChineseRemainderTheorem(remainders, modules)
	if err != nil {
		return nil, fmt.Errorf("chinese remainder theorem: %s", err.Error())
	}

	y := getPublicKey()

	// y' = y * g^-n
	newY := new(big.Int).Mod(tmp.Mul(y, tmp.Exp(g, tmp.Neg(n), p)), p)

	// g' = g^r
	newG := new(big.Int).Exp(g, r, p)

	// [a, b] = [0, (q-1)/r]
	a := new(big.Int).Set(helpers.BigZero)
	b := new(big.Int).Div(tmp.Sub(q, helpers.BigOne), r)

	// if q too small
	if b.Cmp(helpers.BigZero) == 0 {
		b = new(big.Int).SetUint64(1 << 20)
	}

	m := CatchingWildKangaroo(newG, newY, p, a, b)
	if m == nil {
		return nil, errors.New("got wrong value from CatchingWildKangaroo")
	}

	// x = n + m*r
	x := new(big.Int).Add(n, tmp.Mul(m, r))

	return x, nil
}
