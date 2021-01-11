package challenge58

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/svkirillov/cryptopals-go/dh"
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
func tameKangaroo(g, b, p, k *big.Int) (xT, yT *big.Int) {
	N := calcN(p, k)

	xT = new(big.Int).Set(helpers.BigZero)
	yT = new(big.Int).Exp(g, b, p)

	tmp := new(big.Int)

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

	xW := new(big.Int).Set(helpers.BigZero)
	yW := new(big.Int).Set(y)

	tmp := new(big.Int)

	// while xW < b - a + xT:
	for xW.Cmp(tmp.Add(tmp.Sub(b, a), xT)) < 0 {
		// xW := xW + f(yW)
		xW.Add(xW, f(yW, k, p))

		// yW := yW * g^f(yW)
		yW.Mod(yW.Mul(yW, tmp.Exp(g, f(yW, k, p), p)), p)

		// if yW = yT:
		if yW.Cmp(yT) == 0 {
			// b + xT - xW
			return tmp.Add(b, tmp.Sub(xT, xW))
		}
	}

	return nil
}

func CatchingKangaroosAttack(g, p, q, j *big.Int) error {
	// Step #0
	jFactors := helpers.Factorize(j, big.NewInt(1<<16))
	if len(jFactors) == 0 {
		return errors.New("factors not found")
	}

	bob, err := dh.NewKey(g, p, q)
	if err != nil {
		return fmt.Errorf("couldn't create Bob key pair: %s", err.Error())
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
				return fmt.Errorf("couldn't generate random big.Int: %s", err.Error())
			}

			for rand.Cmp(helpers.BigZero) == 0 {
				rand, err = helpers.GenerateBigInt(p)
				if err != nil {
					return fmt.Errorf("couldn't generate random big.Int: %s", err.Error())
				}
			}

			h.Exp(rand, power, p)
		}

		// Step #2,3
		k := bob.SharedSecret(h)
		t := helpers.MAC(k.Bytes(), []byte("crazy flamboyant for the rap enjoyment"))

		// Step #4
		for i := big.NewInt(1); i.Cmp(r) <= 0; i.Add(i, helpers.BigOne) {
			k1 := tmp.Exp(h, i, p)
			t1 := helpers.MAC(k1.Bytes(), []byte("crazy flamboyant for the rap enjoyment"))

			if hmac.Equal(t, t1) {
				modules = append(modules, r)
				remainders = append(remainders, new(big.Int).Set(i))
				continue
			}
		}
	}

	if len(modules) == 0 {
		return errors.New("empty sets of modules and remainders")
	}

	// x = n mod r
	n, r, err := helpers.ChineseRemainderTheorem(remainders, modules)
	if err != nil {
		return fmt.Errorf("chinese remainder theorem: %s", err.Error())
	}

	y := bob.GetPublicKey()

	// y' = y * g^-n
	newY := new(big.Int).Mod(tmp.Mul(y, tmp.Exp(g, tmp.Neg(n), p)), p)

	// g' = g^r
	newG := new(big.Int).Exp(g, r, p)

	// [a, b] = [0, (q-1)/r]
	a := helpers.BigZero
	b := new(big.Int).Div(tmp.Sub(q, helpers.BigOne), r)

	// if q too small
	if b.Cmp(helpers.BigZero) == 0 {
		b = new(big.Int).SetUint64(1 << 20)
	}

	m := CatchingWildKangaroo(newG, newY, p, a, b)
	if m == nil {
		return errors.New("got wrong value from CatchingWildKangaroo")
	}

	// x = n - m*r
	x := new(big.Int).Sub(n, tmp.Mul(m, r))

	if bob.ComparePrivateKey(x) {
		return nil
	}

	return errors.New("computed key isn't equal to Bob's private key")
}
