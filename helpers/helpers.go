package helpers

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	BigZero  = big.NewInt(0)
	BigOne   = big.NewInt(1)
	BigTwo   = big.NewInt(2)
	BigThree = big.NewInt(3)
)

// GenerateBigInt returns a uniform random value in [0, max)
func GenerateBigInt(max *big.Int) (n *big.Int, err error) {
	return rand.Int(rand.Reader, max)
}

// SetBigIntFromDec creates new *big.Int from decimal number as a string
func SetBigIntFromDec(s string) (n *big.Int) {
	n, _ = new(big.Int).SetString(s, 10)
	return
}

// Original: https://github.com/dnkolegov/dhpals/blob/master/dlp.go
//
// ChineseRemainderTheorem finds a solution of the system on m equations using the Chinese Reminder Theorem.
//
// Let n_1, ..., n_m be pairwise coprime (gcd(n_i, n_j) = 1, for different i,j).
// Then the system of m equations:
// x_1 = a_1 mod n_1
// ...
// x_m = a_m mod n_m
// has a unique solution for x modulo N = n_1 ... n_m
func ChineseRemainderTheorem(a, n []*big.Int) (*big.Int, *big.Int, error) {
	p := new(big.Int).Set(n[0])
	for _, n1 := range n[1:] {
		p.Mul(p, n1)
	}
	var x, q, s, z big.Int
	for i, n1 := range n {
		q.Div(p, n1)
		z.GCD(nil, &s, n1, &q)
		if z.Cmp(big.NewInt(1)) != 0 {
			return nil, p, fmt.Errorf("%d not coprime", n1)
		}
		x.Add(&x, s.Mul(a[i], s.Mul(&s, &q)))
	}
	return x.Mod(&x, p), p, nil
}

// Factorize finds factors for n in [2, upperBound)
func Factorize(n *big.Int, upperBound *big.Int) []*big.Int {
	factors := make([]*big.Int, 0)

	i := new(big.Int).Set(BigTwo)
	tmp := new(big.Int)
	newN := new(big.Int).Set(n)

	for {
		tmp.Mod(newN, i)

		if tmp.Cmp(BigZero) == 0 {
			factors = append(factors, new(big.Int).Set(i))
			for tmp.Mod(newN, i).Cmp(BigZero) == 0 {
				newN.Div(newN, i)
			}
		}

		if newN.Cmp(BigOne) == 0 {
			break
		}

		if i.Cmp(upperBound) >= 0 {
			break
		}

		i.Add(i, BigOne)
	}

	return factors
}
