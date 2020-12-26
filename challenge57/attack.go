package challenge57

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"math/big"

	"github.com/svkirillov/cryptopals-go/dh"
	"github.com/svkirillov/cryptopals-go/helpers"
)

func SmallSubgroupAttack(g, p, q, j *big.Int) error {
	// Step #0
	jFactors := helpers.Factorize(j, big.NewInt(1<<16))
	if len(jFactors) == 0 {
		return errors.New("factors not found")
	}

	bob, err := dh.NewKey(g, p, q)
	if err != nil {
		return errors.New(fmt.Sprintf("couldn't create Bob key pair: %s", err.Error()))
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
				return errors.New(fmt.Sprintf("couldn't generate random big.Int: %s", err.Error()))
			}

			for rand.Cmp(helpers.BigZero) == 0 {
				rand, err = helpers.GenerateBigInt(p)
				if err != nil {
					return errors.New(fmt.Sprintf("couldn't generate random big.Int: %s", err.Error()))
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

	// n = r1 * r2 * ... * rn
	n := new(big.Int).Set(helpers.BigOne)
	for _, r := range modules {
		n.Mul(n, r)
	}

	// check if we have enough information to reassemble Bob's secret key
	if n.Cmp(q) <= 0 {
		return errors.New("not enough information to reassemble Bob's secret key")
	}

	// reassemble Bob's secret key using the Chinese Remainder Theorem
	x, _, err := helpers.ChineseRemainderTheorem(remainders, modules)
	if err != nil {
		return errors.New(fmt.Sprintf("chinese remainder theorem: %s", err.Error()))
	}

	if bob.ComparePrivateKey(x) {
		return nil
	}

	return errors.New("computed key isn't equal to Bob's private key")
}
