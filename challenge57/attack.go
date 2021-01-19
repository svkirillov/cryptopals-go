package challenge57

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"math/big"

	"github.com/svkirillov/cryptopals-go/dh"
	"github.com/svkirillov/cryptopals-go/helpers"
	"github.com/svkirillov/cryptopals-go/oracle"
)

func SmallSubgroupAttack(dhGroup dh.DHScheme,
	oracleDH func(publicKey *big.Int) []byte,
) (*big.Int, error) {
	p := dhGroup.DHParams().P
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
				return nil, fmt.Errorf("couldn't generate random big.Int: %s", err.Error())
			}

			for rand.Cmp(helpers.BigZero) == 0 {
				rand, err = helpers.GenerateBigInt(p)
				if err != nil {
					return nil, fmt.Errorf("couldn't generate random big.Int: %s", err.Error())
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

	// n = r1 * r2 * ... * rn
	n := new(big.Int).Set(helpers.BigOne)
	for _, r := range modules {
		n.Mul(n, r)
	}

	// check if we have enough information to reassemble Bob's secret key
	if n.Cmp(q) <= 0 {
		return nil, errors.New("not enough information to reassemble Bob's secret key")
	}

	// reassemble Bob's secret key using the Chinese Remainder Theorem
	x, _, err := helpers.ChineseRemainderTheorem(remainders, modules)
	if err != nil {
		return nil, fmt.Errorf("chinese remainder theorem: %s", err.Error())
	}

	return x, nil
}
