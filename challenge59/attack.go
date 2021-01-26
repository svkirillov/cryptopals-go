package challenge59

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"math/big"

	"github.com/svkirillov/cryptopals-go/elliptic"
	"github.com/svkirillov/cryptopals-go/helpers"
	"github.com/svkirillov/cryptopals-go/oracle"
)

// pickRandomPoint picks a random point on given curve
func pickRandomPoint(curve elliptic.Curve, order *big.Int) (x *big.Int, y *big.Int) {
	k := new(big.Int).Div(curve.Params().N, order).Bytes()

	for {
		x, y = elliptic.GeneratePoint(curve)
		x, y = curve.ScalarMult(x, y, k)

		if x.Cmp(helpers.BigZero) == 0 && y.Cmp(helpers.BigZero) == 0 {
			continue
		}

		return
	}
}

// ecdh performs DH with given curve, public and private keys
func ecdh(curve elliptic.Curve, x *big.Int, y *big.Int, privateKey []byte) []byte {
	ssx, ssy := curve.ScalarMult(x, y, privateKey)
	return oracle.MAC(elliptic.Marshal(curve, ssx, ssy))
}

// checkDuplicate returns true if no duplicates were found
func checkDuplicate(reminders []*big.Int, modules []*big.Int, r *big.Int, m *big.Int) bool {
	if len(reminders) != len(modules) {
		panic("checkDuplicate: len(reminders) != len(modules)")
	}

	ok := true

	for i := 0; i < len(reminders); i++ {
		if reminders[i].Cmp(r) == 0 && modules[i].Cmp(m) == 0 {
			ok = false
			break
		}
	}

	return ok
}

func InvalidCurveAttack(oracleECDH func(x, y *big.Int) []byte) (*big.Int, error) {
	invalidCurves := []elliptic.Curve{elliptic.P128V1(), elliptic.P128V2(), elliptic.P128V3()}

	var modules, remainders []*big.Int

	for _, curve := range invalidCurves {
		factors := helpers.Factorize(curve.Params().N, big.NewInt(1<<16))
		if len(factors) == 0 {
			return nil, errors.New("factors not found")
		}
		if factors[0].Cmp(helpers.BigTwo) == 0 {
			factors = factors[1:]
		}

		for _, factor := range factors {
			x, y := pickRandomPoint(curve, factor)

			ss := oracleECDH(x, y)

			for k := big.NewInt(1); k.Cmp(factor) <= 0; k.Add(k, helpers.BigOne) {
				ss1 := ecdh(curve, x, y, k.Bytes())

				if hmac.Equal(ss, ss1) && checkDuplicate(remainders, modules, k, factor) {
					remainders = append(remainders, new(big.Int).Set(k))
					modules = append(modules, factor)
					break
				}
			}
		}
	}

	x, _, err := helpers.ChineseRemainderTheorem(remainders, modules)
	if err != nil {
		return nil, fmt.Errorf("chinese remainder theorem: %s", err.Error())
	}

	return x, nil
}
