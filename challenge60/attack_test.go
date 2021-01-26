package challenge60

import (
	"context"
	"math/big"
	"testing"

	"github.com/svkirillov/cryptopals-go/elliptic"
	"github.com/svkirillov/cryptopals-go/helpers"
	oracle2 "github.com/svkirillov/cryptopals-go/oracle"
	"github.com/svkirillov/cryptopals-go/x128"
)

func TestECKangarooAlgorithm(t *testing.T) {
	ecKangarooTests := []struct {
		k, b string
	}{
		{"10", "100"},
		{"12130", "17000"},
		{"12132880", "22132880"},
	}

	curve := elliptic.P128()

	a := new(big.Int).Set(helpers.BigZero)
	bx, by := curve.Params().Gx, curve.Params().Gy

	for _, e := range ecKangarooTests {
		k, _ := new(big.Int).SetString(e.k, 10)
		b, _ := new(big.Int).SetString(e.b, 10)

		x, y := curve.ScalarBaseMult(k.Bytes())
		K := calcK(a, b)
		N := calcN(curve.Params().N, K)
		xT, xyT, yyT := tameKangaroo(curve, bx, by, b, K, N)
		kk := catchingWildKangaroo(curve, bx, by, x, y, xT, xyT, yyT, K, a, b, context.Background())
		if kk == nil || kk.Cmp(k) != 0 {
			t.Fatal("Pollard's method for catching kangaroos on elliptic curves fails")
		}
	}
}

func TestInsecureTwistAttack(t *testing.T) {
	v, _ := new(big.Int).SetString("85518893674295321206118380980485522083", 10)
	u := new(big.Int).SetInt64(4)

	if !x128.IsOnCurve(u, v) {
		t.Fatalf("%s: the point is not on the x128 curve", t.Name())
	}

	oracle, isKeyCorrect, getPublic, privateKeyOracle := oracle2.NewX128TwistAttackOracle()

	privateKey, err := InsecureTwistsAttack(oracle, getPublic, privateKeyOracle)
	if err != nil {
		t.Fatalf("%s: %s\n", t.Name(), err.Error())
	}

	if privateKey != nil && isKeyCorrect(privateKey.Bytes()) {
		t.Logf("%s: private key was found: %d", t.Name(), privateKey)
	} else {
		t.Fatalf("%s: wrong private key was found in the insecure twist attack", t.Name())
	}
}
