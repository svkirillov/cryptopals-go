package challenge60

import (
	"math/big"
	"testing"

	"github.com/svkirillov/cryptopals-go/elliptic"
	"github.com/svkirillov/cryptopals-go/helpers"
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
		kk := CatchingWildKangaroo(curve, bx, by, x, y, a, b)
		if kk == nil || kk.Cmp(k) != 0 {
			t.Fatal("Pollard's method for catching kangaroos on elliptic curves fails")
		}
	}
}
