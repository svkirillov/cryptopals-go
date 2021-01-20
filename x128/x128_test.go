// Original: https://github.com/dnkolegov/dhpals/blob/master/x128

package x128

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestCswap(t *testing.T) {
	a := big.NewInt(100)
	b := big.NewInt(200)
	a1 := new(big.Int).Set(a)
	b1 := new(big.Int).Set(b)
	a, b = cswap(a, b, true)
	if a.Cmp(b1) != 0 || b.Cmp(a1) != 0 {
		t.Errorf("%s: cswap failed", t.Name())
	}

	a1 = new(big.Int).Set(a)
	b1 = new(big.Int).Set(b)
	a, b = cswap(a, b, false)
	if a.Cmp(a1) != 0 || b.Cmp(b1) != 0 {
		t.Errorf("%s: cswap failed when swap is disabled", t.Name())
	}
}

func TestBasicLadder(t *testing.T) {
	ku := ladder(U, N)
	if ku.Cmp(bigZero) != 0 {
		t.Errorf("%s: 11wrong ladder sanity check", t.Name())
	}

	for i := 0; i < 1000; i++ {
		k, _ := rand.Int(rand.Reader, Q)

		ku := ScalarBaseMult(k.Bytes())

		e := ScalarMult(new(big.Int).Set(ku), N.Bytes())
		if e.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("%s: wrong ladder sanity check for %d", t.Name(), ku)
		}

	}
}
