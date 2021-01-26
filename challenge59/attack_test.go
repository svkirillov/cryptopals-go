package challenge59

import (
	"testing"

	"github.com/svkirillov/cryptopals-go/elliptic"
	oracle2 "github.com/svkirillov/cryptopals-go/oracle"
)

func TestECDHInvalidCurveAttack(t *testing.T) {
	p128 := elliptic.P128()

	oracle, isKeyCorrect, _ := oracle2.NewECDHAttackOracle(p128)

	privateKey, err := InvalidCurveAttack(oracle)
	if err != nil {
		t.Fatalf("%s: %s\n", t.Name(), err.Error())
	}
	t.Logf("%s: Private key: %d\n", t.Name(), privateKey)

	if !isKeyCorrect(privateKey.Bytes()) {
		t.Fatalf("%s: wrong private key was found in the invalid curve attack\n", t.Name())
	}
}
