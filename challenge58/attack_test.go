package challenge58

import (
	"math/big"
	"testing"

	"github.com/svkirillov/cryptopals-go/dh"
	"github.com/svkirillov/cryptopals-go/helpers"
	oracle2 "github.com/svkirillov/cryptopals-go/oracle"
)

func TestCatchWildKangaroo(t *testing.T) {
	p := helpers.SetBigIntFromDec("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623")
	g := helpers.SetBigIntFromDec("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357")
	y := helpers.SetBigIntFromDec("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119")
	a := new(big.Int).Set(helpers.BigZero)
	b := new(big.Int).SetUint64(1 << 20)

	x := CatchingWildKangaroo(g, y, p, a, b)
	if x == nil || new(big.Int).Exp(g, x, p).Cmp(y) != 0 {
		t.Error("Pollard's method for catching kangaroos fails")
	}
}

func TestCatchingKangaroosAttack(t *testing.T) {
	dhGroup := dh.MODP512V58()

	oracle, isKeyCorrect, getPublicKey := oracle2.NewDHAttackOracle(dhGroup)

	privateKey, err := CatchingKangaroosAttack(dhGroup, oracle, getPublicKey)
	if err != nil {
		t.Fatalf("CatchingKangaroosAttack fails: %s", err.Error())
	}

	if !isKeyCorrect(privateKey.Bytes()) {
		t.Fatal("computed key isn't equal to Bob's private key")
	}
}
