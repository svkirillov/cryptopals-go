package challenge57

import (
	"testing"

	"github.com/svkirillov/cryptopals-go/dh"
	oracle2 "github.com/svkirillov/cryptopals-go/oracle"
)

func TestSmallSubgroupAttack(t *testing.T) {
	dhGroup := dh.MODP512V57()

	oracle, isKeyCorrect, _ := oracle2.NewDHAttackOracle(dhGroup)

	privateKey, err := SmallSubgroupAttack(dhGroup, oracle)
	if err != nil {
		t.Fatalf("small subgroup attack failed: %s", err.Error())
	}

	if !isKeyCorrect(privateKey.Bytes()) {
		t.Fatal("computed key isn't equal to Bob's private key")
	}
}
