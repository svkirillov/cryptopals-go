package challenge57

import (
	"math/big"
	"testing"

	"github.com/svkirillov/cryptopals-go/helpers"
)

func TestSmallSubgroupAttack(t *testing.T) {
	p := helpers.SetBigIntFromDec("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771")
	g := helpers.SetBigIntFromDec("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143")
	q := helpers.SetBigIntFromDec("236234353446506858198510045061214171961")
	j := new(big.Int).Div(new(big.Int).Sub(p, helpers.BigOne), q)

	if err := SmallSubgroupAttack(g, p, q, j); err != nil {
		t.Errorf("small subgroup attack failed: %s", err.Error())
	}
}
