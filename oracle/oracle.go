// Some code is taken from https://github.com/dnkolegov/dhpals/blob/master/oracle.go

package oracle

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"math/big"

	"github.com/svkirillov/cryptopals-go/elliptic"
)

const (
	dhKeyAgreementConst = "crazy flamboyant for the rap enjoyment"
)

func MAC(k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(dhKeyAgreementConst))
	return mac.Sum(nil)
}

func NewECDHAttackOracle(curve elliptic.Curve) (
	ecdh func(x, y *big.Int) []byte,
	isKeyCorrect func([]byte) bool,
	getPublicKey func() (x, y *big.Int),
) {
	privateKey, x, y, err := elliptic.GenerateKey(curve, nil)
	if err != nil {
		panic(err)
	}

	ecdh = func(x, y *big.Int) []byte {
		sx, sy := curve.ScalarMult(x, y, privateKey)
		k := append(elliptic.Marshal(curve, sx, sy))
		return MAC(k)
	}

	isKeyCorrect = func(key []byte) bool {
		return bytes.Equal(privateKey, key)
	}

	getPublicKey = func() (*big.Int, *big.Int) {
		return x, y
	}

	return
}
