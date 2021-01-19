// Some code is taken from https://github.com/dnkolegov/dhpals/blob/master/oracle.go

package oracle

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/svkirillov/cryptopals-go/dh"
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

func NewDHAttackOracle(dhGroup dh.DHScheme) (
	dh func(publicKey *big.Int) []byte,
	isKeyCorrect func([]byte) bool,
	getPublicKey func() *big.Int,
) {
	dhKey, _ := dhGroup.GenerateKey(rand.Reader)

	dh = func(publicKey *big.Int) []byte {
		sharedKey := dhGroup.DH(dhKey.Private, publicKey)
		return MAC(sharedKey.Bytes())
	}

	isKeyCorrect = func(key []byte) bool {
		return bytes.Equal(dhKey.Private.Bytes(), key)
	}

	getPublicKey = func() *big.Int {
		return dhKey.Public
	}

	return
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
		// skipping trailing zeros in fixed size big-endian byte representation of big.Int
		// e.g. if the original private key is 886092136281582889795402858978242928
		// then it's 16-byte representation will be [0 170 167 183 29 163 210 19 176 223 2 100 1 190 113 112]
		// but the given key in big-endian byte representation derived from big.Int doesn't have first zero:
		// [170 167 183 29 163 210 19 176 223 2 100 1 190 113 112]
		i := 0
		for privateKey[i] == 0 {
			i++
		}

		return bytes.Equal(privateKey[i:], key)
	}

	getPublicKey = func() (*big.Int, *big.Int) {
		return x, y
	}

	return
}
