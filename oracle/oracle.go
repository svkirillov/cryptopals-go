package oracle

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/svkirillov/cryptopals-go/dh"
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
