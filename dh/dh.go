package dh

import (
	"math"
	"math/big"

	"github.com/svkirillov/cryptopals-go/helpers"
)

// Key struct represents a key pair with group parameters
type Key struct {
	g *big.Int // g is a subgroup generator of order q
	p *big.Int // p is group order
	q *big.Int // q is subgroup order

	privateKey *big.Int
	publicKey  *big.Int
}

// NewKey creates new key pair with the specified group parameters
func NewKey(g *big.Int, p *big.Int, q *big.Int) (*Key, error) {
	k := Key{
		g:          new(big.Int).Set(g),
		p:          new(big.Int).Set(p),
		q:          new(big.Int).Set(q),
		privateKey: nil,
		publicKey:  nil,
	}

	var err error

	if q.Cmp(helpers.BigZero) == 0 {
		k.privateKey, err = helpers.GenerateBigInt(big.NewInt(math.MaxInt64))
	} else {
		k.privateKey, err = helpers.GenerateBigInt(q)
	}

	if err != nil {
		return nil, err
	}

	k.publicKey = new(big.Int).Exp(k.g, k.privateKey, k.p)

	return &k, nil
}

// GetPublicKey returns copy of publicKey
func (k *Key) GetPublicKey() *big.Int {
	return new(big.Int).Set(k.publicKey)
}

// SharedSecret performs DH with a given public key and return shared secret
func (k *Key) SharedSecret(pubKey *big.Int) *big.Int {
	return new(big.Int).Exp(pubKey, k.privateKey, k.p)
}

// ComparePrivateKey compares a given private key with own one
func (k *Key) ComparePrivateKey(privKey *big.Int) bool {
	return k.privateKey.Cmp(privKey) == 0
}
