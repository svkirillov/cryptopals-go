package dh

import (
	"crypto/rand"
	"io"
	"math/big"
)

type DHKey struct {
	Private *big.Int
	Public  *big.Int
}

type DHScheme interface {
	// GenerateECKeyPair generates a new key pair using random as a source of
	// entropy.
	GenerateKey(random io.Reader) (*DHKey, error)

	// DH performs a Diffie-Hellman calculation between the provided private and
	// public keys and returns the result.
	DH(private, public *big.Int) *big.Int

	// DHLen is the number of bites returned by DH.
	DHLen() int

	// DHName is the name of the DH function.
	DHName() string

	// DHParams returns the parameters of the group.
	DHParams() *GroupParams
}

// GroupParams contains the parameters of an DH group and also provides
// a generic, non-constant time implementation of DH.
type GroupParams struct {
	P       *big.Int // P is group order
	G       *big.Int // G is a subgroup generator of order Q
	Q       *big.Int // Q is subgroup order
	Name    string
	BitSize int
}

func (g *GroupParams) DHParams() *GroupParams {
	return g
}

func (g GroupParams) GenerateKey(rng io.Reader) (*DHKey, error) {
	if rng == nil {
		rng = rand.Reader
	}

	privateKey, err := rand.Int(rand.Reader, g.Q)
	if err != nil {
		return nil, err
	}

	publicKey := new(big.Int).Exp(g.G, privateKey, g.P)

	return &DHKey{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

func (g GroupParams) DH(private, public *big.Int) *big.Int {
	return new(big.Int).Exp(public, private, g.P)
}

func (g GroupParams) DHLen() int {
	return g.BitSize
}

func (g GroupParams) DHName() string {
	return g.Name
}
