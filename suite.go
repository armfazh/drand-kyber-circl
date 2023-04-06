package drand_kyber_circl

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	circl "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/util/random"
	"github.com/drand/kyber/xof/blake2xb"
)

var _ pairing.Suite = Suite{}

type Suite struct{}

func (s Suite) G1() kyber.Group { return G1 }
func (s Suite) G2() kyber.Group { return G2 }
func (s Suite) GT() kyber.Group { return GT }
func (s Suite) Pair(p1, p2 kyber.Point) kyber.Point {
	aa := p1.(*G1Elt).inner
	bb := p2.(*G2Elt).inner
	return &GTElt{*circl.Pair(&aa, &bb)}
}
func (s Suite) ValidatePairing(p1, p2, inv1, inv2 kyber.Point) bool {
	aa := p1.(*G1Elt).inner
	bb := p2.(*G2Elt).inner
	cc := inv1.(*G1Elt).inner
	dd := inv2.(*G2Elt).inner
	out := circl.ProdPairFrac([]*circl.G1{&aa, &cc}, []*circl.G2{&bb, &dd}, []int{1, -1})
	return out.IsIdentity()
}

func (s Suite) New(t reflect.Type) interface{} {
	panic("Suite.Encoding: deprecated in drand")
}

func (s Suite) Read(r io.Reader, objs ...interface{}) error {
	panic("Suite.Read(): deprecated in drand")
}

func (s Suite) Write(w io.Writer, objs ...interface{}) error {
	panic("Suite.Write(): deprecated in drand")
}

func (s Suite) Hash() hash.Hash {
	return sha256.New()
}

func (s Suite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (s Suite) RandomStream() cipher.Stream {
	return random.New()
}
