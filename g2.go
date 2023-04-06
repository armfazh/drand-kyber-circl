package drand_kyber_circl

import (
	E "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
)

var _ kyber.Group = G2{}

type G2 struct{}

func (g G2) String() string       { return "bls12-381.G2" }
func (g G2) ScalarLen() int       { return E.ScalarSize }
func (g G2) Scalar() kyber.Scalar { return Scalar{} }
func (g G2) PointLen() int        { return E.G2SizeCompressed }
func (g G2) Point() kyber.Point   { return nil /*todo*/ }
