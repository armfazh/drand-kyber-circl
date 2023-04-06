package drand_kyber_circl

import (
	E "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
)

var _ kyber.Group = G1{}

type G1 struct{}

func (g G1) String() string       { return "bls12-381.G1" }
func (g G1) ScalarLen() int       { return E.ScalarSize }
func (g G1) Scalar() kyber.Scalar { return Scalar{} }
func (g G1) PointLen() int        { return E.G1SizeCompressed }
func (g G1) Point() kyber.Point   { return nil /*todo*/ }
