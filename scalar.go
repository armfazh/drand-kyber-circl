package drand_kyber_circl

import (
	"crypto/cipher"
	"io"

	E "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
)

var _ kyber.Scalar = Scalar{}

type Scalar struct{ E.Scalar }

func (s Scalar) MarshalBinary() (data []byte, err error) { return nil, nil }
func (s Scalar) UnmarshalBinary(data []byte) error       { return nil }
func (s Scalar) String() string                          { return "nil" }
func (s Scalar) MarshalSize() int                        { return 0 }
func (s Scalar) MarshalTo(w io.Writer) (int, error)      { return 0, nil }
func (s Scalar) UnmarshalFrom(r io.Reader) (int, error)  { return 0, nil }

func (s Scalar) Equal(s2 kyber.Scalar) bool           { return false }
func (s Scalar) Set(a kyber.Scalar) kyber.Scalar      { return nil }
func (s Scalar) Clone() kyber.Scalar                  { return nil }
func (s Scalar) SetInt64(v int64) kyber.Scalar        { return nil }
func (s Scalar) Zero() kyber.Scalar                   { return nil }
func (s Scalar) Add(a, b kyber.Scalar) kyber.Scalar   { return nil }
func (s Scalar) Sub(a, b kyber.Scalar) kyber.Scalar   { return nil }
func (s Scalar) Neg(a kyber.Scalar) kyber.Scalar      { return nil }
func (s Scalar) One() kyber.Scalar                    { return nil }
func (s Scalar) Mul(a, b kyber.Scalar) kyber.Scalar   { return nil }
func (s Scalar) Div(a, b kyber.Scalar) kyber.Scalar   { return nil }
func (s Scalar) Inv(a kyber.Scalar) kyber.Scalar      { return nil }
func (s Scalar) Pick(rand cipher.Stream) kyber.Scalar { return nil }
func (s Scalar) SetBytes([]byte) kyber.Scalar         { return nil }
