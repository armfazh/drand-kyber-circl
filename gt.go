package drand_kyber_circl

import (
	"crypto/cipher"
	"io"

	circl "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
)

var gtBase *circl.Gt

func init() {
	gtBase = circl.Pair(circl.G1Generator(), circl.G2Generator())
}

var _ kyber.Point = &GTElt{}

type GTElt struct{ inner circl.Gt }

func (p *GTElt) MarshalBinary() (data []byte, err error) { return p.inner.MarshalBinary() }

func (p *GTElt) UnmarshalBinary(data []byte) error { return p.inner.UnmarshalBinary(data) }

func (p *GTElt) String() string { return p.inner.String() }

func (p *GTElt) MarshalSize() int { return circl.GtSize }

func (p *GTElt) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *GTElt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *GTElt) Equal(p2 kyber.Point) bool { x := p2.(*GTElt).inner; return p.inner.IsEqual(&x) }

func (p *GTElt) Null() kyber.Point { p.inner.SetIdentity(); return p }

func (p *GTElt) Base() kyber.Point { p.inner = *gtBase; return p }

func (p *GTElt) Pick(rand cipher.Stream) kyber.Point {
	panic("TODO: bls12-381.GT.Pick()")
}

func (p *GTElt) Set(p2 kyber.Point) kyber.Point { p.inner = p2.(*GTElt).inner; return p }

func (p *GTElt) Clone() kyber.Point { return new(GTElt).Set(p) }

func (p *GTElt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Embed(data []byte, r cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*GTElt).inner
	bb := b.(*GTElt).inner
	p.inner.Mul(&aa, &bb)
	return p
}

func (p *GTElt) Sub(a, b kyber.Point) kyber.Point {
	p.Neg(b)
	p.Add(a, p)
	return p
}

func (p *GTElt) Neg(a kyber.Point) kyber.Point {
	aa := a.(*GTElt).inner
	p.inner.Inv(&aa)
	return p
}

func (p *GTElt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	ss := s.(*Scalar).inner
	qq := q.(*GTElt).inner
	p.inner.Exp(&qq, &ss)
	return p
}
