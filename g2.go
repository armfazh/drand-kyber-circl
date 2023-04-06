package drand_kyber_circl

import (
	"crypto/cipher"
	"io"

	circl "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
)

var _ kyber.SubGroupElement = &G2Elt{}

type G2Elt struct{ inner circl.G2 }

func (p *G2Elt) MarshalBinary() (data []byte, err error) { return p.inner.BytesCompressed(), nil }

func (p *G2Elt) UnmarshalBinary(data []byte) error { return p.inner.SetBytes(data) }

func (p *G2Elt) String() string { return p.inner.String() }

func (p *G2Elt) MarshalSize() int { return circl.G1SizeCompressed }

func (p *G2Elt) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *G2Elt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *G2Elt) Equal(p2 kyber.Point) bool { x := p2.(*G2Elt).inner; return p.inner.IsEqual(&x) }

func (p *G2Elt) Null() kyber.Point { p.inner.SetIdentity(); return p }

func (p *G2Elt) Base() kyber.Point { p.inner = *circl.G2Generator(); return p }

func (p *G2Elt) Pick(rand cipher.Stream) kyber.Point {
	var buf [32]byte
	rand.XORKeyStream(buf[:], buf[:])
	p.inner.Hash(buf[:], nil)
	return p
}

func (p *G2Elt) Set(p2 kyber.Point) kyber.Point { p.inner = p2.(*G2Elt).inner; return p }

func (p *G2Elt) Clone() kyber.Point { return new(G2Elt).Set(p) }

func (p *G2Elt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (p *G2Elt) Embed(data []byte, r cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *G2Elt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (p *G2Elt) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*G2Elt).inner
	bb := b.(*G2Elt).inner
	p.inner.Add(&aa, &bb)
	return p
}

func (p *G2Elt) Sub(a, b kyber.Point) kyber.Point {
	p.Neg(b)
	p.Add(a, p)
	return p
}

func (p *G2Elt) Neg(a kyber.Point) kyber.Point {
	p.Set(a)
	p.inner.Neg()
	return p
}

func (p *G2Elt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	ss := s.(*Scalar).inner
	qq := q.(*G2Elt).inner
	p.inner.ScalarMult(&ss, &qq)
	return p
}

func (p *G2Elt) IsInCorrectGroup() bool { return p.inner.IsOnG2() }
