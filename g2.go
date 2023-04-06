package drand_kyber_circl

import (
	"crypto/cipher"
	"fmt"
	"io"

	circl "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
)

var _ kyber.SubGroupElement = &G2Elt{}

type G2Elt struct{ inner circl.G2 }

func (p *G2Elt) MarshalBinary() (data []byte, err error) { return p.inner.BytesCompressed(), nil }

func (p *G2Elt) UnmarshalBinary(data []byte) error { return p.inner.SetBytes(data) }

func (p *G2Elt) String() string { return fmt.Sprintf("bls12-381.G2: %x", p.inner.BytesCompressed()) }

func (p *G2Elt) MarshalSize() int { return circl.G2SizeCompressed }

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

func (p *G2Elt) Equal(p2 kyber.Point) bool { x := p2.(*G2Elt); return p.inner.IsEqual(&x.inner) }

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
	aa, bb := a.(*G2Elt), b.(*G2Elt)
	p.inner.Add(&aa.inner, &bb.inner)
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
	if q == nil {
		q = new(G2Elt).Base()
	}
	ss, qq := s.(*Scalar), q.(*G2Elt)
	p.inner.ScalarMult(&ss.inner, &qq.inner)
	return p
}

func (p *G2Elt) IsInCorrectGroup() bool { return p.inner.IsOnG2() }

func (p *G2Elt) Hash(m []byte) kyber.Point {
	// Domain comes from the ciphersuite used by the RFC of this name compatible
	// with the paired library > v18
	var Domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	p.inner.Hash(m, Domain)
	return p
}
