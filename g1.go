package drand_kyber_circl

import (
	"crypto/cipher"
	"fmt"
	"io"

	circl "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
)

var _ kyber.SubGroupElement = &G1Elt{}

type G1Elt struct{ inner circl.G1 }

func (p *G1Elt) MarshalBinary() (data []byte, err error) { return p.inner.BytesCompressed(), nil }

func (p *G1Elt) UnmarshalBinary(data []byte) error { return p.inner.SetBytes(data) }

func (p *G1Elt) String() string { return fmt.Sprintf("bls12-381.G1: %x", p.inner.BytesCompressed()) }

func (p *G1Elt) MarshalSize() int { return circl.G1SizeCompressed }

func (p *G1Elt) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *G1Elt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *G1Elt) Equal(p2 kyber.Point) bool { x := p2.(*G1Elt); return p.inner.IsEqual(&x.inner) }

func (p *G1Elt) Null() kyber.Point { p.inner.SetIdentity(); return p }

func (p *G1Elt) Base() kyber.Point { p.inner = *circl.G1Generator(); return p }

func (p *G1Elt) Pick(rand cipher.Stream) kyber.Point {
	var buf [32]byte
	rand.XORKeyStream(buf[:], buf[:])
	p.inner.Hash(buf[:], nil)
	return p
}

func (p *G1Elt) Set(p2 kyber.Point) kyber.Point { p.inner = p2.(*G1Elt).inner; return p }

func (p *G1Elt) Clone() kyber.Point { return new(G1Elt).Set(p) }

func (p *G1Elt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (p *G1Elt) Embed(data []byte, r cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *G1Elt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (p *G1Elt) Add(a, b kyber.Point) kyber.Point {
	aa, bb := a.(*G1Elt), b.(*G1Elt)
	p.inner.Add(&aa.inner, &bb.inner)
	return p
}

func (p *G1Elt) Sub(a, b kyber.Point) kyber.Point {
	p.Neg(b)
	p.Add(a, p)
	return p
}

func (p *G1Elt) Neg(a kyber.Point) kyber.Point {
	p.Set(a)
	p.inner.Neg()
	return p
}

func (p *G1Elt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = new(G1Elt).Base()
	}
	ss, qq := s.(*Scalar), q.(*G1Elt)
	p.inner.ScalarMult(&ss.inner, &qq.inner)
	return p
}

func (p *G1Elt) IsInCorrectGroup() bool { return p.inner.IsOnG1() }

func (p *G1Elt) Hash(m []byte) kyber.Point {
	// Domain comes from the ciphersuite used by the RFC of this name compatible
	// with the paired library > v18
	var Domain = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
	p.inner.Hash(m, Domain)
	return p
}
