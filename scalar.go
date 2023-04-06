package drand_kyber_circl

import (
	"crypto/cipher"
	"io"

	circl "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/drand/kyber"
)

var _ kyber.Scalar = &Scalar{}

type Scalar struct{ inner circl.Scalar }

func (s *Scalar) MarshalBinary() (data []byte, err error) { return s.inner.MarshalBinary() }

func (s *Scalar) UnmarshalBinary(data []byte) error { return s.inner.UnmarshalBinary(data) }

func (s *Scalar) String() string { return s.inner.String() }

func (s *Scalar) MarshalSize() int { return circl.ScalarSize }

func (s *Scalar) MarshalTo(w io.Writer) (int, error) {
	buf, err := s.inner.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (s *Scalar) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.inner.UnmarshalBinary(buf)
}

func (s *Scalar) Equal(s2 kyber.Scalar) bool {
	x := s2.(*Scalar).inner
	return s.inner.IsEqual(&x) == 1
}

func (s *Scalar) Set(a kyber.Scalar) kyber.Scalar {
	aa := a.(*Scalar).inner
	s.inner.Set(&aa)
	return s
}

func (s *Scalar) Clone() kyber.Scalar { return new(Scalar).Set(s) }

func (s *Scalar) SetInt64(v int64) kyber.Scalar {
	if v >= 0 {
		s.inner.SetUint64(uint64(v))
	} else {
		s.inner.SetUint64(uint64(-v))
		s.inner.Neg()
	}

	return s
}

func (s *Scalar) Zero() kyber.Scalar { s.inner.SetUint64(0); return s }

func (s *Scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	aa := a.(*Scalar).inner
	bb := b.(*Scalar).inner
	s.inner.Add(&aa, &bb)
	return s
}

func (s *Scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	aa := a.(*Scalar).inner
	bb := b.(*Scalar).inner
	s.inner.Sub(&aa, &bb)
	return s
}

func (s *Scalar) Neg(a kyber.Scalar) kyber.Scalar {
	s.Set(a)
	s.inner.Neg()
	return s
}

func (s *Scalar) One() kyber.Scalar { s.inner.SetUint64(1); return s }

func (s *Scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	aa := a.(*Scalar).inner
	bb := b.(*Scalar).inner
	s.inner.Mul(&aa, &bb)
	return s
}

func (s *Scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	s.Inv(b)
	s.Mul(s, a)
	return s
}

func (s *Scalar) Inv(a kyber.Scalar) kyber.Scalar {
	aa := a.(*Scalar).inner
	s.inner.Inv(&aa)
	return s
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func (s *Scalar) Pick(stream cipher.Stream) kyber.Scalar {
	err := s.inner.Random(cipher.StreamReader{S: stream, R: zeroReader{}})
	if err != nil {
		panic(err)
	}
	return s
}

func (s *Scalar) SetBytes(data []byte) kyber.Scalar { s.inner.SetBytes(data); return s }
