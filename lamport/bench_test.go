package lamport

import (
	"testing"

	. "gopkg.in/check.v1"
)

func BenchTest(t *testing.T) { TestingT(t) }

type BenchSuite struct{}

var _ = Suite(&BenchSuite{})

func (s *BenchSuite) BenchmarkKeyGen(c *C) {
	for i := 0; i < c.N; i++ {
		GenLamportKeyPair()
	}
}

func (s *BenchSuite) BenchmarkGenSignature(c *C) {
	m := `Friends, Romans, countrymen, lend me your ears: I come to bury Caesar
,not to praise him.`
	kp := GenLamportKeyPair()
	for i := 0; i < c.N; i++ {
		Sign(m, kp)
	}
}
