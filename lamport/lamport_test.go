package lamport

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type LamportSuite struct{}

var _ = Suite(&LamportSuite{})

func (s *LamportSuite) TestGenPrivateKeyPair(c *C) {
	privKey := genPrivateKey()
	c.Assert(privKey.first, Not(DeepEquals), privKey.second)
}

func (s *LamportSuite) TestGenRand(c *C) {
	rOne := genRand()
	rTwo := genRand()
	c.Assert(rOne, Not(DeepEquals), rTwo)
}

func (s *LamportSuite) TestGenPublicKeyPair(c *C) {
	privKey := genPrivateKey()
	pubKey := genPublicKey(privKey)
	c.Assert(pubKey.first, Equals, hash256(privKey.first))
}

func (s *LamportSuite) TestGenLamportKeyPair(c *C) {
	lkeyPair := GenLamportKeyPair()
	c.Assert(256, Equals, len(lkeyPair.public))
	c.Assert(256, Equals, len(lkeyPair.private))

	firstPrivKey := lkeyPair.private[0]
	firstPubKey := lkeyPair.public[0]
	c.Assert(firstPubKey.first, Equals, hash256(firstPrivKey.first))
}

func (s *LamportSuite) TestSelectPrivKeyBitZeroSelectsFirstPrivKey(c *C) {
	b := byte(0)
	pk := genPrivateKey()
	actualPk := selectKey(b, pk)
	c.Assert(pk.first, DeepEquals, actualPk)
}

func (s *LamportSuite) TestSelectPrivKeyBitOneSelectsSecondPrivKey(c *C) {
	b := byte(1)
	pk := genPrivateKey()
	actualPk := selectKey(b, pk)
	c.Assert(pk.second, DeepEquals, actualPk)
}

func (s *LamportSuite) TestSignMessage(c *C) {
	m := "When skies are hanged and oceans drowned, the single secret will still be man"
	kp := GenLamportKeyPair()
	sig := GenSignature(m, kp)
	c.Assert(256, Equals, len(sig))
}

func (s *LamportSuite) TestSignMessageOneByte(c *C) {
	kp := GenLamportKeyPair()
	sig := GenSignature("a", kp)
	c.Assert(kp.private[0].first, DeepEquals, sig[0])
	c.Assert(kp.private[1].first, DeepEquals, sig[1])
	c.Assert(kp.private[2].first, DeepEquals, sig[2])
	c.Assert(kp.private[3].first, DeepEquals, sig[3])
	c.Assert(kp.private[4].first, DeepEquals, sig[4])
	c.Assert(kp.private[5].first, DeepEquals, sig[5])
	c.Assert(kp.private[6].first, DeepEquals, sig[6])
	c.Assert(kp.private[7].second, DeepEquals, sig[7])
}

func (s *LamportSuite) TestVerifyMessageOneByte(c *C) {
	m := "a"
	kp := GenLamportKeyPair()
	sig := GenSignature(m, kp)
	ver := Verify(m, kp.public, sig)
	c.Assert(ver, Equals, true)
}
