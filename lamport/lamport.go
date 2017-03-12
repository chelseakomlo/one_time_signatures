package lamport

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

type key struct {
	first  [32]byte
	second [32]byte
}

// Keypair is a lamport keypair, consisting of 256 pairs of private and public
// keys
type Keypair struct {
	public  [256]*key
	private [256]*key
}

// Signature is lamport signature, consisting of an array of bytes
type Signature [256][32]byte

func (s *Signature) equals(other *Signature) bool {
	isEqual := true
	for i := 0; i < 256; i++ {
		h := hash256(s[i])
		if !bytes.Equal(h[:], other[i][:]) {
			isEqual = false
		}
	}
	return isEqual
}

func genRand() []byte {
	b := make([]byte, 256)
	rand.Read(b)
	return b
}

func genPrivateKey() *key {
	f := [32]byte{}
	g := [32]byte{}
	copy(f[:], genRand())
	copy(g[:], genRand())
	return &key{first: f, second: g}
}

func hash256(b [32]byte) [32]byte {
	return sha3.Sum256(b[:])
}

func genPublicKey(privKey *key) *key {
	return &key{
		first:  hash256(privKey.first),
		second: hash256(privKey.second),
	}
}

func genKeyPair() (pub []*key, priv []*key) {
	for i := 0; i < 256; i++ {
		privK := genPrivateKey()
		priv = append(priv, privK)
		pub = append(pub, genPublicKey(privK))
	}
	return pub, priv
}

// GenLamportKeyPair will return the public/private lamport keypair
func GenLamportKeyPair() *Keypair {
	kp := Keypair{
		public:  [256]*key{},
		private: [256]*key{},
	}

	pub, priv := genKeyPair()
	copy(kp.public[:], pub)
	copy(kp.private[:], priv)
	return &kp
}

func selectKey(b byte, pkp *key) [32]byte {
	if b == 0 {
		return pkp.first
	}
	return pkp.second
}

func genSignature(m string, k [256]*key) *Signature {
	mes := sha3.Sum256([]byte(m))
	sig := Signature{}
	counter := 0
	for i := 0; i < 32; i++ {
		for j := 0; j < 8; j++ {
			a := (mes[i] >> byte(j)) & 1
			sig[counter] = selectKey(a, k[counter])
			counter++
		}
	}
	return &sig
}

// Sign will return a Lamport signature for a given message
func Sign(m string, kp *Keypair) *Signature {
	return genSignature(m, kp.private)
}

// Verify returns a boolean indicating whether the signature is valid for a
// given message
func Verify(m string, pubk [256]*key, sig *Signature) bool {
	toVerify := genSignature(m, pubk)
	return sig.equals(toVerify)
}
