package mtls

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	. "mtls/pkg/cipher"
	. "mtls/pkg/curve25519"
	. "mtls/pkg/ed25519"
	"strings"
)

type MTLS struct {
	cipher *Cipher
	sign   string
}

const SignLength = 6

func NewMTLS(pubBs, privBs []byte) (mtls *MTLS, err error) {
	var (
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	)

	pub, priv, err = ParsePemBytesPair(pubBs, privBs)
	if err != nil {
		return mtls, err
	}

	var shared []byte
	shared, err = GenerateSharedKey(pub, priv)
	if err != nil {
		return mtls, err
	}

	mtls = &MTLS{}
	mtls.cipher, err = NewCipher(shared)
	if err != nil {
		return mtls, err
	}

	hashFn := sha512.New()
	hashFn.Write(shared)
	hash := hashFn.Sum(nil)
	hashStr := hex.EncodeToString(hash)

	hashLen := len(hashStr)
	if hashLen < SignLength {
		diff := SignLength - hashLen
		padding := strings.Repeat("0", diff)

		mtls.sign = padding + string(hashStr)
	} else {
		mtls.sign = string(hashStr[0:SignLength])
	}

	return mtls, nil
}

func (m MTLS) Sign() (sign string) {
	return m.sign
}

func (m MTLS) Encode(src []byte) (dst []byte, err error) {
	return m.cipher.Encode(src)
}

func (m MTLS) Decode(src []byte) (dst []byte, err error) {
	return m.cipher.Decode(src)
}
