package mtls

import (
	"mtls/pkg/cipher"
	mtlsEd25519 "mtls/pkg/ed25519"
	"mtls/pkg/ed25519/domain"
)

type MTLS struct {
	cipher *cipher.Cipher
	sign   string
}

func NewMTLSWithPemBlocks(pubPEMBs, privPEMBs []byte) (mtls *MTLS, err error) {
	var pubPEM domain.PEMBlock

	err = pubPEM.FromBytes(pubPEMBs)
	if err != nil {
		return mtls, err
	}

	var privPEM domain.PEMBlock

	err = privPEM.FromBytes(privPEMBs)
	if err != nil {
		return mtls, err
	}

	var pub domain.PublicKey

	pub, err = pubPEM.ToPublicKey()
	if err != nil {
		return mtls, err
	}

	var priv domain.PrivateKey

	priv, err = privPEM.ToPrivateKey()
	if err != nil {
		return mtls, err
	}

	var shared domain.SharedKey

	shared, err = mtlsEd25519.GenerateSharedKey(pub, priv)
	if err != nil {
		return mtls, err
	}

	return NewMTLSWithSharedKey(shared)
}

func NewMTLSWithSharedKey(shared domain.SharedKey) (mtls *MTLS, err error) {
	mtls = &MTLS{}

	mtls.cipher, err = cipher.NewCipher(shared)
	if err != nil {
		return mtls, err
	}

	mtls.sign, err = shared.Sign()
	if err != nil {
		return mtls, err
	}

	return mtls, nil
}

func (m MTLS) Encode(src []byte) (dst []byte, err error) {
	return m.cipher.Encode(src)
}

func (m MTLS) Decode(src []byte) (dst []byte, err error) {
	return m.cipher.Decode(src)
}

func (m MTLS) Sign() (sign string) {
	return m.sign
}

func (m MTLS) Cipher() (cipher *cipher.Cipher) {
	return m.cipher
}
