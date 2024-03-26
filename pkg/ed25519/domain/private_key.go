package domain

import (
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"errors"

	"golang.org/x/crypto/curve25519"
)

var ErrImpossibleToConvertToPrivateCurve = errors.New("impossible to convert Ed25519 private key to Curve25519")

type PrivateKey ed25519.PrivateKey

func (priv PrivateKey) ToBytes() (bs []byte, err error) {
	return x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(priv))
}

func (priv PrivateKey) ToPEMBlock() (pem PEMBlock, err error) {
	var bs []byte

	bs, err = priv.ToBytes()
	if err != nil {
		return pem, err
	}

	pem = PEMBlock{
		Type:  privateKeyPEMType,
		Bytes: bs,
	}

	return pem, nil
}

func (priv PrivateKey) ToPrivateCurve() (privCurve PrivateCurve, err error) {
	edPriv := ed25519.PrivateKey(priv)

	h := sha512.New()
	h.Write(edPriv.Seed())
	out := h.Sum(nil)

	if len(out) < curve25519.ScalarSize {
		return nil, ErrImpossibleToConvertToPrivateCurve
	}

	return out[:curve25519.ScalarSize], nil
}
