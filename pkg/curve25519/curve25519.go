package curve25519

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

var ErrImpossibleToConvertToCurve25519 = errors.New("impossible to convert Ed25519 private key to Curve25519")

func ConvEd25519PrivKeyToCurve25519(priv ed25519.PrivateKey) (bs []byte, err error) {
	h := sha512.New()
	h.Write(priv.Seed())
	out := h.Sum(nil)

	if len(out) < curve25519.ScalarSize {
		return nil, ErrImpossibleToConvertToCurve25519
	}

	return out[:curve25519.ScalarSize], nil
}

func ConvEd25519PubKeyToCurve25519(pub ed25519.PublicKey) (bs []byte, err error) {
	p := &edwards25519.Point{}
	_, err = p.SetBytes(pub)
	if err != nil {
		return nil, err
	}

	return p.BytesMontgomery(), nil
}

func GenerateSharedKey(pub ed25519.PublicKey, priv ed25519.PrivateKey) (bs []byte, err error) {
	var privCurve []byte
	privCurve, err = ConvEd25519PrivKeyToCurve25519(priv)
	if err != nil {
		return nil, err
	}

	var pubCurve []byte
	pubCurve, err = ConvEd25519PubKeyToCurve25519(pub)
	if err != nil {
		return nil, err
	}

	var secret []byte
	secret, err = curve25519.X25519(privCurve, pubCurve)
	if err != nil {
		return nil, err
	}

	return secret, nil
}
