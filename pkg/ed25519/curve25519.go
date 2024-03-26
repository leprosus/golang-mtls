package ed25519

import (
	"mtls/pkg/ed25519/domain"

	"golang.org/x/crypto/curve25519"
)

func GenerateSharedKey(pub domain.PublicKey, priv domain.PrivateKey) (shared domain.SharedKey, err error) {
	var privCurve []byte

	privCurve, err = priv.ToPrivateCurve()
	if err != nil {
		return nil, err
	}

	var pubCurve []byte

	pubCurve, err = pub.ToPublicCurve()
	if err != nil {
		return nil, err
	}

	shared, err = curve25519.X25519(privCurve, pubCurve)
	if err != nil {
		return nil, err
	}

	return shared, nil
}
