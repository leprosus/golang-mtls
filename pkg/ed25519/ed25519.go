package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/leprosus/golang-mtls/pkg/ed25519/domain"
)

func GenerateKeyPair() (pub domain.PublicKey, priv domain.PrivateKey, err error) {
	var (
		edPub  ed25519.PublicKey
		edPriv ed25519.PrivateKey
	)

	edPub, edPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pub, priv, err
	}

	pub = domain.PublicKey(edPub)
	priv = domain.PrivateKey(edPriv)

	return pub, priv, nil
}
