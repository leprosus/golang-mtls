package ed25519_test

import (
	"bytes"
	"testing"

	"github.com/leprosus/golang-mtls/pkg/ed25519"
	"github.com/leprosus/golang-mtls/pkg/ed25519/domain"
)

func TestGenerateSharedKey(t *testing.T) {
	t.Parallel()

	var (
		alicePub  domain.PublicKey
		alicePriv domain.PrivateKey
		err       error
	)

	alicePub, alicePriv, err = ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var (
		bobPub  domain.PublicKey
		bobPriv domain.PrivateKey
	)

	bobPub, bobPriv, err = ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var (
		aliceShared domain.SharedKey
		bobShared   domain.SharedKey
	)

	aliceShared, err = ed25519.GenerateSharedKey(bobPub, alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	bobShared, err = ed25519.GenerateSharedKey(alicePub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatal("got to different shared keys")
	}
}
