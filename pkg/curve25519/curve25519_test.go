package curve25519_test

import (
	"bytes"
	"crypto/ed25519"
	"mtls/pkg/curve25519"
	"testing"

	mtlsEd25519 "mtls/pkg/ed25519"
)

func TestGenerateSharedKey(t *testing.T) {
	t.Parallel()

	var (
		alicePub  ed25519.PublicKey
		alicePriv ed25519.PrivateKey
		err       error
	)

	alicePub, alicePriv, err = mtlsEd25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var (
		bobPub  ed25519.PublicKey
		bobPriv ed25519.PrivateKey
	)

	bobPub, bobPriv, err = mtlsEd25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var (
		aliceShared []byte
		bobShared   []byte
	)

	aliceShared, err = curve25519.GenerateSharedKey(bobPub, alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	bobShared, err = curve25519.GenerateSharedKey(alicePub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatal("got to different shared keys")
	}
}
