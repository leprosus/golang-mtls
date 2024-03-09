package curve25519

import (
	"bytes"
	. "crypto/ed25519"
	"testing"

	"mtls/pkg/ed25519"
)

func TestGenerateSharedKey(t *testing.T) {
	var (
		alicePub  PublicKey
		alicePriv PrivateKey
		err       error
	)

	alicePub, alicePriv, err = ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var (
		bobPub  PublicKey
		bobPriv PrivateKey
	)
	bobPub, bobPriv, err = ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var (
		aliceShared []byte
		bobShared   []byte
	)
	aliceShared, err = GenerateSharedKey(bobPub, alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	bobShared, err = GenerateSharedKey(alicePub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatal("got to different shared keys")
	}
}
