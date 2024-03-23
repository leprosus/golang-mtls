package mtls_test

import (
	"testing"

	"mtls/mtls"
	"mtls/pkg/ed25519"
)

func TestMTL(t *testing.T) {
	t.Parallel()

	alicePub, alicePriv, err := ed25519.GeneratePemBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := ed25519.GeneratePemBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	var aliceMTLS *mtls.MTLS

	aliceMTLS, err = mtls.NewMTLS(bobPub, alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	var bobMTLS *mtls.MTLS

	bobMTLS, err = mtls.NewMTLS(alicePub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	if aliceMTLS.Sign() != bobMTLS.Sign() {
		t.Fatal("signs of alice and bob are not equal")
	}

	const original = "test text"

	var encoded []byte

	encoded, err = aliceMTLS.Encode([]byte(original))
	if err != nil {
		t.Fatal(err)
	}

	var decoded []byte

	decoded, err = bobMTLS.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if original != string(decoded) {
		t.Fatal("encode -> decode process finished unwell")
	}
}
