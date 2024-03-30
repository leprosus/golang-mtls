package mtls_test

import (
	"testing"

	"mtls/pkg/ed25519/domain"

	"mtls/mtls"
	"mtls/pkg/ed25519"
)

func generatePEMPair() (pubPEMBs, privPEMBs []byte, err error) {
	var (
		pub  domain.PublicKey
		priv domain.PrivateKey
	)

	pub, priv, err = ed25519.GenerateKeyPair()
	if err != nil {
		return pubPEMBs, privPEMBs, err
	}

	var pubPEM, privPEM domain.PEMBlock

	pubPEM, err = pub.ToPEMBlock()
	if err != nil {
		return pubPEMBs, privPEMBs, err
	}

	privPEM, err = priv.ToPEMBlock()
	if err != nil {
		return pubPEMBs, privPEMBs, err
	}

	pubPEMBs = pubPEM.ToBytes()
	privPEMBs = privPEM.ToBytes()

	return pubPEMBs, privPEMBs, nil
}

func TestMTL(t *testing.T) {
	t.Parallel()

	alicePub, alicePriv, err := generatePEMPair()
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := generatePEMPair()
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
