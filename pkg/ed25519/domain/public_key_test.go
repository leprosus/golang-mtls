package domain_test

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"

	"github.com/leprosus/golang-mtls/pkg/ed25519/domain"
)

//nolint:gochecknoglobals
var (
	pubBs = []byte{
		112, 75, 111, 206, 158, 65, 176, 187, 106, 181, 240, 128, 199, 181, 22, 181, 24, 150, 159, 145,
		142, 81, 193, 2, 195, 235, 51, 175, 132, 66, 3, 242,
	}
	edPub   = ed25519.PublicKey(pubBs)
	pub     = domain.PublicKey(edPub)
	pubX509 = []byte{
		48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 112, 75, 111, 206, 158, 65, 176, 187, 106, 181,
		240, 128, 199, 181, 22, 181, 24, 150, 159, 145, 142, 81, 193, 2, 195, 235, 51, 175, 132, 66, 3, 242,
	}
	pubCurve = []byte{
		237, 232, 55, 115, 58, 10, 154, 213, 180, 62, 195, 43, 131, 109, 0, 9, 63, 13, 22, 77, 4, 76,
		27, 74, 26, 166, 67, 145, 62, 53, 98, 120,
	}
	pubPEM = domain.PEMBlock{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubX509,
	}
)

func TestPublicKey_ToBytes(t *testing.T) {
	t.Parallel()

	bs, err := pub.ToBytes()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(bs, pubX509) {
		t.Fatal("the computed bytes and the expected bytes are not equal")
	}
}

func TestPublicKey_ToPEMBlock(t *testing.T) {
	t.Parallel()

	pem, err := pub.ToPEMBlock()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !reflect.DeepEqual(pem, pubPEM) {
		t.Fatal("the original public key and a converted from PEM block public key are not equal")
	}
}

func TestPublicKey_ToPublicCurve(t *testing.T) {
	t.Parallel()

	curve, err := pub.ToPublicCurve()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(curve, pubCurve) {
		t.Fatal("the computed curve and the expected curve are not equal")
	}
}
