package domain_test

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"

	"mtls/pkg/ed25519/domain"
)

var (
	privBs    = []byte{99, 156, 113, 194, 19, 205, 122, 70, 24, 114, 78, 144, 232, 239, 68, 85, 192, 98, 106, 213, 126, 107, 233, 31, 198, 199, 134, 120, 140, 249, 73, 9, 100, 226, 151, 91, 10, 177, 3, 10, 95, 115, 139, 36, 242, 29, 17, 172, 39, 186, 36, 33, 209, 86, 193, 124, 151, 109, 35, 247, 153, 65, 113, 197}
	edPriv    = ed25519.PrivateKey(privBs)
	priv      = domain.PrivateKey(edPriv)
	privX509  = []byte{48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 99, 156, 113, 194, 19, 205, 122, 70, 24, 114, 78, 144, 232, 239, 68, 85, 192, 98, 106, 213, 126, 107, 233, 31, 198, 199, 134, 120, 140, 249, 73, 9}
	privCurve = []byte{97, 108, 176, 226, 198, 215, 112, 131, 146, 216, 87, 112, 31, 106, 72, 226, 73, 56, 169, 244, 66, 88, 211, 140, 151, 7, 49, 131, 21, 253, 240, 255}
	privPEM   = domain.PEMBlock{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   privX509,
	}
)

func TestPrivateKey_ToBytes(t *testing.T) {
	t.Parallel()

	bs, err := priv.ToBytes()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(bs, privX509) {
		t.Fatal("the computed bytes and the expected bytes are not equal")
	}
}

func TestPrivateKey_ToPEMBlock(t *testing.T) {
	t.Parallel()

	pem, err := priv.ToPEMBlock()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !reflect.DeepEqual(pem, privPEM) {
		t.Fatal("the original private key and a converted from PEM block private key are not equal")
	}
}

func TestPrivateKey_ToPrivateCurve(t *testing.T) {
	t.Parallel()

	curve, err := priv.ToPrivateCurve()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(curve, privCurve) {
		t.Fatal("the computed curve and the expected curve are not equal")
	}
}
