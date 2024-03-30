package domain_test

import (
	"bytes"
	"strings"
	"testing"

	"mtls/pkg/ed25519/domain"
)

var (
	pubPEMBs  = []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 67, 111, 119, 66, 81, 89, 68, 75, 50, 86, 119, 65, 121, 69, 65, 99, 69, 116, 118, 122, 112, 53, 66, 115, 76, 116, 113, 116, 102, 67, 65, 120, 55, 85, 87, 116, 82, 105, 87, 110, 53, 71, 79, 85, 99, 69, 67, 119, 43, 115, 122, 114, 52, 82, 67, 65, 47, 73, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10}
	privPEMBs = []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 67, 52, 67, 65, 81, 65, 119, 66, 81, 89, 68, 75, 50, 86, 119, 66, 67, 73, 69, 73, 71, 79, 99, 99, 99, 73, 84, 122, 88, 112, 71, 71, 72, 74, 79, 107, 79, 106, 118, 82, 70, 88, 65, 89, 109, 114, 86, 102, 109, 118, 112, 72, 56, 98, 72, 104, 110, 105, 77, 43, 85, 107, 74, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10}
)

func TestPEMBlock_ToPublicKey(t *testing.T) {
	t.Parallel()

	key, err := pubPEM.ToPublicKey()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(key, pub) {
		t.Fatal("the computed public key and the expected key are not equal")
	}
}

func TestPEMBlock_ToPrivateKey(t *testing.T) {
	t.Parallel()

	key, err := privPEM.ToPrivateKey()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(key, priv) {
		t.Fatal("the computed private key and the expected key are not equal")
	}
}

func TestPEMBlock_ToBytes(t *testing.T) {
	t.Parallel()

	bs := pubPEM.ToBytes()
	if !bytes.Equal(bs, pubPEMBs) {
		t.Fatal("the computed bytes and the expected public key bytes are not equal")
	}

	bs = privPEM.ToBytes()
	if !bytes.Equal(bs, privPEMBs) {
		t.Fatal("the computed bytes and the expected private key bytes are not equal")
	}
}

func TestPEMBlock_FromBytes(t *testing.T) {
	t.Parallel()

	pem := domain.PEMBlock{}
	err := pem.FromBytes(pubPEMBs)
	if err != nil {
		t.Fatal(err)
	}

	if strings.ToUpper(pem.Type) != "PUBLIC KEY" {
		t.Fatal("the loaded PEM block has incorrect type")
	}

	if !bytes.Equal(pem.Bytes, pubX509) {
		t.Fatal("the loaded PEM block has incorrect body")
	}

	err = pem.FromBytes(privPEMBs)
	if err != nil {
		t.Fatal(err)
	}

	if strings.ToUpper(pem.Type) != "PRIVATE KEY" {
		t.Fatal("the loaded PEM block has incorrect type")
	}

	if !bytes.Equal(pem.Bytes, privX509) {
		t.Fatal("the loaded PEM block has incorrect body")
	}
}
