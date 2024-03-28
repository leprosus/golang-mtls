package domain_test

import (
	"mtls/pkg/ed25519/domain"
	"testing"
)

var (
	sharedBs = []byte{189, 114, 85, 127, 150, 168, 2, 76, 197, 132, 223, 148, 211, 159, 11, 116, 229, 183, 108, 37, 115, 90, 159, 238, 121, 103, 82, 33, 19, 117, 103, 114}
	shared   = domain.SharedKey(sharedBs)
	sign     = "0a2d63"
)

func TestSharedKey_Sign(t *testing.T) {
	sharedSign, err := shared.Sign()
	if err != nil {
		t.Fatal(err.Error())
	}

	if sharedSign != sign {
		t.Fatal("the computed sign and the expected shared key sign are not equal")
	}
}
