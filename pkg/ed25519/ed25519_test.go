package ed25519_test

import (
	"testing"

	"mtls/pkg/ed25519"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()

	_, _, err := ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
}
