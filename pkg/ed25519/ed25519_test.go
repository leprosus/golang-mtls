package ed25519_test

import (
	"testing"

	"github.com/leprosus/golang-mtls/pkg/ed25519"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()

	_, _, err := ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
}
