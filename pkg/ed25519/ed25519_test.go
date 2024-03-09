package ed25519

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	_, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
}
