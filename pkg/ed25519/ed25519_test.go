package ed25519_test

import (
	"mtls/pkg/ed25519"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()

	_, _, err := ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsePemBlockPair(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GeneratePemBlockPair()
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ed25519.ParsePemBlockPair(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsePemBytesPair(t *testing.T) {
	t.Parallel()

	pubBs, privBs, err := ed25519.GeneratePemBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ed25519.ParsePemBytesPair(pubBs, privBs)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseBytesPair(t *testing.T) {
	t.Parallel()

	pubBs, privBs, err := ed25519.GenerateBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ed25519.ParseBytesPair(pubBs, privBs)
	if err != nil {
		t.Fatal(err)
	}
}
