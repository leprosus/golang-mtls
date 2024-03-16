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

func TestParsePemBlockPair(t *testing.T) {
	pub, priv, err := GeneratePemBlockPair()
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ParsePemBlockPair(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsePemBytesPair(t *testing.T) {
	pubBs, privBs, err := GeneratePemBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ParsePemBytesPair(pubBs, privBs)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseBytesPair(t *testing.T) {
	pubBs, privBs, err := GenerateBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ParseBytesPair(pubBs, privBs)
	if err != nil {
		t.Fatal(err)
	}
}
